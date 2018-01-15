#
# Implementation of elliptic curves, for cryptographic applications.
#
# This module doesn't provide any way to choose a random elliptic
# curve, nor to verify that an elliptic curve was chosen randomly,
# because one can simply use NIST's standard curves.
#
# Notes from X9.62-1998 (draft):
#   Nomenclature:
#     - Q is a public key.
#     The "Elliptic Curve Domain Parameters" include:
#     - q is the "field size", which in our case equals p.
#     - p is a big prime.
#     - G is a point of prime order (5.1.1.1).
#     - n is the order of G (5.1.1.1).
#   Public-key validation (5.2.2):
#     - Verify that Q is not the point at infinity.
#     - Verify that X_Q and Y_Q are in [0,p-1].
#     - Verify that Q is on the curve.
#     - Verify that nQ is the point at infinity.
#   Signature generation (5.3):
#     - Pick random k from [1,n-1].
#   Signature checking (5.4.2):
#     - Verify that r and s are in [1,n-1].
#
# Version of 2008.11.25.
#
# Revision history:
#    2005.12.31 - Initial version.
#    2008.11.25 - Change CurveFp.is_on to contains_point.
#
# Written in 2005 by Peter Pearson and placed in the public domain.

class CurveFp(object):
    """Elliptic Curve over the field of integers modulo a prime."""
    def __init__(self, p, a, b):
        """The curve of points satisfying y^2 = x^3 + a*x + b (mod p)."""
        self.__p = p
        self.__a = a
        self.__b = b

    def p(self):
        return self.__p

    def a(self):
        return self.__a

    def b(self):
        return self.__b

    def contains_point(self, x, y):
        """Is the point (x,y) on this curve?"""
        return (y * y - (x * x * x + self.__a * x + self.__b)) % self.__p == 0

    def __repr__(self):
        return '{}({!r},{!r},{!r})'.format(self.__class__.__name__, self.__p, self.__a, self.__b)

    def __str__(self):
        return 'y^2 = x^3 + {}*x + {} (mod {})'.format(self.__a, self.__b, self.__p)


class Point(object):
    """A point on an elliptic curve. Altering x and y is forbidden,
     but they can be read by the x() and y() methods."""
    def __init__(self, curve, x, y, order=None):
        """curve, x, y, order; order (optional) is the order of this point."""
        self.__curve = curve
        self.__x = x
        self.__y = y
        self.__order = order
        # self.curve is allowed to be None only for INFINITY:
        if self.__curve and not self.__curve.contains_point(x, y):
            raise ValueError('({},{}) is not on the curve {}'.format(x, y, curve))
        if order:
            assert self * order == INFINITY

    def __eq__(self, other):
        """Return 1 if the points are identical, 0 otherwise."""
        if self.__curve == other.__curve \
           and self.__x == other.__x \
           and self.__y == other.__y:
            return 1
        else:
            return 0

    def __add__(self, other):
        """Add one point to another point."""

        # X9.62 B.3:

        if other == INFINITY:
            return self
        if self == INFINITY:
            return other
        assert self.__curve == other.__curve
        if self.__x == other.__x:
            if (self.__y + other.__y) % self.__curve.p() == 0:
                return INFINITY
            else:
                return self.double()

        p = self.__curve.p()

        l = ((other.__y - self.__y) *
             inverse_mod(other.__x - self.__x, p)) % p

        x3 = (l * l - self.__x - other.__x) % p
        y3 = (l * (self.__x - x3) - self.__y) % p

        return Point(self.__curve, x3, y3)

    def __mul__(self, other):
        """Multiply a point by an integer."""

        def leftmost_bit(x):
            assert x > 0
            result = 1
            while result <= x:
                result = 2 * result
            return result // 2

        e = other
        if self.__order:
            e = e % self.__order
        if e == 0:
            return INFINITY
        if self == INFINITY:
            return INFINITY
        assert e > 0

        # From X9.62 D.3.2:

        e3 = 3 * e
        negative_self = Point(self.__curve, self.__x, -self.__y, self.__order)
        i = leftmost_bit(e3) // 2
        result = self
        # print "Multiplying %s by %d (e3 = %d):" % (self, other, e3)
        while i > 1:
            result = result.double()
            if (e3 & i) != 0 and (e & i) == 0:
                result = result + self
            if (e3 & i) == 0 and (e & i) != 0:
                result = result + negative_self
            # print ". . . i = %d, result = %s" % (i, result)
            i = i // 2

        return result

    def __rmul__(self, other):
        """Multiply a point by an integer."""

        return self * other

    def __repr__(self):
        return "{}({!r},{!r},{!r},{!r})".format(self.__class__.__name__, self.__curve, self.__x, self.__y, self.__order)

    def __str__(self):
        if self == INFINITY:
            return "infinity"
        return "(%d,%d)" % (self.__x, self.__y)

    def double(self):
        """Return a new point that is twice the old."""

        if self == INFINITY:
            return INFINITY

        # X9.62 B.3:

        p = self.__curve.p()
        a = self.__curve.a()

        l = ((3 * self.__x * self.__x + a) *
             inverse_mod(2 * self.__y, p)) % p

        x3 = (l * l - 2 * self.__x) % p
        y3 = (l * (self.__x - x3) - self.__y) % p

        return Point(self.__curve, x3, y3)

    def x(self):
        return self.__x

    def y(self):
        return self.__y

    def pair(self):
        return (self.__x, self.__y)

    def curve(self):
        return self.__curve

    def order(self):
        return self.__order


def public_pair_for_x(generator, x, is_even):
    curve = generator.curve()
    p = curve.p()
    alpha = (pow(x, 3, p) + curve.a() * x + curve.b()) % p
    beta = modular_sqrt(alpha, p)
    if bool(is_even) == bool(beta & 1):
        return (x, p - beta)
    return (x, beta)


def inverse_mod(a, m):
    """Inverse of a mod m."""

    if a < 0 or m <= a:
        a = a % m

    # From Ferguson and Schneier, roughly:

    c, d = a, m
    uc, vc, ud, vd = 1, 0, 0, 1
    while c != 0:
        q, c, d = divmod(d, c) + (c,)
        uc, vc, ud, vd = ud - q*uc, vd - q*vc, uc, vc

    # At this point, d is the GCD, and ud*a+vd*m = d.
    # If d == 1, this means that ud is a inverse.

    assert d == 1
    if ud > 0:
        return ud
    else:
        return ud + m


# from http://eli.thegreenplace.net/2009/03/07/computing-modular-square-roots-in-python/
# with few fixes and suggestions from
# http://codereview.stackexchange.com/questions/43210/tonelli-shanks-algorithm-implementation-of-prime-modular-square-root


def modular_sqrt(a, p):
    """ Find a quadratic residue (mod p) of 'a'. p
    must be a prime.

    Solve the congruence of the form:
    x^2 = a (mod p)
    And returns x. Note that p - x is also a root.

    0 is returned if no square root exists for
    these a and p.

    The Tonelli-Shanks algorithm is used (except
    for some simple cases in which the solution
    is known from an identity). This algorithm
    runs in polynomial time (unless the
    generalized Riemann hypothesis is false).
    """
    # Simple cases
    #
    if legendre_symbol(a, p) != 1:
        return 0
    elif a == 0:
        return 0
    elif p == 2:
        return a
    elif p % 4 == 3:
        return pow(a, (p + 1) // 4, p)

    # Partition p-1 to s * 2^e for an odd s (i.e.
    # reduce all the powers of 2 from p-1)
    #
    s = p - 1
    e = 0
    while s % 2 == 0:
        s /= 2
        e += 1

    # Find some 'n' with a legendre symbol n|p = -1.
    # Shouldn't take long.
    #
    n = 2
    while legendre_symbol(n, p) != -1:
        n += 1

    # Here be dragons!
    # Read the paper "Square roots from 1; 24, 51,
    # 10 to Dan Shanks" by Ezra Brown for more
    # information
    #

    # x is a guess of the square root that gets better
    # with each iteration.
    # b is the "fudge factor" - by how much we're off
    # with the guess. The invariant x^2 = ab (mod p)
    # is maintained throughout the loop.
    # g is used for successive powers of n to update
    # both a and b
    # r is the exponent - decreases with each update
    #
    x = pow(a, (s + 1) // 2, p)
    b = pow(a, s, p)
    g = pow(n, s, p)
    r = e

    while True:
        t = b
        m = 0
        for m in xrange(r):
            if t == 1:
                break
            t = pow(t, 2, p)

        if m == 0:
            return x

        gs = pow(g, 1 << (r - m - 1), p)
        g = (gs * gs) % p
        x = (x * gs) % p
        b = (b * g) % p
        r = m


def legendre_symbol(a, p):
    """ Compute the Legendre symbol a|p using
    Euler's criterion. p is a prime, a is
    relatively prime to p (if p divides
    a, then a|p = 0)

    Returns 1 if a has a square root modulo
    p, -1 otherwise.
    """
    ls = pow(a, (p - 1) // 2, p)
    return -1 if ls == p - 1 else ls


# This one point is the Point At Infinity for all purposes:
INFINITY = Point(None, None, None)


# Certicom secp256-k1
_a = 0x0000000000000000000000000000000000000000000000000000000000000000
_b = 0x0000000000000000000000000000000000000000000000000000000000000007
_p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
_Gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
_Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
_r = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
generator_secp256k1 = Point(CurveFp(_p, _a, _b), _Gx, _Gy, _r)
