#!/usr/bin/env python3

import sys
import hmac
import struct
import hashlib
import secrets
import unicodedata

import keccak
import ecdsa

# BIP39
BIP39_WORDS = []
for line in open("bip0039_wordlist_english.txt", "r"):
    BIP39_WORDS.append(line.strip("\n"))
def mnemonic_to_seed(mnemonic, password=""):
    mnemonic_norm = unicodedata.normalize("NFKD", mnemonic).lower()
    for word in mnemonic_norm.split(" "):
        assert word in BIP39_WORDS
    mnemonic_norm = mnemonic_norm.encode("ascii")
    password_norm = unicodedata.normalize("NFKD", password).encode("utf-8")
    return hashlib.pbkdf2_hmac("sha512", mnemonic_norm, b"mnemonic" + password_norm, 2048, 64)
def generate_mnemonic(strength=256):
    entropy = secrets.randbits(strength)
    data = int.to_bytes(entropy, strength//8, "big")
    h = hashlib.sha256(data).hexdigest()
    b = bin(entropy)[2:].zfill(strength) + bin(int(h, 16))[2:].zfill(256)[:strength//32]
    words = []
    for i in range(len(b)//11):
        idx = int(b[i*11:(i + 1)*11], 2)
        words.append(BIP39_WORDS[idx])
    return words

# Base58 Encoding
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
def b58encode_int(i):
    string = ""
    while i:
        i, idx = divmod(i, 58)
        string = BASE58_ALPHABET[idx] + string
    return string
def b58encode(v):
    nPad = len(v)
    v = v.lstrip(b"\0")
    nPad -= len(v)
    p, acc = 1, 0
    for c in reversed(v):
        acc += p * c
        p = p << 8
    result = b58encode_int(acc)
    return (BASE58_ALPHABET[0] * nPad + result)
def b58encode_check(v):
    digest = hashlib.sha256(hashlib.sha256(v).digest()).digest()
    return b58encode(v + digest[:4])
def b58decode_int(v):
    decimal = 0
    for char in v:
        decimal = decimal * 58 + BASE58_ALPHABET.index(char)
    return decimal
def b58decode(v):
    origlen = len(v)
    v = v.lstrip(BASE58_ALPHABET[0])
    newlen = len(v)
    acc = b58decode_int(v)
    result = []
    while acc > 0:
        acc, mod = divmod(acc, 256)
        result.append(mod)
    return (b"\0" * (origlen - newlen) + bytes(reversed(result)))
def b58decode_check(v):
    result = b58decode(v)
    result, check = result[:-4], result[-4:]
    digest = hashlib.sha256(hashlib.sha256(result).digest()).digest()
    assert check == digest[:4]
    return result

def hash160(data):
    return hashlib.new("ripemd160", hashlib.sha256(data).digest()).digest()

# BIP32 Helper Functions
def parse_256(p):
    return int.from_bytes(p, byteorder="big")
def ser_32(v):
    return v.to_bytes(4, byteorder="big")
def ser_256(v):
    return v.to_bytes(32, byteorder="big")
def ser_p(public_key):
    x, y = public_key[0], public_key[1]
    if y % 2 == 0:
        header = b"\x02"
    else:
        header = b"\x03"
    return header + ser_256(x)
def CKDpriv(secret_exponent, chain_code_bytes, index, hardened, public_pair):
    if hardened:
        data = b"\0" + ser_256(secret_exponent) + ser_32(index)
    else:
        data = ser_p(public_pair) + ser_32(index)
    I64 = hmac.HMAC(key=chain_code_bytes, msg=data, digestmod=hashlib.sha512).digest()
    I_left_as_exponent = parse_256(I64[:32])
    assert I_left_as_exponent < ecdsa.generator_secp256k1.order()
    new_secret_exponent = (I_left_as_exponent + secret_exponent) % ecdsa.generator_secp256k1.order()
    assert new_secret_exponent != 0
    new_chain_code = I64[32:]
    return new_secret_exponent, new_chain_code
def CKDpub(public_pair, chain_code_bytes, index):
    assert index < 0x80000000
    data = ser_p(public_pair) + ser_32(index)
    I64 = hmac.HMAC(key=chain_code_bytes, msg=data, digestmod=hashlib.sha512).digest()
    I_left_as_exponent = parse_256(I64[:32])
    assert I_left_as_exponent < ecdsa.generator_secp256k1.order()
    x, y = public_pair
    the_point = (I_left_as_exponent * ecdsa.generator_secp256k1) + ecdsa.Point(ecdsa.generator_secp256k1.curve(), x, y, ecdsa.generator_secp256k1.order())
    assert the_point != ecdsa.INFINITY
    new_public_pair = the_point.pair()
    new_chain_code = I64[32:]
    return new_public_pair, new_chain_code

# BIP32
HWIF_VERSIONS = {
    "mainnet": {"public": b"\x04\x88\xB2\x1E", "private": b"\x04\x88\xAD\xE4"},
    "testnet": {"public": b"\x04\x35\x87\xCF", "private": b"\x04\x35\x83\x94"},
}
HWIF_VERSION_CODES = {
    b"\x04\x88\xB2\x1E": ("mainnet", "public"),
    b"\x04\x88\xAD\xE4": ("mainnet", "private"),
    b"\x04\x35\x87\xCF": ("testnet", "public"),
    b"\x04\x35\x83\x94": ("testnet", "private"),
}
def seed_to_hwif(seed, testnet=False):
    I64 = hmac.HMAC(key=b"Bitcoin seed", msg=seed, digestmod=hashlib.sha512).digest()
    secret_key = parse_256(I64[:32])
    assert secret_key != 0
    assert secret_key < ecdsa.generator_secp256k1.order()
    chain_code = I64[32:]
    return to_hwif(testnet, 0, b"\0\0\0\0", 0, chain_code, secret_key)
def to_hwif(testnet, depth, parent_fingerprint, child_index, chain_code, secret_key=None, public_key=None):
    ba = bytearray()
    netcode = "testnet" if testnet else "mainnet"
    if secret_key is None:
        ba.extend(HWIF_VERSIONS[netcode]["public"])
    else:
        ba.extend(HWIF_VERSIONS[netcode]["private"])
    ba.extend([depth])
    ba.extend(parent_fingerprint + struct.pack(">L", child_index) + chain_code)
    assert secret_key or public_key
    if secret_key is not None:
        ba += b"\0" + ser_256(secret_key)
    else:
        ba += ser_p(public_key)
    return b58encode_check(bytes(ba))
def from_hwif(hwif):
    data = b58decode_check(hwif)
    assert len(data) == 78
    version = data[0:4]
    depth = ord(data[4:5])
    parent_fingerprint = data[5:9]
    child_index = struct.unpack(">L", data[9:13])[0]
    chain_code = data[13:45]
    netcode, key_type = HWIF_VERSION_CODES[version]
    if key_type == "private":
        assert data[45:46] == b"\0"
        secret_key = parse_256(data[46:78])
        assert secret_key != 0
        assert secret_key < ecdsa.generator_secp256k1.order()
        public_key = (ecdsa.generator_secp256k1*secret_key).pair()
    else: # key_type == "public":
        parity = data[45:46]
        assert parity in (b"\x02", b"\x03")
        is_even = parity == b"\x02"
        public_key = ecdsa.public_pair_for_x(ecdsa.generator_secp256k1, parse_256(data[46:78]), is_even)
        secret_key = None
    return (netcode == "testnet", depth, parent_fingerprint, child_index, chain_code, secret_key, public_key)
def hwif_subkey(hwif, index, hardened=False):
    testnet, depth, parent_fingerprint, child_index, chain_code, secret_key, public_key = from_hwif(hwif)
    assert index >= 0
    assert index < 0x80000000
    index &= 0x7fffffff
    if hardened:
        assert secret_key is not None
        index |= 0x80000000
    if secret_key is None:
        sub_public_key, sub_chain_code = CKDpub(public_key, chain_code, index)
        sub_secret_key = None
    else:
        sub_secret_key, sub_chain_code = CKDpriv(secret_key, chain_code, index, hardened, public_key)
        sub_public_key = None
    sub_parent_fingerprint = hash160(ser_p(public_key))[:4]
    return to_hwif(testnet, depth+1, sub_parent_fingerprint, index, sub_chain_code, sub_secret_key, sub_public_key)
def private_hwif_to_public(hwif):
    testnet, depth, parent_fingerprint, child_index, chain_code, secret_key, public_key = from_hwif(hwif)
    assert secret_key is not None
    return to_hwif(testnet, depth, parent_fingerprint, child_index, chain_code, None, public_key)
def hwif_subkey_path(hwif, path):
    path_parts = path.split("/")
    if not path_parts[0] or path_parts[0].lower() == "m":
        path_parts.pop(0)
    if not path_parts:
        return hwif
    if path_parts[0].endswith("'") or path_parts[0].endswith("h") or path_parts[0].endswith("H"):
        hardened = True
        path_parts[0] = path_parts[0][:-1]
    else:
        hardened = False
    index = int(path_parts[0])
    hwif = hwif_subkey(hwif, index, hardened)
    return hwif_subkey_path(hwif, "/".join(path_parts[1:]))

# Public keys
def hwif_to_p2pkh_address(hwif, compressed=True):
    testnet, depth, parent_fingerprint, child_index, chain_code, secret_key, public_key = from_hwif(hwif)
    if compressed:
        data = ser_p(public_key)
    else:
        data = b"\x04" + ser_256(public_key[0]) + ser_256(public_key[1])
    keyhash = hash160(data)
    prefix = b"\x6f" if testnet else b"\x00"
    return b58encode_check(prefix + keyhash)
def hwif_to_p2wpkh_address(hwif):
    testnet, depth, parent_fingerprint, child_index, chain_code, secret_key, public_key = from_hwif(hwif)
    data = ser_p(public_key)
    keyhash = hash160(data)
    script = b"\x00\x14" + keyhash
    scripthash = hash160(script)
    prefix = b"\xc4" if testnet else b"\x05"
    return b58encode_check(prefix + scripthash)
# BIP173
import segwit_addr
def hwif_to_bech32_address(hwif):
    testnet, depth, parent_fingerprint, child_index, chain_code, secret_key, public_key = from_hwif(hwif)
    data = ser_p(public_key)
    keyhash = hash160(data)
    hrp = "tb" if testnet else "bc"
    return segwit_addr.encode(hrp, 0, keyhash)
def hwif_to_eth_account(hwif):
    testnet, depth, parent_fingerprint, child_index, chain_code, secret_key, public_key = from_hwif(hwif)
    data = ser_256(public_key[0]) + ser_256(public_key[1])
    keyhash =  keccak.Keccak256(data).digest()
    return mixed_case_checksum(keyhash[-20:])

# Private keys
def hwif_to_wif(hwif, compressed=True):
    testnet, depth, parent_fingerprint, child_index, chain_code, secret_key, public_key = from_hwif(hwif)
    prefix = b"\xef" if testnet else b"\x80"
    data = prefix + ser_256(secret_key)
    if compressed:
        data += b"\x01"
    return b58encode_check(data)
def hwif_to_eth_privatekey(hwif):
    testnet, depth, parent_fingerprint, child_index, chain_code, secret_key, public_key = from_hwif(hwif)
    data = ser_256(secret_key)
    return data.hex()

# EIP55
def mixed_case_checksum(data):
    o = ""
    checksum = keccak.Keccak256(data.hex().encode("ascii")).digest()
    v = parse_256(checksum)
    for i, c in enumerate(data.hex()):
        if c in "0123456789":
            o += c
        else:
            o += c.upper() if (v & (2**(255 - 4*i))) else c.lower()
    return "0x" + o

def private_eth_to_public(priv):
    secret_key = parse_256(bytearray.fromhex(priv))
    public_key = (ecdsa.generator_secp256k1*secret_key).pair()
    data = ser_256(public_key[0]) + ser_256(public_key[1])
    keyhash =  keccak.Keccak256(data).digest()
    return mixed_case_checksum(keyhash[-20:])

def wif_to_wif(wif, compressed=None):
    data = b58decode_check(wif)
    prefix, data = data[0:1], data[1:]
    testnet = prefix == b"\xef"
    if not testnet:
        assert prefix == b"\x80"
    wif_compressed = len(data) == 33
    if wif_compressed:
        suffix, data = data[-1], data[:-1]
        assert suffix == 1
    if compressed is None:
        compressed = wif_compressed
    secret_exponent = parse_256(data)
    prefix = b"\xef" if testnet else b"\x80"
    data = prefix + ser_256(secret_exponent)
    if compressed:
        data += b"\x01"
    return b58encode_check(data)
def wif_to_p2pkh(wif, compressed=None):
    data = b58decode_check(wif)
    prefix, data = data[0:1], data[1:]
    testnet = prefix == b"\xef"
    if not testnet:
        assert prefix == b"\x80"
    wif_compressed = len(data) == 33
    if wif_compressed:
        suffix, data = data[-1], data[:-1]
        assert suffix == 1
    if compressed is None:
        compressed = wif_compressed
    secret_exponent = parse_256(data)
    public_pair = (ecdsa.generator_secp256k1*secret_exponent).pair()
    if compressed:
        data = ser_p(public_pair)
    else:
        data = b"\x04" + ser_256(public_pair[0]) + ser_256(public_pair[1])
    keyhash = hash160(data)
    prefix = b"\x6f" if testnet else b"\x00"
    return b58encode_check(prefix + keyhash)
def wif_to_p2wpkh(wif):
    data = b58decode_check(wif)
    prefix, data = data[0:1], data[1:]
    testnet = prefix == b"\xef"
    if not testnet:
        assert prefix == b"\x80"
    compressed = len(data) == 33
    if compressed:
        suffix, data = data[-1], data[:-1]
        assert suffix == 1
    secret_exponent = parse_256(data)
    public_pair = (ecdsa.generator_secp256k1*secret_exponent).pair()
    data = ser_p(public_pair)
    keyhash = hash160(data)
    script = b"\x00\x14" + keyhash
    scripthash = hash160(script)
    prefix = b"\xc4" if testnet else b"\x05"
    return b58encode_check(prefix + scripthash)
def wif_to_p2wpkh_redeem_script(wif):
    data = b58decode_check(wif)
    prefix, data = data[0:1], data[1:]
    testnet = prefix == b"\xef"
    if not testnet:
        assert prefix == b"\x80"
    compressed = len(data) == 33
    if compressed:
        suffix, data = data[-1], data[:-1]
        assert suffix == 1
    secret_exponent = parse_256(data)
    public_pair = (ecdsa.generator_secp256k1*secret_exponent).pair()
    data = ser_p(public_pair)
    keyhash = hash160(data)
    script = b"\x00\x14" + keyhash
    return script.hex()
def wif_to_bech32(wif):
    data = b58decode_check(wif)
    prefix, data = data[0:1], data[1:]
    testnet = prefix == b"\xef"
    if not testnet:
        assert prefix == b"\x80"
    compressed = len(data) == 33
    if compressed:
        suffix, data = data[-1], data[:-1]
        assert suffix == 1
    secret_exponent = parse_256(data)
    public_pair = (ecdsa.generator_secp256k1*secret_exponent).pair()
    data = ser_p(public_pair)
    keyhash = hash160(data)
    hrp = "tb" if testnet else "bc"
    return segwit_addr.encode(hrp, 0, keyhash)

def main():
    testnet = False
    if len(sys.argv) > 1:
        if sys.argv[1] == "testnet" or sys.argv[1] == "-testnet" or sys.argv[1] == "--testnet":
            testnet = True
        else:
            print("Usage:")
            print("\t{} [--testnet]".format(sys.argv[0]))
            sys.exit(1)

    if testnet:
        print("Testnet mode active.")

    print("1) Enter a BIP39 mnemonic phrase")
    print("2) Enter a Bitcoin private key")
    print("3) Enter an Ethereum private key")
    print("4) Generate a BIP39 mnemonic phrase")
    print("5) Generate a Bitcoin private key")
    print("6) Generate an Ethereum private key")
    print("q) Quit")
    selection = None
    query = "Please make your selection: "
    while not selection:
        selection = input(query)
        if selection.lower() not in ("q", "1", "2", "3", "4", "5", "6"):
            query = "Please enter a number 1-6 or q to quit: "
            selection = None

    def show_bip39_details(phrase=None):
        while not phrase:
            phrase = input("Please enter your 12 or 24 word recovery phrase: ").lower()
            words = phrase.split(" ")
            if len(words) != 12 and len(words) != 24:
                phrase = None
                continue
            is_valid = True
            for word in words:
                if word not in BIP39_WORDS:
                    print("Invalid word in phrase: {}".format(word))
                    is_valid = False
            if not is_valid:
                phrase = None
        password = input("Please enter the password that protects this recovery phrase (hit enter for no password): ")
        seed = mnemonic_to_seed(phrase, password)
        root_hwif = seed_to_hwif(seed, testnet=testnet)
        derivation_path = "m/44'/0'/0'/0/0"
        while True:
            hwif = hwif_subkey_path(root_hwif, derivation_path)
            print()
            print("Recovery phrase:                      {}".format(phrase))
            print("Password:                             {}".format(password))
            print("Current derivation path:              {}".format(derivation_path))
            print("Private BIP32 extended key:           {}".format(hwif))
            print("Public BIP32 extended key:            {}".format(private_hwif_to_public(hwif)))
            show_wif_details(hwif_to_wif(hwif))
            show_eth_details(hwif_to_eth_privatekey(hwif))
            print()
            new_derivation_path = input("Enter a new derivation path or type q to quit: m")
            if new_derivation_path.lower() == "q":
                break
            else:
                derivation_path = "m" + new_derivation_path
    def show_wif_details(wif=None):
        while not wif:
            wif = input("Enter the compressed or uncompressed Bitcoin private key: ")
        print("Bitcoin private key (compressed):     {}".format(wif_to_wif(wif, compressed=True)))
        print("Bitcoin private key (uncompressed):   {}".format(wif_to_wif(wif, compressed=False)))
        print("Bitcoin P2PKH address (compressed):   {}".format(wif_to_p2pkh(wif, compressed=True)))
        print("Bitcoin P2PKH address (uncompressed): {}".format(wif_to_p2pkh(wif, compressed=False)))
        print("Bitcoin P2SH-P2WPKH address:          {}".format(wif_to_p2wpkh(wif)))
        print("Bitcoin P2SH-P2WPKH redeem script:    {}".format(wif_to_p2wpkh_redeem_script(wif)))
        print("Bitcoin Bech32 address:               {}".format(wif_to_bech32(wif)))
    def show_eth_details(key=None):
        while not key:
            key = input("Enter the Ethereum private key: ")
        print("Ethereum private key:                 {}".format(key))
        print("Ethereum account:                     {}".format(private_eth_to_public(key)))

    print()

    if selection == "1":
        show_bip39_details()
    elif selection == "2":
        show_wif_details()
    elif selection == "3":
        show_eth_details()
    elif selection == "4":
        words = generate_mnemonic()
        phrase = " ".join(words)
        show_bip39_details(phrase)
    elif selection == "5":
        secret_exponent = secrets.randbits(256)
        prefix = b"\xef" if testnet else b"\x80"
        data = prefix + ser_256(secret_exponent)
        data += b"\x01"
        wif = b58encode_check(data)
        show_wif_details(wif)
    elif selection == "6":
        key = ser_256(secrets.randbits(256)).hex()
        show_eth_details(key)

if __name__ == "__main__":
    main()
