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
for line in open("bip0039_wordlist_english.txt", "rU"):
    BIP39_WORDS.append(line.strip("\n"))
def mnemonic_to_seed(mnemonic, password=""):
    mnemonic_norm = unicodedata.normalize("NFKD", mnemonic).lower()
    for word in mnemonic_norm.split(" "):
        assert word in BIP39_WORDS
    mnemonic_norm = mnemonic_norm.encode("ascii")
    password_norm = unicodedata.normalize("NFKD", password).encode("utf-8")
    return hashlib.pbkdf2_hmac("sha512", mnemonic_norm, b"mnemonic" + password_norm, 2048, 64)

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

def tests():
    seed = mnemonic_to_seed("claim source near salon police abstract seminar chronic creek iron luggage result upgrade motor nature base dawn senior junior twenty taxi sun hat front")
    # Regular hwif
    hwif = seed_to_hwif(seed)
    assert hwif_subkey_path(hwif, "m/44'/0'/0'/0/0") == "xprvA35z6phkf68xmyaKsZwh4qRmhvaZVKLYztpVPrMebRJtkSetUViDKaRQAPthhpwDhtBpSC33Z9PZGPbEv9Akc5w1tz42ceLNuUBcB64jqL5"
    # Testnet hwif
    hwif = seed_to_hwif(seed, testnet=True)
    assert hwif_subkey_path(hwif, "m/44'/1'/0'/0/0") == "tprv8koauTdVR3GEFXLNRnawkFBuWDHVFgkKvSkk2X77177ioNDESUyv8zv7j9Ljp8e8KfitDyoNDZyxZFkHNzopcty7uQACRPwmWur28yyFRVX"
    # Regular public hwif
    hwif = seed_to_hwif(seed)
    assert private_hwif_to_public(hwif_subkey_path(hwif, "m/44'/0'/0'/0/0")) == "xpub6G5LWLEeVThFzTenybUhRyNWFxR3tn4QN7k6CEmG9kqsdEz3232TsNjt1f9FDg7ojYZwym5HqDvE8x2Ah2fZZCPVS6W8eQ14eE9Py8vmgrd"
    # Testnet public hwif
    hwif = seed_to_hwif(seed, testnet=True)
    assert private_hwif_to_public(hwif_subkey_path(hwif, "m/44'/1'/0'/0/0")) == "tpubDHVd3sfjZQwu8zNAKSFY9er25EoRR1wEVkMXK39QRNv7drU14soWKVXyuFHoXqYhs9wp6zmBpWgUgNgfwnGmqp3PHgfpnZoE4JV7WjHXpRz"
    # Regular WIF
    hwif = seed_to_hwif(seed)
    assert hwif_to_wif(hwif_subkey_path(hwif, "m/44'/0'/0'/0/0")) == "L5QjUF1AZ9Vk8FhpDc8mt3e4DcjNouWmc4wUDEQYvipmzCMNsd1R"
    # Testnet WIF
    hwif = seed_to_hwif(seed, testnet=True)
    assert hwif_to_wif(hwif_subkey_path(hwif, "m/44'/1'/0'/0/0")) == "cSHjnErhinQjYLTRWjwevNVz1L1bnD58pT42msnJgBiyaiSM62gY"
    # Regular WIF (uncompressed)
    hwif = seed_to_hwif(seed)
    assert hwif_to_wif(hwif_subkey_path(hwif, "m/44'/0'/0'/0/0"), compressed=False) == "5KfufoDj3JLCapHVpiVVkHTXBZZiC5eZJv17AZwj8BqS9X2aHrD"
    # Testnet WIF (uncompressed)
    hwif = seed_to_hwif(seed, testnet=True)
    assert hwif_to_wif(hwif_subkey_path(hwif, "m/44'/1'/0'/0/0"), compressed=False) == "92en36QViBjzDY9FcjopZUys59qcyTkXmjc8CXY7Gg8hTgaj4TM"
    # Regular P2PKH
    hwif = seed_to_hwif(seed)
    assert hwif_to_p2pkh_address(hwif_subkey_path(hwif, "m/44'/0'/0'/0/0")) == "15UY8V5RT5p3ov15dJXv5AEUJDJCGCARLC"
    # Testnet P2PKH
    hwif = seed_to_hwif(seed, testnet=True)
    assert hwif_to_p2pkh_address(hwif_subkey_path(hwif, "m/44'/1'/0'/0/0")) == "mxP41RqRvAdGAJNCX5Dr2GEMemUY8ZjHUg"
    # Regular P2PKH (uncompressed)
    hwif = seed_to_hwif(seed)
    assert hwif_to_p2pkh_address(hwif_subkey_path(hwif, "m/44'/0'/0'/0/0"), compressed=False) == "192oQj1gqEbkXy8EnrBCdmMWfn8qUN3RDj"
    # Testnet P2PKH (uncompressed)
    hwif = seed_to_hwif(seed, testnet=True)
    assert hwif_to_p2pkh_address(hwif_subkey_path(hwif, "m/44'/1'/0'/0/0"), compressed=False) == "mzNkSF2tGjcaed5UL7zsd7pYzFXWTqXMLA"
    # Regular P2WPHK
    hwif = seed_to_hwif(seed)
    assert hwif_to_p2wpkh_address(hwif_subkey_path(hwif, "m/49'/0'/0'/0/0")) == "3B4pjc3Tgf1KsCbmUuYMoaMXwcQJUUYdDQ"
    # Testnet P2WPKH
    hwif = seed_to_hwif(seed, testnet=True)
    assert hwif_to_p2wpkh_address(hwif_subkey_path(hwif, "m/49'/1'/0'/0/0")) == "2NBnetKatpDruiyF6fUHFaoEgDkaX5UK54F"
    # Regular ETH Account
    hwif = seed_to_hwif(seed)
    assert hwif_to_eth_account(hwif_subkey_path(hwif, "m/44'/60'/0'/0/0")) == "0x357FF629155cF91E9D32464F738e0A9bA32BAe7C"
    # Testnet ETH Account
    hwif = seed_to_hwif(seed)
    assert hwif_to_eth_account(hwif_subkey_path(hwif, "m/44'/60'/0'/0/0")) == "0x357FF629155cF91E9D32464F738e0A9bA32BAe7C"
    # Regular ETH Private
    hwif = seed_to_hwif(seed)
    assert hwif_to_eth_privatekey(hwif_subkey_path(hwif, "m/44'/60'/0'/0/0")) == "fd59899e8c3a6ace9aa9898b51bf85de0b8d635e37f3e935e10ffd2aa7abd897"
    # Testnet ETH Private
    hwif = seed_to_hwif(seed)
    assert hwif_to_eth_privatekey(hwif_subkey_path(hwif, "m/44'/60'/0'/0/0")) == "fd59899e8c3a6ace9aa9898b51bf85de0b8d635e37f3e935e10ffd2aa7abd897"

    # Test path syntax
    seed = mnemonic_to_seed("claim source near salon police abstract seminar chronic creek iron luggage result upgrade motor nature base dawn senior junior twenty taxi sun hat front")
    hwif = seed_to_hwif(seed)
    hwif = hwif_subkey_path(hwif, "m/44H/60'/0h/0/0/")
    assert hwif_to_eth_privatekey(hwif) == "fd59899e8c3a6ace9aa9898b51bf85de0b8d635e37f3e935e10ffd2aa7abd897"
    hwif = seed_to_hwif(seed)
    hwif = hwif_subkey_path(hwif, "44H/60'/0h/0/0/")
    assert hwif_to_eth_privatekey(hwif) == "fd59899e8c3a6ace9aa9898b51bf85de0b8d635e37f3e935e10ffd2aa7abd897"
    hwif = seed_to_hwif(seed)
    hwif = hwif_subkey_path(hwif, "/44H/60'/0h/0/0")
    assert hwif_to_eth_privatekey(hwif) == "fd59899e8c3a6ace9aa9898b51bf85de0b8d635e37f3e935e10ffd2aa7abd897"

    # BIP32 Test Vectors
    tv1 = seed_to_hwif(bytearray.fromhex("000102030405060708090a0b0c0d0e0f"))
    assert tv1 == "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
    assert private_hwif_to_public(tv1) == "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"

    tv1a = hwif_subkey_path(tv1, "m/0H")
    assert tv1a == "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"
    assert private_hwif_to_public(tv1a) == "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"

    tv1b = hwif_subkey_path(tv1, "m/0H/1")
    assert tv1b == "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs"
    assert private_hwif_to_public(tv1b) == "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ"

    tv1c = hwif_subkey_path(tv1, "m/0H/1/2H")
    assert tv1c == "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM"
    assert private_hwif_to_public(tv1c) == "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5"

    tv1d = hwif_subkey_path(tv1, "m/0H/1/2H/2")
    assert tv1d == "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334"
    assert private_hwif_to_public(tv1d) == "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV"

    tv1e = hwif_subkey_path(tv1, "m/0H/1/2H/2/1000000000")
    assert tv1e == "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76"
    assert private_hwif_to_public(tv1e) == "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy"

    tv2 = seed_to_hwif(bytearray.fromhex("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"))
    assert tv2 == "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U"
    assert private_hwif_to_public(tv2) == "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"

    tv2a = hwif_subkey_path(tv2, "m/0")
    assert tv2a == "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt"
    assert private_hwif_to_public(tv2a) == "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH"

    tv2b = hwif_subkey_path(tv2, "m/0/2147483647H")
    assert tv2b == "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9"
    assert private_hwif_to_public(tv2b) == "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a"

    tv2c = hwif_subkey_path(tv2, "m/0/2147483647H/1")
    assert tv2c == "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef"
    assert private_hwif_to_public(tv2c) == "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon"

    tv2d = hwif_subkey_path(tv2, "m/0/2147483647H/1/2147483646H")
    assert tv2d == "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc"
    assert private_hwif_to_public(tv2d) == "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL"

    tv2e = hwif_subkey_path(tv2, "m/0/2147483647H/1/2147483646H/2")
    assert tv2e == "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j"
    assert private_hwif_to_public(tv2e) == "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt"

    tv3 = seed_to_hwif(bytearray.fromhex("4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be"))
    assert tv3 == "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6"
    assert private_hwif_to_public(tv3) == "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13"

    tv3a = hwif_subkey_path(tv3, "m/0H")
    assert tv3a == "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L"
    assert private_hwif_to_public(tv3a) == "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y"

    # BIP49 Test Vectors (P2WPKH)
    seed = mnemonic_to_seed("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
    hwif = seed_to_hwif(seed, testnet=True)
    assert hwif == "tprv8ZgxMBicQKsPe5YMU9gHen4Ez3ApihUfykaqUorj9t6FDqy3nP6eoXiAo2ssvpAjoLroQxHqr3R5nE3a5dU3DHTjTgJDd7zrbniJr6nrCzd"
    account0 = hwif_subkey_path(hwif, "m/49'/1'/0'")
    assert account0 == "tprv8gRrNu65W2Msef2BdBSUgFdRTGzC8EwVXnV7UGS3faeXtuMVtGfEdidVeGbThs4ELEoayCAzZQ4uUji9DUiAs7erdVskqju7hrBcDvDsdbY"
    account00 = hwif_subkey_path(hwif, "m/49'/1'/0'/0/0")
    assert hwif_to_p2wpkh_address(account00) == "2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2"

    # EIP55 Test Vectors (Mixed-case checksums)
    assert mixed_case_checksum(bytearray.fromhex("5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed")) == "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
    assert mixed_case_checksum(bytearray.fromhex("fB6916095ca1df60bB79Ce92cE3Ea74c37c5d359")) == "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"
    assert mixed_case_checksum(bytearray.fromhex("dbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB")) == "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB"
    assert mixed_case_checksum(bytearray.fromhex("D1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb")) == "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb"

    # Private to public
    assert private_eth_to_public("fd59899e8c3a6ace9aa9898b51bf85de0b8d635e37f3e935e10ffd2aa7abd897") == "0x357FF629155cF91E9D32464F738e0A9bA32BAe7C"
    assert wif_to_p2pkh("L5QjUF1AZ9Vk8FhpDc8mt3e4DcjNouWmc4wUDEQYvipmzCMNsd1R") == "15UY8V5RT5p3ov15dJXv5AEUJDJCGCARLC"
    assert wif_to_p2pkh("cSHjnErhinQjYLTRWjwevNVz1L1bnD58pT42msnJgBiyaiSM62gY") == "mxP41RqRvAdGAJNCX5Dr2GEMemUY8ZjHUg"
    assert wif_to_p2pkh("5KfufoDj3JLCapHVpiVVkHTXBZZiC5eZJv17AZwj8BqS9X2aHrD") == "192oQj1gqEbkXy8EnrBCdmMWfn8qUN3RDj"
    assert wif_to_p2pkh("92en36QViBjzDY9FcjopZUys59qcyTkXmjc8CXY7Gg8hTgaj4TM") == "mzNkSF2tGjcaed5UL7zsd7pYzFXWTqXMLA"
    assert wif_to_p2wpkh("KxfQCqjvwEX362W2cMZuvcsLFaEn4V1dmRX1uDrtEBv8Xw46vpfY") == "3B4pjc3Tgf1KsCbmUuYMoaMXwcQJUUYdDQ"
    assert wif_to_p2wpkh("cVUnfa1d6j93eBEgjWFgyUePCakdraZoH9pdPiPVmZfDAY6JUzVs") == "2NBnetKatpDruiyF6fUHFaoEgDkaX5UK54F"
    assert wif_to_p2wpkh("5J9FKYS8gvp8ivMdANRgBLTMg6idwiEjmW7oRX6s84qHfHv1NCw") == "3B4pjc3Tgf1KsCbmUuYMoaMXwcQJUUYdDQ"
    assert wif_to_p2wpkh("93NhhunuavW1bhqQxPwXonETKwKVjxBbxKK3MZ2veHTnMPKsr66") == "2NBnetKatpDruiyF6fUHFaoEgDkaX5UK54F"

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
            print("Bitcoin private key (compressed):     {}".format(hwif_to_wif(hwif, compressed=True)))
            print("Bitcoin private key (uncompressed):   {}".format(hwif_to_wif(hwif, compressed=False)))
            print("Bitcoin P2PKH address (compressed):   {}".format(hwif_to_p2pkh_address(hwif, compressed=True)))
            print("Bitcoin P2PKH address (uncompressed): {}".format(hwif_to_p2pkh_address(hwif, compressed=False)))
            print("Bitcoin P2SH-P2WPKH address:          {}".format(hwif_to_p2wpkh_address(hwif)))
            print("Bitcoin P2SH-P2WPKH redeem script:    {}".format(wif_to_p2wpkh_redeem_script(hwif_to_wif(hwif))))
            print("Bitcoin Bech32 address:               {}".format(hwif_to_bech32_address(hwif)))
            print("Ethereum private key:                 {}".format(hwif_to_eth_privatekey(hwif)))
            print("Ethereum account:                     {}".format(hwif_to_eth_account(hwif)))
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
        print("Ethereum private key: {}".format(key))
        print("Ethereum account:     {}".format(private_eth_to_public(key)))

    print()

    if selection == "1":
        show_bip39_details()
    elif selection == "2":
        show_wif_details()
    elif selection == "3":
        show_eth_details()
    elif selection == "4":
        words = [secrets.choice(BIP39_WORDS) for _ in range(24)]
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
    tests()
    main()
