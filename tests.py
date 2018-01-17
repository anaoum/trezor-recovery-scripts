from recover import *

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

if __name__ == "__main__":
    tests()
