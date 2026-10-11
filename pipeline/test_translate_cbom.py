import unittest


if __package__:
    from .translate_network_cbom import (
        numeric_id,
        readable_name,
        split_cipher_suite,
        split_group,
        translate_cbom,
    )
else:
    from translate_network_cbom import (
        numeric_id,
        readable_name,
        split_cipher_suite,
        split_group,
        translate_cbom,
    )


class TranslationTest(unittest.TestCase):
    def test_identifier_formats_and_unknowns(self):
        for value in (4866, "4866", "0x1302", "0x13,0x02"):
            self.assertEqual(numeric_id(value), 4866)
        self.assertEqual(readable_name("99999", {}), "Unknown algorithm")
        self.assertEqual(readable_name("Legacy_Or_None", {}), "Not recorded")

    def test_translation_replaces_ids_and_handles_named_groups(self):
        properties = {
            "cipherSuite": "4866",
            "keyExchangeGroup": "X25519MLKEM768",
            "supportedGroups": ["29", "23"],
            "protocol": "0x303",
        }
        cbom = {
            "components": [{"type": "network-session", "cryptoProperties": properties}]
        }
        translate_cbom(cbom)
        self.assertEqual(properties["cipherSuite"]["encryption"]["keySizeBits"], 256)
        self.assertEqual(properties["cipherSuite"]["hash"]["outputBits"], 384)
        self.assertEqual(properties["keyExchangeGroup"]["name"], "X25519MLKEM768")
        self.assertEqual(
            [group["name"] for group in properties["supportedGroups"]],
            ["x25519", "secp256r1"],
        )
        self.assertEqual(
            properties["protocol"], "TLS (negotiated version not determined)"
        )
        self.assertNotIn("cipherSuiteName", properties)
        before = dict(properties)
        translate_cbom(cbom)
        self.assertEqual(properties, before)

    def test_cipher_parts_keep_roles_and_sizes_separate(self):
        rsa = split_cipher_suite("TLS_RSA_WITH_AES_128_CBC_SHA")
        self.assertEqual(rsa["keyExchange"], "RSA")
        self.assertEqual(rsa["authentication"], "RSA")
        self.assertEqual(
            rsa["encryption"], {"algorithm": "AES", "keySizeBits": 128, "mode": "CBC"}
        )
        self.assertEqual(
            rsa["hash"], {"algorithm": "SHA-1", "outputBits": 160, "role": "HMAC hash"}
        )
        modern = split_cipher_suite("TLS_AES_256_GCM_SHA384")
        self.assertEqual(modern["keyExchange"], "Negotiated separately")
        self.assertEqual(modern["encryption"]["authenticationTagBits"], 128)
        ccm = split_cipher_suite("TLS_AES_128_CCM_8_SHA256")
        self.assertEqual(ccm["encryption"]["mode"], "CCM")
        self.assertEqual(ccm["encryption"]["authenticationTagBits"], 64)
        chacha = split_cipher_suite("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256")
        self.assertEqual(chacha["keyExchange"], "ECDHE")
        self.assertEqual(chacha["encryption"]["authenticator"], "Poly1305")
        self.assertEqual(chacha["hash"]["role"], "PRF hash")
        self.assertNotIn("encryption", split_cipher_suite("TLS_FALLBACK_SCSV"))

    def test_group_parameters_are_not_symmetric_key_sizes(self):
        hybrid = split_group("X25519MLKEM768")
        self.assertTrue(hybrid["hybrid"])
        self.assertEqual(hybrid["components"][0]["curveBits"], 255)
        self.assertEqual(
            hybrid["components"][1],
            {"algorithm": "ML-KEM", "parameterSet": "768", "nistSecurityLevel": 3},
        )
        self.assertEqual(split_group("ffdhe4096")["components"][0]["modulusBits"], 4096)
        self.assertEqual(split_group("secp384r1")["components"][0]["curveBits"], 384)
        self.assertEqual(split_group("Not recorded"), {"name": "Not recorded"})


if __name__ == "__main__":
    unittest.main()
