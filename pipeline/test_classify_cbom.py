import copy
import unittest

if __package__:
    from .classify_cbom import classify_cbom, classify_session, primitive_risk
    from .translate_cbom import split_cipher_suite, split_group
else:
    from classify_cbom import classify_cbom, classify_session, primitive_risk
    from translate_cbom import split_cipher_suite, split_group


def session(suite, group="Not recorded"):
    return {
        "cipherSuite": split_cipher_suite(suite),
        "keyExchangeGroup": split_group(group),
    }


class ClassificationTest(unittest.TestCase):
    def test_key_sizes(self):
        for bits, risk in [
            (128, "MEDIUM"),
            (192, "MEDIUM"),
            (256, "SAFE"),
            (None, "UNKNOWN"),
            (512, "UNKNOWN"),
            (True, "UNKNOWN"),
        ]:
            self.assertEqual(
                primitive_risk({"algorithm": "AES", "keySizeBits": bits}, "encryption")[
                    "risk"
                ],
                risk,
            )
        for bits in [1024, 4096, None]:
            self.assertEqual(
                primitive_risk(
                    {"algorithm": "RSA", "keySizeBits": bits}, "keyExchange"
                )["risk"],
                "CRITICAL",
            )

    def test_hybrid_risk_excludes_missing_authentication(self):
        result = classify_session(session("TLS_AES_256_GCM_SHA384", "X25519MLKEM768"))
        self.assertEqual(result["encryptionAndKeyExchangeRisk"], "SAFE")
        self.assertEqual(result["risk"], "SAFE")
        self.assertEqual(result["findings"]["authentication"]["risk"], "UNKNOWN")
        self.assertEqual(result["missingOrUnsupported"], ["authentication"])
        result = classify_session(session("TLS_AES_128_GCM_SHA256", "X25519MLKEM768"))
        self.assertEqual(result["encryptionAndKeyExchangeRisk"], "MEDIUM")
        self.assertEqual(result["risk"], "MEDIUM")

    def test_authentication_contributes_only_when_recorded(self):
        for authentication, expected in [
            (None, "SAFE"),
            ({}, "SAFE"),
            ("", "SAFE"),
            ({"algorithm": None}, "SAFE"),
            ("Not recorded", "SAFE"),
            ("Not determined", "SAFE"),
            ("Negotiated separately", "SAFE"),
            ("RSA", "CRITICAL"),
            ({"algorithm": "ECDSA"}, "CRITICAL"),
            ({"algorithm": "ML-DSA", "parameterSet": "65"}, "SAFE"),
            ({"algorithm": "ML-DSA"}, "UNKNOWN"),
            ("Unsupported signature", "UNKNOWN"),
            ("None", "UNKNOWN"),
        ]:
            with self.subTest(authentication=authentication):
                properties = session("TLS_AES_256_GCM_SHA384", "X25519MLKEM768")
                properties["cipherSuite"]["authentication"] = authentication
                cbom = {
                    "components": [
                        {"type": "network-session", "cryptoProperties": properties}
                    ]
                }
                classified = classify_cbom(cbom)
                self.assertEqual(classified["components"][0]["risk"], expected)
                self.assertEqual(
                    classified["classificationSummary"]["sessionRiskCounts"][expected],
                    1,
                )
        del properties["cipherSuite"]["authentication"]
        self.assertEqual(classify_session(properties)["risk"], "SAFE")

    def test_classical_and_unknown_evidence(self):
        for suite, group, risk in [
            ("TLS_RSA_WITH_AES_128_CBC_SHA", "Not recorded", "CRITICAL"),
            ("TLS_AES_256_GCM_SHA384", "x25519", "CRITICAL"),
            ("TLS_AES_256_GCM_SHA384", "Not recorded", "UNKNOWN"),
            ("TLS_AES_256_GCM_SHA384", "MLKEM999", "UNKNOWN"),
        ]:
            with self.subTest(suite=suite, group=group):
                properties = session(suite, group)
                properties["clientOfferedPQC"] = True
                properties["supportedGroups"] = [split_group("X25519MLKEM768")]
                self.assertEqual(classify_session(properties)["risk"], risk)

    def test_output_preserves_input_and_counts_sessions(self):
        properties = session("TLS_RSA_WITH_AES_128_CBC_SHA")
        original = copy.deepcopy(properties)
        cbom = {
            "components": [{"type": "network-session", "cryptoProperties": properties}]
        }
        classified = classify_cbom(cbom)
        self.assertEqual(properties, original)
        self.assertEqual(
            classified["classificationSummary"]["sessionRiskCounts"]["CRITICAL"], 1
        )
        suite = classified["components"][0]["cryptoProperties"]
        self.assertEqual(suite["encryption"]["risk"], "MEDIUM")
        self.assertEqual(suite["hash"]["risk"], "MEDIUM")
        self.assertEqual(suite["keyExchange"]["risk"], "CRITICAL")
        self.assertEqual(suite["authentication"]["risk"], "CRITICAL")
        self.assertEqual(suite["hash"]["role"], "HMAC hash")
        self.assertNotIn("reason", suite["hash"])
        self.assertNotIn("cipherSuite", suite)
        self.assertNotIn("keyExchangeGroup", suite)
        self.assertNotIn("quantumAssessment", classified["components"][0])
        self.assertEqual(
            classified["classificationSummary"]["algorithmRiskCounts"]["MEDIUM"], 2
        )
        with self.assertRaises(ValueError):
            classify_session({"cipherSuite": "4866"})

    def test_brief_medium_algorithms_and_inline_hybrid(self):
        for algorithm in ("SHA-1", "3DES"):
            self.assertEqual(
                primitive_risk({"algorithm": algorithm}, "hash")["risk"], "MEDIUM"
            )
        properties = session("TLS_AES_256_GCM_SHA384", "X25519MLKEM768")
        classified = classify_cbom(
            {
                "components": [
                    {"type": "network-session", "cryptoProperties": properties}
                ]
            }
        )
        group = classified["components"][0]["cryptoProperties"]["keyExchange"]
        self.assertEqual(group["risk"], "SAFE")
        self.assertEqual(group["components"][0]["risk"], "CRITICAL")
        self.assertEqual(group["components"][1]["risk"], "SAFE")
        self.assertNotIn("riskScope", group["components"][0])


if __name__ == "__main__":
    unittest.main()
