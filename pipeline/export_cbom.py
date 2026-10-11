"""Convert a database source snapshot to CycloneDX 1.7 without changing scanner data.

Specification: https://cyclonedx.org/docs/1.7/json/
Unknown facts stay absent; scanner risk ratings are not security-level certifications.
"""
from datetime import datetime, timezone
import json
import re
import uuid

CURVES = {"X25519": "other/Curve25519", "X448": "other/Curve448",
          "secp256r1": "secg/secp256r1", "secp384r1": "secg/secp384r1", "secp521r1": "secg/secp521r1"}
MODES = {"cbc", "ecb", "ccm", "gcm", "cfb", "ofb", "ctr"}


def recorded(value):
    return isinstance(value, str) and value.strip() and value.lower() not in {
        "not recorded", "not determined", "negotiated separately", "unknown", "none"}


def properties(values):
    return [{"name": f"quantumtrace:{name}", "value": value if isinstance(value, str) else json.dumps(value)}
            for name, value in values.items() if value is not None]


def algorithm_properties(details):
    name = details["algorithm"]
    mode = (details.get("mode") or "").lower()
    primitive = "unknown"
    if details.get("components"):
        primitive = "combiner"
    elif re.match(r"^HMAC[- ]", name, re.I):
        primitive = "mac"
    elif re.match(r"^(SHA-?\d+\b|MD5\b|Legacy-Hash)", name, re.I):
        primitive = "hash"
    elif re.match(r"^(AES|3DES|DES|CAMELLIA|ARIA|SM4)(?:\b|_)", name, re.I):
        primitive = "ae" if mode in {"gcm", "ccm"} else "block-cipher"
    elif re.match(r"^(ChaCha20|RC4)\b", name, re.I):
        primitive = "stream-cipher"
    elif name.upper() in {"ECDH", "ECDHE", "DH", "DHE", "X25519", "X448"}:
        primitive = "key-agree"
    elif re.match(r"^(ECDSA|DSA|Ed25519|Ed448|ML-DSA|SLH-DSA)(?:\b|_)", name, re.I):
        primitive = "signature"
    elif re.match(r"^(ML-KEM|Kyber)(?:\b|_)", name, re.I):
        primitive = "kem"
    # RSA's role cannot be inferred from its family name alone.
    result = {"primitive": primitive}
    parameter = next((details[field] for field in ("parameterSet", "keySizeBits", "outputBits", "modulusBits")
                      if details.get(field) is not None), None)
    if isinstance(parameter, str) and parameter or type(parameter) is int and parameter > 0:
        result["parameterSetIdentifier"] = str(parameter)
    if mode in MODES:
        result["mode"] = mode
    if details.get("curve") in CURVES:
        result["ellipticCurve"] = CURVES[details["curve"]]
    level = details.get("nistSecurityLevel")
    if type(level) is int and 0 <= level <= 6:
        result["nistQuantumSecurityLevel"] = level
    return result


def export_cbom(source):
    """Accept the selected source reconstructed by SourceStore.get, not browser data."""
    if source["status"] != "ready":
        raise ValueError("Wait for this source's analysis to finish before exporting.")
    subject = {"type": "application" if source["kind"] == "repository" else "data",
               "bom-ref": f"source:{source['id']}", "name": source["name"]}
    if source["kind"] == "repository" and source.get("url"):
        subject["externalReferences"] = [{"type": "vcs", "url": source["url"]}]
    components, dependencies, roots = [], [], []
    headers = {}

    def algorithm(details, ref, evidence, purpose):
        if not recorded(details.get("algorithm")):
            return None
        normalized = dict(details)
        if details.get("role") == "HMAC hash":
            normalized["algorithm"] = "HMAC-" + details["algorithm"]
        attrs = algorithm_properties(normalized)
        if purpose == "certificate-signature":
            attrs["primitive"] = "signature"
        parameter = attrs.get("parameterSetIdentifier", "")
        name = [normalized["algorithm"], parameter if parameter not in normalized["algorithm"] else "", attrs.get("mode", "").upper()]
        component = {"type": "cryptographic-asset", "bom-ref": ref, "name": "-".join(part for part in name if part),
                     "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": attrs},
                     "properties": properties({"purpose": purpose, "scanner:algorithm": details, "risk:tier": details.get("risk")})}
        if evidence:
            component["evidence"] = evidence
        components.append(component)
        parts = [algorithm(part, f"{ref}:part:{index}", evidence, purpose)
                 for index, part in enumerate(details.get("components", []))]
        if any(parts):
            dependencies.append({"ref": ref, "dependsOn": [part["bom-ref"] for part in parts if part]})
        return component

    for kind in ("network", "code", "cloud"):
        report = source.get("reports", {}).get(kind)
        if report is None:
            continue
        headers[kind] = {key: value for key, value in report.items() if key != "components"}
        for index, finding in enumerate(report["components"]):
            ref = f"{kind}:{index}"
            props = finding.get("cryptoProperties", {})
            path = finding.get("source") or report.get("metadata", {}).get("sourceFile")
            occurrence = {"location": path} if isinstance(path, str) and path else None
            if occurrence and type(finding.get("line")) is int and finding["line"] >= 0:
                occurrence["line"] = finding["line"]
            if occurrence and isinstance(finding.get("codeSnippet"), str):
                occurrence["additionalContext"] = finding["codeSnippet"]
            evidence = {"occurrences": [occurrence]} if occurrence else None
            component = None
            if kind == "code":
                # Code keySize is a regex heuristic; preserve it as evidence, not a verified parameter.
                component = algorithm({"algorithm": props.get("detectedAlgorithm") or finding.get("name") or "Unknown algorithm"}, ref, evidence, "code")
            if component is None:
                component = {"type": "cryptographic-asset", "bom-ref": ref, "name": finding.get("name") or f"{kind} finding {index + 1}"}
                components.append(component)
                if evidence:
                    component["evidence"] = evidence
                related = []
                if kind == "network" or finding.get("type") == "load-balancer-listener":
                    protocol = {"type": "tls" if re.match(r"^(TLS|HTTPS)\b", props.get("protocol") or "", re.I) else "unknown"}
                    if recorded(props.get("negotiatedVersion")):
                        protocol["version"] = props["negotiatedVersion"]
                    component["cryptoProperties"] = {"assetType": "protocol", "protocolProperties": protocol}
                    for purpose in ("encryption", "hash", "keyExchange", "authentication"):
                        target = algorithm(props.get(purpose) or {}, f"{ref}:{purpose}", evidence, purpose)
                        if target:
                            related.append({"type": "algorithm", "ref": target["bom-ref"]})
                    # A cloud TLS policy name is not evidence of negotiated algorithms.
                    if related:
                        protocol["relatedCryptographicAssets"] = related
                elif finding.get("type") == "x509-certificate":
                    certificate = {"certificateFormat": "X.509"}
                    component["cryptoProperties"] = {"assetType": "certificate", "certificateProperties": certificate}
                    for field, purpose, relation in (("signatureAlgorithm", "certificate-signature", "signatureAlgorithm"),
                                                     ("keyAlgorithm", "certificate-key-algorithm", "algorithm")):
                        target = algorithm({"algorithm": props.get(field)}, f"{ref}:{field}", evidence, purpose)
                        if target:
                            related.append({"type": relation, "ref": target["bom-ref"]})
                    if related:
                        certificate["relatedCryptographicAssets"] = related
                elif finding.get("type") == "cloud-kms-key":
                    material = {"type": "key"}
                    if finding.get("arn"):
                        material["id"] = finding["arn"]
                    component["cryptoProperties"] = {"assetType": "related-crypto-material", "relatedCryptoMaterialProperties": material}
                    target = algorithm({"algorithm": props.get("keySpec")}, f"{ref}:algorithm", evidence, "key-specification")
                    if target:
                        related.append({"type": "algorithm", "ref": target["bom-ref"]})
                        material["relatedCryptographicAssets"] = related
                else:
                    component["cryptoProperties"] = {"assetType": "algorithm", "algorithmProperties": {"primitive": "unknown"}}
                if related:
                    dependencies.append({"ref": ref, "dependsOn": [asset["ref"] for asset in related]})
            assessment = finding.get("quantumRiskAssessment", {})
            component.setdefault("properties", []).extend(properties({
                "report:kind": kind, "risk:tier": finding.get("risk", assessment.get("tier")),
                "risk:reason": assessment.get("reason"), "risk:threat": assessment.get("threat"),
                "risk:suggestion": assessment.get("suggestion"), "scanner:finding": finding,
            }))
            roots.append(ref)
    return {
        "$schema": "https://cyclonedx.org/schema/bom-1.7.schema.json", "bomFormat": "CycloneDX", "specVersion": "1.7",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
        "metadata": {"timestamp": datetime.now(timezone.utc).isoformat(), "component": subject,
                     "tools": {"components": [{"type": "application", "name": "QuantumTrace"}]},
                     "properties": properties({"source:id": source["id"], "source:kind": source["kind"],
                         "export:scope": "All database reports for the selected source; inventory filters do not apply.",
                         "scanner:reports": headers,
                         "inventory:limitations": "Scanner observations only. Code detection and risk ratings are heuristic; completeness and cryptographic implementation correctness are not established."})},
        "components": components, "dependencies": [{"ref": subject["bom-ref"], "dependsOn": roots}, *dependencies],
        "compositions": [{"aggregate": "unknown", "assemblies": [subject["bom-ref"]]}],
    }
