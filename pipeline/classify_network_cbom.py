"""Classify a structured, readable network CBOM using the hackathon risk matrix."""

import argparse
import json
from collections import Counter
from copy import deepcopy
from pathlib import Path

POLICY = {
    "primary": "pdfs/inspiring_solutions.pdf",
    "keySizeReference": "pdfs/nist_standards.pdf",
    "sha1Resolution": "SHA-1 is Medium per the challenge brief; the reference matrix instead rates it Critical.",
}
CLASSICAL = {
    "RSA",
    "DSA",
    "ECDSA",
    "ECDH",
    "ECDHE",
    "DH",
    "DHE",
    "X25519",
    "X448",
    "Ed25519",
    "Ed448",
}
# Only recognized combined constructions get a hybrid assessment.
MLKEM_GROUPS = {
    "MLKEM512",
    "MLKEM768",
    "MLKEM1024",
    "SecP256r1MLKEM512",
    "MLKEM512X25519",
    "SecP256r1MLKEM768",
    "X25519MLKEM768",
    "SecP384r1MLKEM1024",
    "curveSM2MLKEM768",
}


def finding(risk, reason, suggestion=None, standard=None):
    result = {"risk": risk, "reason": reason}
    if suggestion:
        result["suggestion"] = suggestion
    if standard:
        result["nistStandard"] = standard
    return result


def primitive_risk(details, purpose):
    algorithm = details.get("algorithm")
    if algorithm in CLASSICAL or (
        isinstance(algorithm, str)
        and any(part in CLASSICAL for part in algorithm.split(" + "))
    ):
        signing = purpose == "authentication"
        return finding(
            "CRITICAL",
            "Vulnerable to Shor's algorithm regardless of key size.",
            "Migrate signatures to ML-DSA or SLH-DSA."
            if signing
            else "Migrate key exchange to ML-KEM or a supported ML-KEM hybrid.",
            "FIPS 204 / 205" if signing else "FIPS 203",
        )
    if algorithm == "AES":
        bits = details.get("keySizeBits")
        if type(bits) is not int or bits not in (128, 192, 256):
            return finding("UNKNOWN", "AES key size is missing or invalid.")
        return finding(
            "SAFE" if bits == 256 else "MEDIUM",
            f"The matrix's generic quantum key-search model gives approximately {bits // 2}-bit security.",
            "Keep AES-256."
            if bits == 256
            else "Increase the encryption key size to AES-256.",
        )
    if algorithm == "3DES":
        return finding(
            "MEDIUM",
            "Legacy symmetric cipher rated Medium by the challenge brief.",
            "Migrate to AES-256 with an authenticated encryption mode.",
        )
    if algorithm == "SHA-1":
        return finding(
            "MEDIUM",
            "SHA-1 is Medium under the challenge brief's quantum risk tiers. "
            "The reference matrix rates it Critical for classical collision weaknesses; "
            "collisions alone do not establish an HMAC forgery.",
            "Migrate to a SHA-256 or stronger hash-based construction.",
        )
    if algorithm == "MD5":
        reason = "The supplied risk matrix classifies this hash as Critical."
        if details.get("role") == "HMAC hash":
            reason += " This is a policy rating; hash collisions do not by themselves demonstrate an HMAC forgery."
        return finding(
            "CRITICAL",
            reason,
            "Migrate to a SHA-256 or stronger hash-based construction.",
        )
    if algorithm in ("SHA-256", "SHA-384", "SHA-512"):
        return finding(
            "SAFE",
            "Accepted SHA-2 hash under the supplied matrix and its recommended alternatives.",
        )
    parameters = {"ML-KEM": {"512", "768", "1024"}, "ML-DSA": {"44", "65", "87"}}
    if (
        algorithm in parameters
        and str(details.get("parameterSet")) in parameters[algorithm]
    ):
        return finding(
            "SAFE",
            "Recognized NIST post-quantum parameter set.",
            standard="FIPS 203" if algorithm == "ML-KEM" else "FIPS 204",
        )
    return finding(
        "UNKNOWN", "Algorithm, parameters, or classification rule are unavailable."
    )


def combined_risk(findings):
    risks = {item["risk"] for item in findings}
    # A known critical finding stands even when other evidence is missing.
    return next(
        (risk for risk in ("CRITICAL", "UNKNOWN", "MEDIUM", "SAFE") if risk in risks),
        "UNKNOWN",
    )


def classify_session(properties):
    suite = properties.get("cipherSuite", {})
    group = properties.get("keyExchangeGroup", {})
    if not isinstance(suite, dict) or not isinstance(group, dict):
        raise TypeError(
            "Expected structured readable CBOM; run translate_cbom.py first."
        )
    encryption = primitive_risk(suite.get("encryption", {}), "encryption")
    hashed = primitive_risk(suite.get("hash", {}), "hash")
    authentication_details = suite.get("authentication") or {}
    if isinstance(authentication_details, str):
        authentication_details = {"algorithm": authentication_details}
    authentication_available = (
        authentication_details.get("algorithm") or ""
    ).strip() not in (
        "",
        "Negotiated separately",
        "Not recorded",
        "Not determined",
    )
    authentication = primitive_risk(authentication_details, "authentication")
    exchange_details = suite.get("keyExchange", {})
    if isinstance(exchange_details, str):
        exchange_details = {"algorithm": exchange_details}
    exchange = primitive_risk(exchange_details, "keyExchange")
    parts = group.get("components", [])
    part_findings = [{**part, **primitive_risk(part, "keyExchange")} for part in parts]
    if exchange_details.get("algorithm") in (
        "Negotiated separately",
        group.get("name"),
    ):
        if (
            group.get("name") in MLKEM_GROUPS
            and any(
                part.get("algorithm") == "ML-KEM" and result["risk"] == "SAFE"
                for part, result in zip(parts, part_findings)
            )
            and all(part.get("algorithm") in ("ML-KEM", "ECDH") for part in parts)
        ):
            exchange = finding(
                "SAFE",
                "Recognized ML-KEM group; a hybrid is assessed as a combined construction.",
                standard="FIPS 203 (ML-KEM component)",
            )
        elif part_findings:
            exchange = finding(
                combined_risk(part_findings),
                "Assessment of the recorded negotiated group.",
            )
    exchange["components"] = part_findings
    if group.get("hybrid"):
        for part in part_findings:
            part["riskScope"] = (
                "Primitive considered alone; see the combined key-exchange rating."
            )
    findings = {
        "encryption": encryption,
        "hash": hashed,
        "keyExchange": exchange,
        "authentication": authentication,
    }
    # Missing authentication remains visible as evidence, but does not set session risk.
    overall_findings = [encryption, hashed, exchange]
    if authentication_available:
        overall_findings.append(authentication)
    return {
        "risk": combined_risk(overall_findings),
        "encryptionAndKeyExchangeRisk": combined_risk([encryption, exchange]),
        "findings": findings,
        "missingOrUnsupported": [
            name for name, item in findings.items() if item["risk"] == "UNKNOWN"
        ],
        "policy": POLICY,
        "scope": "Quantum risk of reported algorithms; authentication contributes only when recorded. "
        "Not a complete TLS configuration or certificate audit.",
    }


def compact_algorithm(details, assessment):
    fields = (
        "keySizeBits",
        "mode",
        "authenticationTagBits",
        "authenticator",
        "construction",
        "outputBits",
        "role",
        "curve",
        "curveBits",
        "modulusBits",
        "parameterSet",
        "nistSecurityLevel",
    )
    result = {
        "algorithm": details.get("algorithm", "Not recorded"),
        "risk": assessment["risk"],
    }
    result.update({key: details[key] for key in fields if details.get(key) is not None})
    return result


def classify_cbom(cbom):
    if not isinstance(cbom, dict) or not isinstance(cbom.get("components"), list):
        raise TypeError("Expected a CBOM object containing a components list.")
    cbom = deepcopy(cbom)
    session_counts = Counter()
    algorithm_counts = Counter()
    for component in cbom["components"]:
        if component.get("type") != "network-session":
            continue
        properties = component["cryptoProperties"]
        assessment = classify_session(properties)
        suite = properties["cipherSuite"]
        findings = assessment["findings"]
        clean = {"protocol": "TLS", "negotiatedVersion": None}
        for purpose in ("encryption", "hash"):
            clean[purpose] = compact_algorithm(
                suite.get(purpose, {}), findings[purpose]
            )
        for purpose in ("keyExchange", "authentication"):
            algorithm = suite.get(purpose) or "Not recorded"
            if isinstance(algorithm, dict):
                algorithm = algorithm.get("algorithm", "Not recorded")
            clean[purpose] = compact_algorithm(
                {"algorithm": algorithm}, findings[purpose]
            )
        if clean["authentication"]["algorithm"] == "Negotiated separately":
            clean["authentication"]["algorithm"] = "Not recorded"
        parts = findings["keyExchange"]["components"]
        if clean["keyExchange"]["algorithm"] == "Negotiated separately":
            if len(parts) == 1:
                clean["keyExchange"] = compact_algorithm(
                    parts[0], findings["keyExchange"]
                )
            elif len(parts) > 1:
                clean["keyExchange"] = {
                    "algorithm": "Hybrid key exchange",
                    "risk": findings["keyExchange"]["risk"],
                    "components": [compact_algorithm(part, part) for part in parts],
                }
            else:
                clean["keyExchange"]["algorithm"] = "Not recorded"
        # Offered groups are distinct evidence, but need no duplicate breakdown.
        if properties.get("supportedGroups"):
            clean["offeredGroups"] = [
                group["name"] for group in properties["supportedGroups"]
            ]
        component["cryptoProperties"] = clean
        component.pop("quantumAssessment", None)
        component["risk"] = assessment["risk"]
        if component.get("source") == cbom.get("metadata", {}).get("sourceFile"):
            component.pop("source", None)
        session_counts[assessment["risk"]] += 1
        algorithm_counts.update(item["risk"] for item in findings.values())
    cbom["classificationSummary"] = {
        "sessionRiskCounts": {
            risk: session_counts[risk]
            for risk in ("CRITICAL", "MEDIUM", "SAFE", "UNKNOWN")
        },
        "algorithmRiskCounts": {
            risk: algorithm_counts[risk]
            for risk in ("CRITICAL", "MEDIUM", "SAFE", "UNKNOWN")
        },
    }
    return cbom


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="Structured human-readable CBOM JSON")
    parser.add_argument("output", type=Path, help="Classified CBOM JSON")
    args = parser.parse_args()
    if args.input.resolve() == args.output.resolve():
        parser.error("Choose a separate output file to preserve the readable input.")
    try:
        with args.input.open(encoding="utf-8") as source:
            cbom = classify_cbom(json.load(source))
    except (ValueError, KeyError, TypeError) as error:
        parser.error(str(error))
    args.output.write_text(json.dumps(cbom, indent=2) + "\n", encoding="utf-8")
    print(f"Classified CBOM saved to {args.output}")
    print(json.dumps(cbom["classificationSummary"], indent=2))
