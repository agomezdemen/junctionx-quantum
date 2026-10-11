import json
import os
import re
from typing import Any

RULES = [
    {
        "lang": "python",
        "ext": [".py"],
        "regex": r"(?:RSA\.generate\(\s*(\d+)|algorithms\.RSA\(\s*(\d+))",
        "name_fmt": lambda m: f"RSA-{m.group(1) or m.group(2)}",
        "threat": "Shor",
        "tier": "Critical",
        "reason": "Asymmetric RSA key vulnerable to factoring via Shor's Algorithm.",
    },
    {
        "lang": "python",
        "ext": [".py"],
        "regex": r"(?:ec\.SECP(\d+)R1|ec\.generate_private_key\([^)]*SECP(\d+))",
        "name_fmt": lambda m: f"ECDSA-SECP{m.group(1) or m.group(2)}R1",
        "threat": "Shor",
        "tier": "Critical",
        "reason": "Classical elliptic curve vulnerable to discrete logarithm via Shor's Algorithm.",
    },
    {
        "lang": "python",
        "ext": [".py"],
        "regex": r"(?:algorithms\.AES\([^)]*\)|AES\.new\([^)]*\))",
        "name_fmt": lambda m: "AES",
        "threat": "Grover",
        "tier": "Medium",
        "reason": "Standard symmetric cipher; requires keys >= 256 bits to resist Grover.",
    },
    {
        "lang": "python",
        "ext": [".py"],
        "regex": r"(?:hashes\.SHA1\(\)|hashlib\.sha1\(\)|hashlib\.md5\(\))",
        "name_fmt": lambda m: "Legacy-Hash (SHA1/MD5)",
        "threat": "Classical Weakness",
        "tier": "Critical",
        "reason": "Obsolete hash function with classical collisions and susceptible to Grover.",
    },
    {
        "lang": "python",
        "ext": [".py"],
        "regex": r"(?:kyber|mlkem|dilithium|sphincs)",
        "name_fmt": lambda m: f"PQC-{m.group(0).upper()}",
        "threat": "None",
        "tier": "Safe",
        "reason": "Post-quantum lattice/hashing algorithm resistant to Shor and Grover.",
    },
    {
        "lang": "java",
        "ext": [".java"],
        "regex": r'KeyPairGenerator\.getInstance\(\s*"RSA"\s*\)',
        "name_fmt": lambda m: "RSA (Java KeyPairGenerator)",
        "threat": "Shor",
        "tier": "Critical",
        "reason": "RSA key generation in Java vulnerable to Shor.",
    },
    {
        "lang": "java",
        "ext": [".java"],
        "regex": r'KeyPairGenerator\.getInstance\(\s*"(?:EC|ECDSA)"\s*\)',
        "name_fmt": lambda m: "ECDSA (Java KeyPairGenerator)",
        "threat": "Shor",
        "tier": "Critical",
        "reason": "Classical elliptic curves in Java vulnerable to Shor.",
    },
    {
        "lang": "java",
        "ext": [".java"],
        "regex": r'Cipher\.getInstance\(\s*"AES(?:/[^"]+)?"\s*\)',
        "name_fmt": lambda m: "AES (Java Cipher)",
        "threat": "Grover",
        "tier": "Medium",
        "reason": "Symmetric AES cipher; verify if key is 256 bits for practical immunity to Grover.",
    },
    {
        "lang": "java",
        "ext": [".java"],
        "regex": r'MessageDigest\.getInstance\(\s*"(?:SHA-1|MD5)"\s*\)',
        "name_fmt": lambda m: "SHA1/MD5 (Java MessageDigest)",
        "threat": "Classical Weakness",
        "tier": "Critical",
        "reason": "Weak and obsolete cryptographic digest.",
    },
    {
        "lang": "java",
        "ext": [".java"],
        "regex": r"(?:MLKEM|Kyber|Dilithium|BNCrypto|BouncyCastlePQC)",
        "name_fmt": lambda m: f"PQC-Java-{m.group(0)}",
        "threat": "None",
        "tier": "Safe",
        "reason": "PQC primitive identified in Java.",
    },
    {
        "lang": "go",
        "ext": [".go"],
        "regex": r"rsa\.GenerateKey\(",
        "name_fmt": lambda m: "RSA (crypto/rsa)",
        "threat": "Shor",
        "tier": "Critical",
        "reason": "Asymmetric RSA key in Go vulnerable to Shor's Algorithm.",
    },
    {
        "lang": "go",
        "ext": [".go"],
        "regex": r"ecdsa\.GenerateKey\(",
        "name_fmt": lambda m: "ECDSA (crypto/ecdsa)",
        "threat": "Shor",
        "tier": "Critical",
        "reason": "Standard elliptic curves from crypto/ecdsa library in Go vulnerable to Shor.",
    },
    {
        "lang": "go",
        "ext": [".go"],
        "regex": r"aes\.NewCipher\(",
        "name_fmt": lambda m: "AES (crypto/aes)",
        "threat": "Grover",
        "tier": "Medium",
        "reason": "AES cipher in Go; Grover reduces the effective search space to half the key size.",
    },
    {
        "lang": "go",
        "ext": [".go"],
        "regex": r"(?:circl/pqc|mlkem|kyber)",
        "name_fmt": lambda m: f"PQC-Go-{m.group(0)}",
        "threat": "None",
        "tier": "Safe",
        "reason": "Post-quantum package resistant to quantum attacks.",
    },
]


def scan_repositories(
    base_dir: str = "../input_files/sample-repos", output_file: str = "cbom_code.json"
):
    if not os.path.exists(base_dir):
        if os.path.exists("input_files/sample-repos"):
            base_dir = "input_files/sample-repos"
        elif os.path.exists("./sample-repos"):
            base_dir = "./sample-repos"

    components: list[dict[str, Any]] = []
    stats = {"Critical": 0, "Medium": 0, "Safe": 0}

    for root, _, files in os.walk(base_dir):
        for file in files:
            file_ext = os.path.splitext(file)[1].lower()
            applicable_rules = [r for r in RULES if file_ext in r["ext"]]
            if not applicable_rules:
                continue

            file_path = os.path.join(root, file)

            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line_num, line in enumerate(f, start=1):
                        clean_line = line.strip()
                        if clean_line.startswith(("//", "#", "/*", "*")):
                            continue

                        for rule in applicable_rules:
                            match = re.search(rule["regex"], line, re.IGNORECASE)
                            if match:
                                alg_name = rule["name_fmt"](match)
                                stats[rule["tier"]] += 1

                                size_match = re.search(
                                    r"\b(128|192|256|512|1024|2048|3072|4096)\b",
                                    clean_line,
                                )
                                key_size = (
                                    int(size_match.group(1)) if size_match else None
                                )

                                components.append(
                                    {
                                        "type": "application-code",
                                        "name": f"{file}:{line_num}",
                                        "source": file_path,
                                        "line": line_num,
                                        "codeSnippet": clean_line[:120],
                                        "cryptoProperties": {
                                            "assetType": "code-primitive",
                                            "language": rule["lang"],
                                            "detectedAlgorithm": alg_name,
                                            "keySize": key_size,
                                        },
                                        "quantumRiskAssessment": {
                                            "tier": rule["tier"],
                                            "threat": rule["threat"],
                                            "reason": rule["reason"],
                                        },
                                    }
                                )
            except Exception:
                pass

    total = len(components)
    score = round(
        ((stats["Critical"] * 1.0 + stats["Medium"] * 0.4) / max(total, 1)) * 100, 2
    )

    cbom_code = {
        "bomFormat": "CycloneDX-CBOM-Draft",
        "specVersion": "1.6",
        "metadata": {
            "source": "Static Code Cryptographic Inventory (SAST)",
            "quantumRiskSummary": {
                "totalFindings": total,
                "criticalFindings": stats["Critical"],
                "mediumFindings": stats["Medium"],
                "safeFindings": stats["Safe"],
                "codeQuantumRiskScore": f"{score}%",
            },
        },
        "components": components,
    }

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(cbom_code, f, indent=2)


if __name__ == "__main__":
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "../input_files/sample-repos"
    scan_repositories(base_dir=target)
