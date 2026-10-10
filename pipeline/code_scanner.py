import os
import re
import json
from typing import Dict, Any, List

# Padrões regex por linguagem com indicação de algoritmo e família
RULES = [
    # --- Python ---
    {
        "lang": "python",
        "ext": [".py"],
        "regex": r"(?:RSA\.generate\(\s*(\d+)|algorithms\.RSA\(\s*(\d+))",
        "name_fmt": lambda m: f"RSA-{m.group(1) or m.group(2)}",
        "threat": "Shor",
        "tier": "Critical",
        "reason": "Chave assimétrica RSA vulnerável à fatorização via Algoritmo de Shor."
    },
    {
        "lang": "python",
        "ext": [".py"],
        "regex": r"(?:ec\.SECP(\d+)R1|ec\.generate_private_key\([^)]*SECP(\d+))",
        "name_fmt": lambda m: f"ECDSA-SECP{m.group(1) or m.group(2)}R1",
        "threat": "Shor",
        "tier": "Critical",
        "reason": "Curva elíptica clássica vulnerável a logaritmo discreto via Algoritmo de Shor."
    },
    {
        "lang": "python",
        "ext": [".py"],
        "regex": r"(?:algorithms\.AES\([^)]*\)|AES\.new\([^)]*\))",
        "name_fmt": lambda m: "AES",
        "threat": "Grover",
        "tier": "Medium",
        "reason": "Cifra simétrica padrão; requer chaves >= 256 bits para resistir a Grover."
    },
    {
        "lang": "python",
        "ext": [".py"],
        "regex": r"(?:hashes\.SHA1\(\)|hashlib\.sha1\(\)|hashlib\.md5\(\))",
        "name_fmt": lambda m: "Legacy-Hash (SHA1/MD5)",
        "threat": "Classical Weakness",
        "tier": "Critical",
        "reason": "Função de dispersão obsoleta com colisões clássicas e suscetível a Grover."
    },
    {
        "lang": "python",
        "ext": [".py"],
        "regex": r"(?:kyber|mlkem|dilithium|sphincs)",
        "name_fmt": lambda m: f"PQC-{m.group(0).upper()}",
        "threat": "None",
        "tier": "Safe",
        "reason": "Algoritmo pós-quântico de reticulados/hashing resistente a Shor e Grover."
    },

    # --- Java ---
    {
        "lang": "java",
        "ext": [".java"],
        "regex": r'KeyPairGenerator\.getInstance\(\s*"RSA"\s*\)',
        "name_fmt": lambda m: "RSA (Java KeyPairGenerator)",
        "threat": "Shor",
        "tier": "Critical",
        "reason": "Geração de chaves RSA em Java vulnerável a Shor."
    },
    {
        "lang": "java",
        "ext": [".java"],
        "regex": r'KeyPairGenerator\.getInstance\(\s*"(?:EC|ECDSA)"\s*\)',
        "name_fmt": lambda m: "ECDSA (Java KeyPairGenerator)",
        "threat": "Shor",
        "tier": "Critical",
        "reason": "Curvas elípticas clássicas em Java vulneráveis a Shor."
    },
    {
        "lang": "java",
        "ext": [".java"],
        "regex": r'Cipher\.getInstance\(\s*"AES(?:/[^"]+)?"\s*\)',
        "name_fmt": lambda m: "AES (Java Cipher)",
        "threat": "Grover",
        "tier": "Medium",
        "reason": "Cifra simétrica AES; verificar se chave é de 256 bits para imunidade prática a Grover."
    },
    {
        "lang": "java",
        "ext": [".java"],
        "regex": r'MessageDigest\.getInstance\(\s*"(?:SHA-1|MD5)"\s*\)',
        "name_fmt": lambda m: "SHA1/MD5 (Java MessageDigest)",
        "threat": "Classical Weakness",
        "tier": "Critical",
        "reason": "Digest criptográfico fraco e obsoleto."
    },
    {
        "lang": "java",
        "ext": [".java"],
        "regex": r'(?:MLKEM|Kyber|Dilithium|BNCrypto|BouncyCastlePQC)',
        "name_fmt": lambda m: f"PQC-Java-{m.group(0)}",
        "threat": "None",
        "tier": "Safe",
        "reason": "Primitiva PQC identificada em Java."
    },

    # --- Go ---
    {
        "lang": "go",
        "ext": [".go"],
        "regex": r"rsa\.GenerateKey\(",
        "name_fmt": lambda m: "RSA (crypto/rsa)",
        "threat": "Shor",
        "tier": "Critical",
        "reason": "Chave assimétrica RSA em Go vulnerável ao Algoritmo de Shor."
    },
    {
        "lang": "go",
        "ext": [".go"],
        "regex": r"ecdsa\.GenerateKey\(",
        "name_fmt": lambda m: "ECDSA (crypto/ecdsa)",
        "threat": "Shor",
        "tier": "Critical",
        "reason": "Curvas elípticas padrão da biblioteca crypto/ecdsa em Go vulneráveis a Shor."
    },
    {
        "lang": "go",
        "ext": [".go"],
        "regex": r"aes\.NewCipher\(",
        "name_fmt": lambda m: "AES (crypto/aes)",
        "threat": "Grover",
        "tier": "Medium",
        "reason": "Cifra AES em Go; Grover reduz o espaço de busca efetivo para metade do tamanho da chave."
    },
    {
        "lang": "go",
        "ext": [".go"],
        "regex": r"(?:circl/pqc|mlkem|kyber)",
        "name_fmt": lambda m: f"PQC-Go-{m.group(0)}",
        "threat": "None",
        "tier": "Safe",
        "reason": "Pacote pós-quântico (ex: Cloudflare CIRCL / ML-KEM) resistente a ataques quânticos."
    }
]

def scan_repositories(base_dir: str = "../input_files/sample-repos", output_file: str = "cbom_code.json"):
    # Fallback para caminhos comuns
    if not os.path.exists(base_dir):
        if os.path.exists("input_files/sample-repos"):
            base_dir = "input_files/sample-repos"
        elif os.path.exists("./sample-repos"):
            base_dir = "./sample-repos"

    components: List[Dict[str, Any]] = []
    stats = {"Critical": 0, "Medium": 0, "Safe": 0}

    print(f"[*] A iniciar varrimento SAST em: {base_dir}")

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
                        # Ignorar comentários simples
                        if clean_line.startswith(("//", "#", "/*", "*")):
                            continue

                        for rule in applicable_rules:
                            match = re.search(rule["regex"], line, re.IGNORECASE)
                            if match:
                                alg_name = rule["name_fmt"](match)
                                stats[rule["tier"]] += 1

                                components.append({
                                    "type": "application-code",
                                    "name": f"{file}:{line_num}",
                                    "source": file_path,
                                    "line": line_num,
                                    "codeSnippet": clean_line[:120],
                                    "cryptoProperties": {
                                        "assetType": "code-primitive",
                                        "language": rule["lang"],
                                        "detectedAlgorithm": alg_name
                                    },
                                    "quantumRiskAssessment": {
                                        "tier": rule["tier"],
                                        "threat": rule["threat"],
                                        "reason": rule["reason"]
                                    }
                                })
            except Exception as e:
                print(f"[!] Erro ao ler ficheiro {file_path}: {e}")

    total = len(components)
    score = round(((stats["Critical"] * 1.0 + stats["Medium"] * 0.4) / max(total, 1)) * 100, 2)

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
                "codeQuantumRiskScore": f"{score}%"
            }
        },
        "components": components
    }

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(cbom_code, f, indent=2)

    print(f"\n[✓] Varrimento de código concluído!")
    print(f"    - Total de Ocorrências: {total}")
    print(f"    - Críticas (Shor): {stats['Critical']}")
    print(f"    - Médias (Grover): {stats['Medium']}")
    print(f"    - Seguras (PQC): {stats['Safe']}")
    print(f"    - Score de Risco no Código: {score}%")
    print(f"    - Ficheiro gravado em: '{output_file}'")

    
if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "../input_files/sample-repos"
    scan_repositories(base_dir=target)