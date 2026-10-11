import json
import os


def evaluate_cloud_crypto(key_spec_or_alg: str) -> dict[str, str]:
    """Classify KMS, ACM, and ELB policy algorithms against Shor and Grover."""
    val = (key_spec_or_alg or "").upper()

    if val in ["SYMMETRIC_DEFAULT", "AES_256", "AES-256"]:
        return {
            "tier": "Safe",
            "threat": "None",
            "reason": "256-bit symmetric key (AES-256-GCM). Grover reduces effective security to 128 bits, remaining safe.",
        }

    if any(k in val for k in ["RSA", "ECC", "ECDSA", "SECP", "PRIME256"]):
        return {
            "tier": "Critical",
            "threat": "Shor",
            "reason": f"Classical asymmetric primitive ({val}) fully vulnerable to factorization or discrete logarithm via Shor's Algorithm.",
        }

    if "ELBSECURITYPOLICY" in val:
        if "TLS13" in val:
            return {
                "tier": "Critical",
                "threat": "Shor",
                "reason": "Policy supports TLS 1.3 but uses classical AWS ECDHE curves without PQC hybrid groups (vulnerable to Harvest Now, Decrypt Later).",
            }
        else:
            return {
                "tier": "Critical",
                "threat": "Shor / Legacy",
                "reason": "Legacy TLS policy with obsolete ciphers and classical static/ECDHE key exchange vulnerable to Shor.",
            }

    return {
        "tier": "Medium",
        "threat": "Grover / Inconclusive",
        "reason": f"Configuration requires further analysis: {val}",
    }


def scan_cloud_posture(
    base_dir: str = "../input_files/cloud-posture", output_file: str = "cbom_cloud.json"
):
    if not os.path.exists(base_dir):
        if os.path.exists("input_files/cloud-posture"):
            base_dir = "input_files/cloud-posture"
        elif os.path.exists("./cloud-posture"):
            base_dir = "./cloud-posture"

    kms_path = os.path.join(base_dir, "kms_key_inventory.json")
    acm_path = os.path.join(base_dir, "acm_certificates.json")
    elb_path = os.path.join(base_dir, "load_balancer_listeners.json")

    components: list[dict] = []
    stats = {"Critical": 0, "Medium": 0, "Safe": 0}

    if os.path.exists(kms_path):
        with open(kms_path, "r", encoding="utf-8") as f:
            kms_data = json.load(f)
        for key in kms_data.get("Keys", []):
            spec = key.get("KeySpec", "UNKNOWN")
            eval_res = evaluate_cloud_crypto(spec)
            stats[eval_res["tier"]] += 1

            components.append(
                {
                    "type": "cloud-kms-key",
                    "name": key.get("AliasName", key.get("KeyId")),
                    "source": kms_path,
                    "arn": key.get("KeyArn"),
                    "cryptoProperties": {
                        "assetType": "key",
                        "keySpec": spec,
                        "keyUsage": key.get("KeyUsage"),
                        "keyRotationEnabled": key.get("KeyRotationStatus") == "ENABLED",
                        "origin": key.get("Origin"),
                    },
                    "quantumRiskAssessment": eval_res,
                }
            )

    if os.path.exists(acm_path):
        with open(acm_path, "r", encoding="utf-8") as f:
            acm_data = json.load(f)
        for cert in acm_data.get("Certificates", []):
            alg = cert.get("KeyAlgorithm", "UNKNOWN")
            eval_res = evaluate_cloud_crypto(alg)
            stats[eval_res["tier"]] += 1

            components.append(
                {
                    "type": "x509-certificate",
                    "name": cert.get("DomainName"),
                    "source": acm_path,
                    "arn": cert.get("CertificateArn"),
                    "cryptoProperties": {
                        "assetType": "certificate",
                        "keyAlgorithm": alg,
                        "signatureAlgorithm": cert.get("SignatureAlgorithm"),
                        "type": cert.get("Type"),
                        "status": cert.get("Status"),
                    },
                    "quantumRiskAssessment": eval_res,
                }
            )

    if os.path.exists(elb_path):
        with open(elb_path, "r", encoding="utf-8") as f:
            elb_data = json.load(f)
        for lb in elb_data.get("LoadBalancers", []):
            lb_name = lb.get("LoadBalancerName")
            for listener in lb.get("Listeners", []):
                proto = listener.get("Protocol")
                if proto not in ["HTTPS", "TLS"]:
                    continue

                policy = listener.get("SslPolicy", "NONE")
                eval_res = evaluate_cloud_crypto(policy)
                stats[eval_res["tier"]] += 1

                components.append(
                    {
                        "type": "load-balancer-listener",
                        "name": f"{lb_name}:{listener.get('Port')}",
                        "source": elb_path,
                        "arn": listener.get("ListenerArn"),
                        "cryptoProperties": {
                            "assetType": "protocol-policy",
                            "protocol": proto,
                            "port": listener.get("Port"),
                            "sslPolicy": policy,
                            "associatedCertificates": [
                                c.get("CertificateArn")
                                for c in listener.get("Certificates", [])
                            ],
                        },
                        "quantumRiskAssessment": eval_res,
                    }
                )

    total = len(components)
    score = round(
        ((stats["Critical"] * 1.0 + stats["Medium"] * 0.4) / max(total, 1)) * 100, 2
    )

    cbom_cloud = {
        "bomFormat": "CycloneDX-CBOM-Draft",
        "specVersion": "1.6",
        "metadata": {
            "source": "AWS Cloud Posture Audit",
            "quantumRiskSummary": {
                "totalAssets": total,
                "criticalAssets": stats["Critical"],
                "mediumAssets": stats["Medium"],
                "safeAssets": stats["Safe"],
                "quantumRiskScore": f"{score}%",
            },
        },
        "components": components,
    }

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(cbom_cloud, f, indent=2)

    print("[✓] Cloud CBOM successfully created!")
    print(f"    - Total Assets Audited: {total}")
    print(f"    - Critical (Shor): {stats['Critical']}")
    print(f"    - Medium (Grover): {stats['Medium']}")
    print(f"    - Safe (AES-256): {stats['Safe']}")
    print(f"    - Cloud Quantum Risk Score: {score}%")
    print(f"    - File saved to: '{output_file}'")


if __name__ == "__main__":
    scan_cloud_posture()
