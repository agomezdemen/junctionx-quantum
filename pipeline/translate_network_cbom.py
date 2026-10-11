"""Replace TLS identifiers with readable names using the bundled IANA CSVs."""

import argparse
import csv
import json
import re
from pathlib import Path


def numeric_id(value):
    """Read decimal IDs, hex IDs, or IANA's two-byte hex notation."""
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise TypeError("Expected a numeric identifier")
    text = str(value).strip()
    if "," in text:
        high, low = (int(part.strip(), 16) for part in text.split(","))
        if not (0 <= high <= 255 and 0 <= low <= 255):
            raise ValueError("Invalid byte pair")
        return high * 256 + low
    return int(text, 16 if text.lower().startswith("0x") else 10)


def load_names(path):
    names = {}
    with path.open(encoding="utf-8", newline="") as source:
        for row in csv.DictReader(source):
            if row["Description"].startswith(("Reserved", "Unassigned")):
                continue
            try:
                names[numeric_id(row["Value"])] = row["Description"]
            except ValueError:
                continue  # Ranges are not individual algorithm identifiers.
    return names


def readable_name(value, names):
    if isinstance(value, dict):
        value = value.get("name")
    if value in (None, "", "Legacy_Or_None", "Not recorded"):
        return "Not recorded"
    if value in ("ClientHello_Only", "Not recorded (ClientHello only)"):
        return "Not recorded (ClientHello only)"
    try:
        return names.get(numeric_id(value), "Unknown algorithm")
    except ValueError:
        # Existing analyzer output sometimes already contains group names.
        return next(
            (
                name
                for name in names.values()
                if name.removesuffix(" (OBSOLETE)").lower() == str(value).lower()
            ),
            "Unknown algorithm",
        )


def split_cipher_suite(name):
    """Extract parameters from known naming patterns, never guess missing sizes.

    TLS 1.3: RFC 8446 section 4.1.2; older suites: RFC 5246 appendix A.5.
    """
    result = {"name": name}
    if not name.startswith("TLS_"):
        return result
    if name.endswith("_SCSV"):
        return {"name": name, "type": "Signaling value (not an encryption suite)"}
    prefix, separator, body = name.removeprefix("TLS_").partition("_WITH_")
    if not separator:
        body = prefix
        result["keyExchange"] = "Negotiated separately"
        result["authentication"] = "Negotiated separately"
    else:
        exchange = prefix.removesuffix("_EXPORT")
        exchanges = {
            "RSA": ("RSA", "RSA"),
            "DHE_RSA": ("DHE", "RSA"),
            "DHE_DSS": ("DHE", "DSA"),
            "ECDHE_RSA": ("ECDHE", "RSA"),
            "ECDHE_ECDSA": ("ECDHE", "ECDSA"),
            "DH_RSA": ("DH", "RSA"),
            "DH_DSS": ("DH", "DSA"),
            "ECDH_RSA": ("ECDH", "RSA"),
            "ECDH_ECDSA": ("ECDH", "ECDSA"),
            "DH_anon": ("DH", "None"),
            "ECDH_anon": ("ECDH", "None"),
            "PSK": ("PSK", "PSK"),
            "DHE_PSK": ("DHE + PSK", "PSK"),
            "ECDHE_PSK": ("ECDHE + PSK", "PSK"),
            "RSA_PSK": ("RSA + PSK", "RSA + PSK"),
        }
        result["keyExchange"], result["authentication"] = exchanges.get(
            exchange, (exchange, "Not determined")
        )
        if "EXPORT" in prefix:
            result["exportRestricted"] = True

    hashed = re.search(r"_(SHA512|SHA384|SHA256|SHA|MD5|SM3|ASCONHASH256)$", body)
    if hashed:
        token = hashed[1]
        algorithm, bits = {
            "SHA": ("SHA-1", 160),
            "SHA256": ("SHA-256", 256),
            "SHA384": ("SHA-384", 384),
            "SHA512": ("SHA-512", 512),
            "MD5": ("MD5", 128),
            "SM3": ("SM3", 256),
            "ASCONHASH256": ("Ascon-Hash256", 256),
        }[token]
        result["hash"] = {"algorithm": algorithm, "outputBits": bits}
        body = body[: hashed.start()]

    encryption = {"algorithm": body, "keySizeBits": None, "mode": None}
    sized = re.fullmatch(r"(AES|CAMELLIA|ARIA)_(128|192|256)_(CBC|GCM|CCM|CCM_8)", body)
    if sized:
        algorithm, bits, mode = sized.groups()
        encryption.update(
            algorithm=algorithm, keySizeBits=int(bits), mode=mode.removesuffix("_8")
        )
        if mode in ("GCM", "CCM", "CCM_8"):
            encryption["authenticationTagBits"] = 64 if mode == "CCM_8" else 128
    elif body == "CHACHA20_POLY1305":
        encryption.update(
            algorithm="ChaCha20",
            keySizeBits=256,
            mode="Stream cipher",
            authenticator="Poly1305",
            authenticationTagBits=128,
        )
    elif body in ("SM4_GCM", "SM4_CCM"):
        encryption.update(
            algorithm="SM4",
            keySizeBits=128,
            mode=body.split("_")[1],
            authenticationTagBits=128,
        )
    elif body == "3DES_EDE_CBC":
        encryption.update(
            algorithm="3DES", keySizeBits=168, mode="CBC", construction="EDE"
        )
    elif body in ("DES_CBC", "DES40_CBC", "IDEA_CBC"):
        algorithm, bits = {
            "DES_CBC": ("DES", 56),
            "DES40_CBC": ("DES", 40),
            "IDEA_CBC": ("IDEA", 128),
        }[body]
        encryption.update(algorithm=algorithm, keySizeBits=bits, mode="CBC")
    elif body.startswith("RC4_") and body[4:].isdigit():
        encryption.update(
            algorithm="RC4", keySizeBits=int(body[4:]), mode="Stream cipher"
        )
    elif body == "NULL":
        encryption.update(algorithm="None", keySizeBits=0)
    result["encryption"] = encryption
    if "hash" in result:
        result["hash"]["role"] = (
            "HKDF and transcript hash"
            if not separator
            else "PRF hash"
            if "authenticationTagBits" in encryption
            else "HMAC hash"
        )
    return result


def split_group(name):
    """Separate curve/modulus sizes from PQC parameter sets."""
    result = {"name": name}
    pqc = re.search(r"(MLKEM|Kyber)(512|768|1024)", name)
    parts = []
    lower = name.lower()
    if "x25519" in lower or lower == "x448":
        parts.append(
            {
                "algorithm": "ECDH",
                "curve": "X25519" if "x25519" in lower else "X448",
                "curveBits": 255 if "x25519" in lower else 448,
            }
        )
    else:
        curve = re.search(r"(sec[pt](\d+)[kr]\d|brainpoolP(\d+)r1)", name, re.I)
        if curve:
            parts.append(
                {
                    "algorithm": "ECDH",
                    "curve": curve[1],
                    "curveBits": int(curve[2] or curve[3]),
                }
            )
        elif lower.startswith("ffdhe") and lower[5:].isdigit():
            parts.append({"algorithm": "DH", "modulusBits": int(lower[5:])})
        elif "SM2" in name:
            parts.append({"algorithm": "ECDH", "curve": "SM2", "curveBits": 256})
    if pqc:
        algorithm = "ML-KEM" if pqc[1] == "MLKEM" else "Kyber (pre-standard)"
        part = {"algorithm": algorithm, "parameterSet": pqc[2]}
        if pqc[1] == "MLKEM":
            part["nistSecurityLevel"] = {"512": 1, "768": 3, "1024": 5}[pqc[2]]
        parts.append(part)
    if parts:
        result["components"] = parts
        result["hybrid"] = len(parts) > 1
    return result


def translate_cbom(cbom):
    """Replace cryptographic IDs in place, retaining session metadata."""
    directory = Path(__file__).resolve().parent
    suites = load_names(directory / "tls_cipher_suites.csv")
    groups = load_names(directory / "tls_supported_groups.csv")
    for component in cbom.get("components", []):
        if component.get("type") != "network-session":
            continue
        properties = component["cryptoProperties"]
        properties["cipherSuite"] = split_cipher_suite(
            readable_name(properties.get("cipherSuite"), suites)
        )
        properties["keyExchangeGroup"] = split_group(
            readable_name(properties.get("keyExchangeGroup"), groups)
        )
        properties["supportedGroups"] = [
            split_group(readable_name(value, groups))
            for value in properties.get("supportedGroups", [])
        ]
        # The analyzer records ClientHello.version, not the negotiated version.
        properties["protocol"] = "TLS (negotiated version not determined)"
        for field in (
            "cipherSuiteName",
            "keyExchangeGroupName",
            "supportedGroupNames",
            "protocolNote",
        ):
            properties.pop(field, None)
    return cbom


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="Original network CBOM JSON")
    parser.add_argument("output", type=Path, help="Readable network CBOM JSON")
    args = parser.parse_args()
    if args.input.resolve() == args.output.resolve():
        parser.error("Choose a separate output file to preserve the original CBOM.")
    with args.input.open(encoding="utf-8") as source:
        cbom = translate_cbom(json.load(source))
    args.output.write_text(json.dumps(cbom, indent=2) + "\n", encoding="utf-8")
    print(f"Readable CBOM saved to {args.output}")
