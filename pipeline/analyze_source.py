"""Run existing scanners in an isolated source directory; never execute input code."""

import json
import os
import sys
from pathlib import Path

from pipeline.classify_network_cbom import classify_cbom
from pipeline.cloud_posture_scanner import scan_cloud_posture
from pipeline.code_scanner import scan_repositories
from pipeline.translate_network_cbom import translate_cbom

CLOUD_FILES = {
    "kms_key_inventory.json",
    "acm_certificates.json",
    "load_balancer_listeners.json",
}
MAX_BYTES = 100 * 1024 * 1024
MAX_FILES = 2000


def source_files(root):
    files = []
    total = 0
    for directory, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = [
            name
            for name in dirs
            if name not in {".git", "node_modules", ".venv", "venv", "__pycache__"}
            and not (Path(directory) / name).is_symlink()
        ]
        for name in names:
            path = Path(directory) / name
            if path.is_symlink() or not path.is_file():
                continue
            total += path.stat().st_size
            if total > MAX_BYTES or len(files) >= MAX_FILES:
                raise ValueError(
                    "Source exceeds the 100 MiB / 2,000 file analysis limit."
                )
            files.append(path)
    return files


def analyze(root, output):
    files = source_files(root)
    reports = {}
    scratch = output.parent
    if any(path.suffix.lower() in {".py", ".java", ".go"} for path in files):
        scan_repositories(str(root), str(scratch / "code.json"))
        reports["code"] = json.loads((scratch / "code.json").read_text())
    for folder in sorted({path.parent for path in files if path.name in CLOUD_FILES}):
        scan_cloud_posture(str(folder), str(scratch / "cloud.json"))
        report = json.loads((scratch / "cloud.json").read_text())
        reports.setdefault("cloud", {"components": []})["components"].extend(
            report["components"]
        )
    for path in files:
        if path.suffix.lower() in {".pcap", ".pcapng"}:
            try:
                from pipeline.pcap_scanner import analyze_pcap_to_cbom
            except ImportError as error:
                raise ValueError(
                    "Packet analysis requires Scapy. Install requirements.txt and retry."
                ) from error
            report = classify_cbom(
                translate_cbom(
                    analyze_pcap_to_cbom(str(path), str(scratch / "network.json"))
                )
            )
            for component in report["components"]:
                component["source"] = str(path)
            reports.setdefault("network", {"components": []})["components"].extend(
                report["components"]
            )
        elif path.suffix.lower() == ".json" and path.name not in CLOUD_FILES:
            # Also accept existing scanner exports without reclassifying their ratings.
            try:
                report = json.loads(path.read_text(encoding="utf-8"))
            except (ValueError, UnicodeError):
                continue
            if not isinstance(report, dict) or not isinstance(
                report.get("components"), list
            ):
                continue
            for component in report["components"]:
                if not isinstance(component, dict):
                    raise TypeError(f"Invalid CBOM component in {path.name}.")
                kind = {
                    "network-session": "network",
                    "application-code": "code",
                    "cloud-kms-key": "cloud",
                    "x509-certificate": "cloud",
                    "load-balancer-listener": "cloud",
                }.get(component.get("type"))
                if kind:
                    if kind == "network" and "risk" not in component:
                        individual = {
                            "metadata": report.get("metadata", {}),
                            "components": [component],
                        }
                        if not isinstance(
                            component.get("cryptoProperties", {}).get("cipherSuite"),
                            dict,
                        ):
                            translate_cbom(individual)
                        component = classify_cbom(individual)["components"][0]
                    component.setdefault(
                        "source",
                        report.get("metadata", {}).get("sourceFile") or str(path),
                    )
                    reports.setdefault(kind, {"components": []})["components"].append(
                        component
                    )
    if not reports:
        raise ValueError(
            "No supported inputs found. Add Python, Java, Go, PCAP/PCAPNG, a CBOM report, or supported cloud inventory JSON."
        )
    for report in reports.values():
        for component in report["components"]:
            source = component.get("source")
            if (
                source
                and Path(source).is_absolute()
                and Path(source).is_relative_to(root)
            ):
                component["source"] = str(Path(source).relative_to(root))
        report.setdefault("metadata", {})["inputFileCount"] = len(files)
    output.write_text(json.dumps(reports), encoding="utf-8")


if __name__ == "__main__":
    try:
        analyze(Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve())
    except Exception as error:
        print(f"Analysis failed: {error}", file=sys.stderr)
        sys.exit(1)
