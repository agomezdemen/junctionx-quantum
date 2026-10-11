import argparse
import json
import os
import shutil
from pathlib import Path

from code_scanner_2 import scan_repositories

from classify_network_cbom import classify_cbom
from cloud_posture_scanner import scan_cloud_posture
from database import create_source, init_db
from load_db import (
    load_cloud_infrastructure,
    load_code_classification,
    load_network_session,
)
from pcap_scanner import analyze_pcap_to_cbom
from translate_network_cbom import translate_cbom


def archive_processed_file(filepath: str):
    os.makedirs("processed", exist_ok=True)
    if os.path.exists(filepath):
        shutil.move(filepath, os.path.join("processed", os.path.basename(filepath)))


def process_target(target_path: str, source_type: str = "upload"):
    p = Path(target_path).resolve()
    if not p.exists():
        print(f"Error: Path does not exist: {target_path}")
        return

    init_db()

    source_name = p.name
    source_id = create_source(
        name=source_name, target_path=str(p), source_type=source_type
    )
    print(f"\nSource registered [ID: {source_id}]: {source_name}")

    if p.is_file() and p.suffix.lower() in [".pcap", ".pcapng", ".cap"]:
        out_cbom = f"cbom_network_src_{source_id}.json"
        print("Dissecting and classifying network traffic...")
        raw_cbom = analyze_pcap_to_cbom(str(p), output_json="temp_raw.json")
        translated = translate_cbom(raw_cbom)
        classified = classify_cbom(translated)

        with open(out_cbom, "w", encoding="utf-8") as f:
            json.dump(classified, f, indent=2)
        if os.path.exists("temp_raw.json"):
            os.remove("temp_raw.json")

        load_network_session(classified, source_id=source_id)
        archive_processed_file(out_cbom)

    elif p.is_file() and p.suffix.lower() in [".py", ".java", ".go"]:
        out_cbom = f"cbom_code_src_{source_id}.json"
        print(f"Executing SAST on code file {p.name}...")
        scan_repositories(base_dir=str(p.parent), output_file=out_cbom)

        with open(out_cbom, "r", encoding="utf-8") as f:
            cbom_data = json.load(f)

        cbom_data["components"] = [
            c
            for c in cbom_data.get("components", [])
            if str(Path(c.get("source", "")).resolve()) == str(p)
        ]

        load_code_classification(cbom_data, source_id=source_id)
        archive_processed_file(out_cbom)

    elif p.is_dir():
        files_in_dir = [f for root, _, files in os.walk(p) for f in files]
        has_cloud_configs = any(
            f
            in [
                "kms_key_inventory.json",
                "acm_certificates.json",
                "load_balancer_listeners.json",
            ]
            for f in files_in_dir
        )
        has_code_files = any(f.endswith((".py", ".java", ".go")) for f in files_in_dir)
        has_pcap_files = [
            str(Path(p, f)) for f in files_in_dir if f.endswith((".pcap", ".pcapng"))
        ]

        if has_cloud_configs:
            out_cbom = f"cbom_cloud_src_{source_id}.json"
            scan_cloud_posture(base_dir=str(p), output_file=out_cbom)

            with open(out_cbom, "r", encoding="utf-8") as f:
                load_cloud_infrastructure(json.load(f), source_id=source_id)
            archive_processed_file(out_cbom)

        if has_code_files:
            out_cbom = f"cbom_code_src_{source_id}.json"
            scan_repositories(base_dir=str(p), output_file=out_cbom)

            with open(out_cbom, "r", encoding="utf-8") as f:
                load_code_classification(json.load(f), source_id=source_id)
            archive_processed_file(out_cbom)

        for pcap_file in has_pcap_files:
            out_cbom = f"cbom_network_src_{source_id}.json"
            print(f"PCAP found in directory: {pcap_file}")
            raw_cbom = analyze_pcap_to_cbom(pcap_file, output_json="temp_raw.json")
            translated = translate_cbom(raw_cbom)
            classified = classify_cbom(translated)

            with open(out_cbom, "w", encoding="utf-8") as f:
                json.dump(classified, f, indent=2)
            if os.path.exists("temp_raw.json"):
                os.remove("temp_raw.json")

            load_network_session(classified, source_id=source_id)
            archive_processed_file(out_cbom)

    print(f"Cycle completed for source '{source_name}'. Data loaded into database.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process a target file or directory")
    parser.add_argument("target", help="Path to file or directory")
    parser.add_argument(
        "--type",
        default="upload",
        choices=["upload", "git_repo"],
        help="Type of source",
    )
    args = parser.parse_args()

    process_target(args.target, source_type=args.type)
