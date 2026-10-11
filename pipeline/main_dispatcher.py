import argparse
import json
import os
from pathlib import Path

from classify_network_cbom import classify_cbom
from cloud_posture_scanner import scan_cloud_posture
from code_scanner import scan_repositories
from pcap_scanner import analyze_pcap_to_cbom
from translate_network_cbom import translate_cbom


def execute_network_pipeline(pcap_files: list[str], output_dir: str = "."):
    for pcap in pcap_files:
        pcap_name = Path(pcap).stem
        raw_output = os.path.join(output_dir, f"cbom_{pcap_name}_raw.json")
        classified_output = os.path.join(
            output_dir, f"cbom_{pcap_name}_classified.json"
        )

        print(f"\nAnalyzing network traffic: {pcap}")
        raw_cbom = analyze_pcap_to_cbom(pcap, output_json=raw_output)

        print("Translating IANA identifiers...")
        translated_cbom = translate_cbom(raw_cbom)

        print("Classifying network quantum risk...")
        final_cbom = classify_cbom(translated_cbom)

        with open(classified_output, "w", encoding="utf-8") as f:
            json.dump(final_cbom, f, indent=2)

        if os.path.exists(raw_output):
            os.remove(raw_output)

        print(f"CBOM successfully generated: '{classified_output}'")


def execute_cloud_scanner(cloud_dirs_or_files: list[str], output_dir: str = "."):
    target_dirs = set()
    for item in cloud_dirs_or_files:
        p = Path(item)
        if p.is_dir():
            target_dirs.add(str(p))
        elif p.is_file():
            target_dirs.add(str(p.parent))

        for idx, c_dir in enumerate(target_dirs, start=1):
            suffix = f"_{idx}" if len(target_dirs) > 1 else ""
            out_file = os.path.join(output_dir, f"cbom_cloud{suffix}.json")
            print(f"\nRunning Cloud Posture Scanner on: {c_dir}")
            scan_cloud_posture(base_dir=c_dir, output_file=out_file)


def execute_code_scanner(code_dirs_or_files: list[str], output_dir: str = "."):
    target_dirs = set()
    for item in code_dirs_or_files:
        p = Path(item)
        if p.is_dir():
            target_dirs.add(str(p))
        elif p.is_file():
            target_dirs.add(str(p.parent))

        for idx, c_dir in enumerate(target_dirs, start=1):
            suffix = f"_{idx}" if len(target_dirs) > 1 else ""
            out_file = os.path.join(output_dir, f"cbom_code{suffix}.json")
            print(f"\nRunning Code SAST Scanner on: {c_dir}")
            scan_repositories(base_dir=c_dir, output_file=out_file)


def main():
    parser = argparse.ArgumentParser(
        description="PQC Security Posture - Scanner Dispatcher for CBOM Generation"
    )
    parser.add_argument(
        "targets",
        nargs="+",
        help="File or directory paths to analyze (.pcap, AWS .json, repositories or code files)",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        default=".",
        help="Directory where cbom_*.json files will be saved (default: current directory)",
    )
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    network_targets: list[str] = []
    cloud_targets: list[str] = []
    code_targets: list[str] = []

    for target in args.targets:
        p = Path(target)
        if not p.exists():
            print(f"Path not found: {target}")
            continue

        if p.is_file():
            ext = p.suffix.lower()
            if ext in [".pcap", ".pcapng", ".cap"]:
                network_targets.append(str(p.resolve()))
            elif ext in [".py", ".java", ".go"]:
                code_targets.append(str(p.resolve()))
            elif ext == ".json":
                try:
                    with open(p, "r", encoding="utf-8", errors="ignore") as f:
                        data = json.load(f)
                    if any(
                        k in data for k in ["Keys", "Certificates", "LoadBalancers"]
                    ):
                        cloud_targets.append(str(p.resolve()))
                except Exception as e:
                    print(f"Warning: Failed to parse JSON {p} - {e}")

        elif p.is_dir():
            has_code = False
            has_cloud = False
            for root, _, files in os.walk(p):
                for f in files:
                    full_p = Path(root, f)
                    ext = full_p.suffix.lower()
                    if ext in [".pcap", ".pcapng", ".cap"]:
                        network_targets.append(str(full_p.resolve()))
                    elif ext in [".py", ".java", ".go"]:
                        has_code = True
                    elif ext == ".json":
                        try:
                            with open(
                                full_p, "r", encoding="utf-8", errors="ignore"
                            ) as jf:
                                data = json.load(jf)
                            if any(
                                k in data
                                for k in ["Keys", "Certificates", "LoadBalancers"]
                            ):
                                has_cloud = True
                        except Exception as e:
                            print(f"Warning: Failed to parse JSON {full_p} - {e}")

            if has_code:
                code_targets.append(str(p.resolve()))
            if has_cloud:
                cloud_targets.append(str(p.resolve()))

    print("Scanner Dispatch Summary")
    print(f"Network targets: {len(network_targets)} PCAP file(s)")
    print(f"Cloud targets:   {len(cloud_targets)} directory(s) with AWS files")
    print(f"Code targets:    {len(code_targets)} repository(s) with code files")

    if network_targets:
        execute_network_pipeline(network_targets, output_dir=args.output_dir)

    if cloud_targets:
        execute_cloud_scanner(cloud_targets, output_dir=args.output_dir)

    if code_targets:
        execute_code_scanner(code_targets, output_dir=args.output_dir)

    print("\nAll requested scanners have completed CBOM generation.")
    print(
        f"You can now load the generated JSON files from '{args.output_dir}' into the database."
    )


if __name__ == "__main__":
    main()
