import os
import sys
import json
from pathlib import Path
from typing import List

from database import init_db, create_source
from load_db import (
    load_cloud_infrastructure,
    load_code_classification,
    load_network_session,
)

# Importar diretamente os scanners existentes
from pcap_scanner import analyze_pcap_to_cbom
from translate_network_cbom import translate_cbom
from classify_network_cbom import classify_cbom
from cloud_posture_scanner import scan_cloud_posture
from code_scanner import scan_repositories


def process_target(target_path: str, source_type: str = "upload"):
    """
    Processa um ficheiro ou pasta individual:
    1. Cria a entrada na tabela `sources`
    2. Deteta o scanner apropriado e gera o CBOM JSON
    3. Ingesta os dados na BD associados ao source_id
    """
    p = Path(target_path).resolve()
    if not p.exists():
        print(f"[!] Erro: Caminho não existe: {target_path}")
        return

    init_db()

    # 1. Registar a nova fonte
    source_name = p.name
    source_id = create_source(
        name=source_name, target_path=str(p), source_type=source_type
    )
    print(f"\n[+] Fonte registada na BD [ID: {source_id}]: {source_name}")

    # 2. Despachar para o scanner correto de acordo com a estrutura do ficheiro/diretório

    # --- CENÁRIO A: Ficheiro PCAP (Rede) ---
    if p.is_file() and p.suffix.lower() in [".pcap", ".pcapng", ".cap"]:
        out_cbom = f"cbom_network_src_{source_id}.json"
        print(f"[*] A dissecar tráfego de rede e a classificar...")
        raw_cbom = analyze_pcap_to_cbom(str(p), output_json="temp_raw.json")
        translated = translate_cbom(raw_cbom)
        classified = classify_cbom(translated)

        with open(out_cbom, "w", encoding="utf-8") as f:
            json.dump(classified, f, indent=2)
        if os.path.exists("temp_raw.json"):
            os.remove("temp_raw.json")

        load_network_session(classified, source_id=source_id)

    # --- CENÁRIO B: Ficheiro Singular de Código ---
    elif p.is_file() and p.suffix.lower() in [".py", ".java", ".go"]:
        out_cbom = f"cbom_code_src_{source_id}.json"
        print(f"[*] A executar SAST no ficheiro de código {p.name}...")
        # Executa o scanner apontando para a pasta pai
        scan_repositories(base_dir=str(p.parent), output_file=out_cbom)
        with open(out_cbom, "r", encoding="utf-8") as f:
            cbom_data = json.load(f)
        # Filtra apenas achados pertencentes a este ficheiro específico se necessário
        cbom_data["components"] = [
            c
            for c in cbom_data.get("components", [])
            if str(Path(c.get("source", "")).resolve()) == str(p)
        ]
        load_code_classification(cbom_data, source_id=source_id)

    # --- CENÁRIO C: Diretório de Código (Repo) ou Cloud ---
    elif p.is_dir():
        # Inspecionar conteúdo do diretório
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

        # 1. Tratar Cloud
        if has_cloud_configs:
            out_cbom = f"cbom_cloud_src_{source_id}.json"
            print(
                f"[*] Configurações AWS detetadas. A executar Cloud Posture Scanner..."
            )
            scan_cloud_posture(base_dir=str(p), output_file=out_cbom)
            with open(out_cbom, "r", encoding="utf-8") as f:
                load_cloud_infrastructure(json.load(f), source_id=source_id)

        # 2. Tratar Código
        if has_code_files:
            out_cbom = f"cbom_code_src_{source_id}.json"
            print(f"[*] Código-fonte detetado. A executar Code SAST Scanner...")
            scan_repositories(base_dir=str(p), output_file=out_cbom)
            with open(out_cbom, "r", encoding="utf-8") as f:
                load_code_classification(json.load(f), source_id=source_id)

        # 3. Tratar PCAPs encontrados dentro da pasta
        for pcap_file in has_pcap_files:
            out_cbom = f"cbom_network_src_{source_id}.json"
            print(f"[*] PCAP encontrado na pasta: {pcap_file}")
            raw_cbom = analyze_pcap_to_cbom(pcap_file, output_json="temp_raw.json")
            translated = translate_cbom(raw_cbom)
            classified = classify_cbom(translated)
            load_network_session(classified, source_id=source_id)

    print(
        f"[✓] Ciclo concluído para a fonte '{source_name}'. Dados carregados na base de dados!"
    )


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(
            "Uso: python runner.py <caminho_ficheiro_ou_diretorio> [tipo: upload|git_repo]"
        )
        sys.exit(1)

    input_target = sys.argv[1]
    input_type = sys.argv[2] if len(sys.argv) > 2 else "upload"

    process_target(input_target, source_type=input_type)
