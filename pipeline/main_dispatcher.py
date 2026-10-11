import os
import sys
import json
import argparse
from pathlib import Path
from typing import List, Dict, Any

# Importar diretamente as funções principais dos teus scanners
from pcap_scanner import analyze_pcap_to_cbom
from translate_network_cbom import translate_cbom
from classify_network_cbom import classify_cbom
from cloud_posture_scanner import scan_cloud_posture
from code_scanner import scan_repositories


# =====================================================================
# WRAPPERS PARA EXECUTAR OS SCANNERS E GERAR OS RESPETIVOS CBOMs
# =====================================================================

def execute_network_pipeline(pcap_files: List[str], output_dir: str = "."):
    """
    Executa o pipeline completo de rede para cada PCAP:
    1. pcap_scanner -> gera CBOM bruto
    2. translate_network_cbom -> traduz IDs usando os CSVs IANA
    3. classify_network_cbom -> classifica o risco e grava o CBOM final de rede
    """
    for pcap in pcap_files:
        pcap_name = Path(pcap).stem
        raw_output = os.path.join(output_dir, f"cbom_{pcap_name}_raw.json")
        classified_output = os.path.join(output_dir, f"cbom_{pcap_name}_classified.json")

        print(f"\n[+] [Rede] A analisar tráfego: {pcap}")
        # 1. Extração
        raw_cbom = analyze_pcap_to_cbom(pcap, output_json=raw_output)

        # 2. Tradução dos identificadores TLS
        print(f"[*] [Rede] A traduzir identificadores IANA...")
        translated_cbom = translate_cbom(raw_cbom)

        # 3. Classificação de risco e exportação
        print(f"[*] [Rede] A classificar risco quântico da rede...")
        final_cbom = classify_cbom(translated_cbom)

        with open(classified_output, "w", encoding="utf-8") as f:
            json.dump(final_cbom, f, indent=2)

        # Limpar o ficheiro bruto temporário
        if os.path.exists(raw_output):
            os.remove(raw_output)

        print(f"[✓] [Rede] CBOM gerado com sucesso: '{classified_output}'")


def execute_cloud_scanner(cloud_dirs_or_files: List[str], output_dir: str = "."):
    """
    Executa o scanner de postura cloud. Se forem ficheiros isolados numa pasta,
    identifica a pasta-mãe ou executa sobre o diretório indicado.
    """
    # Identificar diretórios únicos que contêm as configurações cloud
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
        print(f"\n[+] [Cloud] A executar Cloud Posture Scanner em: {c_dir}")
        scan_cloud_posture(base_dir=c_dir, output_file=out_file)


def execute_code_scanner(code_dirs_or_files: List[str], output_dir: str = "."):
    """
    Executa o scanner de código SAST sobre os diretórios ou ficheiros de código.
    """
    # Identificar diretórios raiz ou ficheiros a analisar
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
        print(f"\n[+] [Código] A executar Code SAST Scanner em: {c_dir}")
        scan_repositories(base_dir=c_dir, output_file=out_file)


# =====================================================================
# MAIN DISPATCHER
# =====================================================================

def main():
    parser = argparse.ArgumentParser(
        description="PQC Security Posture - Dispatcher de Scanners para Geração de CBOMs"
    )
    parser.add_argument(
        "targets", nargs="+",
        help="Caminhos de ficheiros ou diretórios a analisar (.pcap, .json da AWS, repositórios ou ficheiros de código)"
    )
    parser.add_argument(
        "-o", "--output-dir", default=".",
        help="Diretório onde os ficheiros cbom_*.json serão guardados (por defeito: diretório atual)"
    )
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    network_targets: List[str] = []
    cloud_targets: List[str] = []
    code_targets: List[str] = []

    # 1. Descobrir e classificar cada caminho fornecido
    for target in args.targets:
        p = Path(target)
        if not p.exists():
            print(f"[!] Caminho não encontrado: {target}")
            continue

        if p.is_file():
            ext = p.suffix.lower()
            if ext in [".pcap", ".pcapng", ".cap"]:
                network_targets.append(str(p.resolve()))
            elif ext in [".py", ".java", ".go"]:
                code_targets.append(str(p.resolve()))
            elif ext == ".json":
                # Inspecionar se é configuração AWS Cloud
                try:
                    with open(p, "r", encoding="utf-8", errors="ignore") as f:
                        data = json.load(f)
                    if any(k in data for k in ["Keys", "Certificates", "LoadBalancers"]):
                        cloud_targets.append(str(p.resolve()))
                except Exception:
                    pass

        elif p.is_dir():
            # Inspecionar o conteúdo do diretório para decidir a que categorias pertence
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
                            with open(full_p, "r", encoding="utf-8", errors="ignore") as jf:
                                data = json.load(jf)
                            if any(k in data for k in ["Keys", "Certificates", "LoadBalancers"]):
                                has_cloud = True
                        except Exception:
                            pass

            if has_code:
                code_targets.append(str(p.resolve()))
            if has_cloud:
                cloud_targets.append(str(p.resolve()))

    # 2. Resumo da deteção mais explícito
    print("=== Despacho de Scanners Identificado ===")
    print("=== Alvos podem ser ficheiros ou diretórios ===")
    print(f"[*] Alvos de Rede:   {len(network_targets)} ficheiro(s) PCAP")
    print(f"[*] Alvos de Cloud:  {len(cloud_targets)} diretório(s) com ficheiros AWS (KMS/ACM/ELB)")
    print(f"[*] Alvos de Código: {len(code_targets)} repositório(s) com ficheiros (.py/.java/.go)")
    print("=========================================")

    # 3. Invocar os scanners especializados para gerarem os seus CBOMs
    if network_targets:
        execute_network_pipeline(network_targets, output_dir=args.output_dir)

    if cloud_targets:
        execute_cloud_scanner(cloud_targets, output_dir=args.output_dir)

    if code_targets:
        execute_code_scanner(code_targets, output_dir=args.output_dir)

    print("\n[✓] Todos os scanners solicitados concluíram a geração dos seus CBOMs.")
    print(f"    Podes agora carregar os ficheiros JSON gerados em '{args.output_dir}' para a base de dados.")


if __name__ == "__main__":
    main()