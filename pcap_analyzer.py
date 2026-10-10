# python pcap_analyzer.py <caminho_real_do_ficheiro.pcap>

import json
from scapy.all import rdpcap, TCP
from scapy.layers.tls.all import (
    TLS,
    TLSClientHello,
    TLSServerHello
)

# Palavras-chave e IDs conhecidos para algoritmos PQC / Híbridos
PQC_KEYWORDS = ["kyber", "mlkem", "ml-kem", "hybrid", "bikel", "hqc", "frodo"]
PQC_GROUP_IDS = {
    0x6399: "X25519Kyber768Draft00",
    0x11ec: "X25519MLKEM768",
    0x023a: "Kyber768",
    0x023c: "Kyber1024",
    0x2f3a: "MLKEM768",
    0x2f3c: "MLKEM1024",
}

def is_pqc_indicator(val) -> bool:
    if isinstance(val, int):
        return val in PQC_GROUP_IDS
    val_str = str(val).lower()
    return any(kw in val_str for kw in PQC_KEYWORDS)

def analyze_pcap_to_cbom(pcap_path: str, output_json: str = "cbom_network.json"):
    print(f"[*] A dissecar pacotes de '{pcap_path}'...")
    packets = rdpcap(pcap_path)
    print(f"[+] Total de pacotes lidos: {len(packets)}")

    sessions = {}

    for pkt in packets:
        if not pkt.haslayer(TCP) or not pkt.haslayer(TLS):
            continue

        ip_src = pkt["IP"].src if pkt.haslayer("IP") else pkt["IPv6"].src
        ip_dst = pkt["IP"].dst if pkt.haslayer("IP") else pkt["IPv6"].dst
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport

        forward_flow = f"{ip_src}:{sport} -> {ip_dst}:{dport}"
        reverse_flow = f"{ip_dst}:{dport} -> {ip_src}:{sport}"

        # 1. Processar ClientHello
        if pkt.haslayer(TLSClientHello):
            ch = pkt[TLSClientHello]
            session_key = forward_flow

            ciphers = [str(c) for c in getattr(ch, "ciphers", [])]
            supported_groups = []

            # Inspecionar extensões de forma dinâmica e segura
            if hasattr(ch, "ext"):
                for ext in ch.ext:
                    # Supported Groups (Elliptic Curves / PQC Groups)
                    if hasattr(ext, "groups"):
                        for g in ext.groups:
                            group_name = PQC_GROUP_IDS.get(g, str(g))
                            supported_groups.append(group_name)

            client_pqc = any(is_pqc_indicator(g) for g in supported_groups)

            sessions[session_key] = {
                "client_endpoint": f"{ip_src}:{sport}",
                "server_endpoint": f"{ip_dst}:{dport}",
                "offered_ciphers_count": len(ciphers),
                "supported_groups": supported_groups,
                "client_offered_pqc": client_pqc,
                "negotiated_cipher": None,
                "negotiated_group": None,
                "tls_version": hex(ch.version) if hasattr(ch, "version") else "TLS",
            }

        # 2. Processar ServerHello
        elif pkt.haslayer(TLSServerHello):
            sh = pkt[TLSServerHello]
            target_key = reverse_flow if reverse_flow in sessions else forward_flow

            if target_key not in sessions:
                sessions[target_key] = {
                    "client_endpoint": f"{ip_dst}:{dport}",
                    "server_endpoint": f"{ip_src}:{sport}",
                    "offered_ciphers_count": 0,
                    "supported_groups": [],
                    "client_offered_pqc": False,
                    "negotiated_cipher": None,
                    "negotiated_group": None,
                    "tls_version": "TLS",
                }

            # Cifra selecionada pelo servidor
            chosen_cipher = str(getattr(sh, "cipher", "UNKNOWN"))
            sessions[target_key]["negotiated_cipher"] = chosen_cipher

            # Grupo selecionado (KeyShare no TLS 1.3)
            if hasattr(sh, "ext"):
                for ext in sh.ext:
                    # Inspecionar servidor KeyShare
                    if hasattr(ext, "server_share"):
                        share = ext.server_share
                        raw_grp = getattr(share, "group", None)
                        if raw_grp is not None:
                            sessions[target_key]["negotiated_group"] = PQC_GROUP_IDS.get(raw_grp, str(raw_grp))

    # 3. Gerar entradas normalizadas de CBOM
    cbom_components = []
    for flow_id, data in sessions.items():
        neg_cipher = data.get("negotiated_cipher") or "ClientHello_Only"
        neg_group = data.get("negotiated_group") or "Legacy_Or_None"
        server_pqc = is_pqc_indicator(neg_group) or is_pqc_indicator(neg_cipher)

        component = {
            "type": "network-session",
            "name": f"TLS-Session-{data['server_endpoint']}",
            "source": pcap_path,
            "evidence": {
                "client": data["client_endpoint"],
                "server": data["server_endpoint"],
            },
            "cryptoProperties": {
                "assetType": "protocol",
                "protocol": data.get("tls_version", "TLS"),
                "cipherSuite": neg_cipher,
                "keyExchangeGroup": neg_group,
                "clientOfferedPQC": data["client_offered_pqc"],
                "serverNegotiatedPQC": server_pqc,
                "supportedGroups": data["supported_groups"][:5],  # top 5 para brevidade
            }
        }
        cbom_components.append(component)

    cbom_data = {
        "bomFormat": "CycloneDX-CBOM-Draft",
        "specVersion": "1.6",
        "metadata": {
            "sourceFile": pcap_path,
            "totalSessions": len(cbom_components)
        },
        "components": cbom_components
    }

    with open(output_json, "w", encoding="utf-8") as f:
        json.dump(cbom_data, f, indent=2)

    print(f"\n[✓] Sucesso! {len(cbom_components)} sessões TLS exportadas para '{output_json}'.")
    return cbom_data

if __name__ == "__main__":
    import sys
    # Se passares argumento usa-o, senão tenta o caminho por defeito
    target_pcap = sys.argv[1] if len(sys.argv) > 1 else "network-capture/network.pcap"
    analyze_pcap_to_cbom(target_pcap)