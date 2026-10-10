from scapy.all import rdpcap, TCP

PCAP_FILE = "network-capture/network.pcap"

print(f"[*] A carregar {PCAP_FILE}...")
packets = rdpcap(PCAP_FILE)
print(f"[+] Total de pacotes carregados: {len(packets)}")

tls_handshake_count = 0

for pkt in packets:
    # 0x16 é o primeiro byte do registo TLS correspondente a 'Handshake'
    if pkt.haslayer(TCP) and bytes(pkt[TCP].payload).startswith(b"\x16\x03"):
        tls_handshake_count += 1

print(f"[+] Pacotes com início de TLS Handshake detetados: {tls_handshake_count}")