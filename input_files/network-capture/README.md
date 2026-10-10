# network-capture

`network.pcap` — captura sintetica (2000 pacotes, ~135 sessoes de rede mais
ruido de fundo DNS) cobrindo varias aplicacoes e portas: HTTPS, LDAPS,
IMAPS, SMTP com STARTTLS, Postgres, SSH e HTTP sem TLS. Nenhum pacote
corresponde a trafego real — e so para inspecao com Wireshark/tshark/Zeek.
