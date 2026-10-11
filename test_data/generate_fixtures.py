"""Generate synthetic upload fixtures, then check them against the current scanners.

Run from the repository root: .venv/bin/python -m test_data.generate_fixtures
No packets are transmitted and no example application code is executed.
"""
from collections import Counter
import json
from pathlib import Path
import tempfile
import textwrap
import zipfile

from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, wrpcap
from scapy.layers.tls.all import (
    TLS, TLSClientHello, TLSServerHello, TLS_Ext_SupportedGroups,
    TLS_Ext_KeyShare_CH, TLS_Ext_KeyShare_SH, KeyShareEntry,
    TLS_Ext_SupportedVersion_CH, TLS_Ext_SupportedVersion_SH,
)
from pipeline.analyze_source import analyze

HERE = Path(__file__).resolve().parent
PACK = HERE / 'quantumtrace_demo'


def write(relative, content):
    path = PACK / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(content).lstrip(), encoding='utf-8')


def tls_session(index, cipher, group=None, server=True):
    client, service = f'192.0.2.{index}', f'198.51.100.{index}'
    port = 50000 + index
    forward = Ether(src='02:00:00:00:00:01', dst='02:00:00:00:00:02') / IP(src=client, dst=service)
    reverse = Ether(src='02:00:00:00:00:02', dst='02:00:00:00:00:01') / IP(src=service, dst=client)
    client_extensions = [TLS_Ext_SupportedGroups(groups=[group or 29])]
    server_extensions = []
    if group is not None:
        # Correct wire lengths; public key-share bytes are dummy test data.
        client_length, server_length = (1216, 1120) if group == 0x11ec else (32, 32)
        client_extensions += [TLS_Ext_SupportedVersion_CH(versions=[0x0304]),
                              TLS_Ext_KeyShare_CH(client_shares=[KeyShareEntry(group=group, key_exchange=b'\x01' * client_length)])]
        server_extensions = [TLS_Ext_SupportedVersion_SH(version=0x0304),
                             TLS_Ext_KeyShare_SH(server_share=KeyShareEntry(group=group, key_exchange=b'\x02' * server_length))]
    hello = TLS(version=0x0303, msg=[TLSClientHello(version=0x0303, gmt_unix_time=1700000000,
                random_bytes=bytes([index]) * 28, ciphers=[cipher], comp=[0], ext=client_extensions)])
    reply = TLS(version=0x0303, msg=[TLSServerHello(version=0x0303, gmt_unix_time=1700000001,
                random_bytes=bytes([index + 10]) * 28, cipher=cipher, comp=[0], ext=server_extensions)])
    packets = [forward / TCP(sport=port, dport=443, flags='S', seq=1000),
               reverse / TCP(sport=443, dport=port, flags='SA', seq=2000, ack=1001),
               forward / TCP(sport=port, dport=443, flags='A', seq=1001, ack=2001),
               forward / TCP(sport=port, dport=443, flags='PA', seq=1001, ack=2001) / hello]
    if server:
        packets.append(reverse / TCP(sport=443, dport=port, flags='PA', seq=2001, ack=1001 + len(bytes(hello))) / reply)
    return packets


def generate():
    code = {
        'code/python/legacy/main.py': '''
            # Static analysis fixture only; deliberately includes legacy cryptography.
            from Crypto.PublicKey import RSA
            import hashlib

            def legacy_credentials():
                key = RSA.generate(2048)
                digest = hashlib.sha1()
                return key, digest
        ''',
        'code/python/symmetric/main.py': '''
            # Static fixture: the current regex scanner does not infer this key length.
            from cryptography.hazmat.primitives.ciphers import algorithms

            def symmetric_cipher(key: bytes):
                return algorithms.AES(key)
        ''',
        'code/python/pqc_config.py': '''
            # A declared migration target, not an implementation of cryptography.
            migration_target = {"key_exchange": "mlkem768"}
        ''',
        'code/python/no_crypto.py': '''
            # Negative control: should produce no cryptographic findings.
            def add(left, right):
                return left + right
        ''',
        'code/java/LegacyCrypto.java': '''
            // Static analysis fixture; do not use these choices as security guidance.
            import java.security.KeyPairGenerator;
            import java.security.MessageDigest;
            import java.security.GeneralSecurityException;

            public class LegacyCrypto {
                public void examples() throws GeneralSecurityException {
                    KeyPairGenerator.getInstance("RSA");
                    KeyPairGenerator.getInstance("EC");
                    MessageDigest.getInstance("MD5");
                }
            }
        ''',
        'code/java/SymmetricCrypto.java': '''
            import javax.crypto.Cipher;
            import java.security.GeneralSecurityException;

            public class SymmetricCrypto {
                public Cipher example() throws GeneralSecurityException {
                    return Cipher.getInstance("AES/GCM/NoPadding");
                }
            }
        ''',
        'code/java/MigrationConfig.java': '''
            // A declared migration target; no encryption takes place here.
            public class MigrationConfig {
                public static final String TARGET = "MLKEM";
            }
        ''',
        'code/go/legacy/main.go': '''
            // Static analysis fixture only.
            package main

            import (
                "crypto/ecdsa"
                "crypto/elliptic"
                "crypto/rand"
                "crypto/rsa"
            )

            func main() {
                _, _ = rsa.GenerateKey(rand.Reader, 2048)
                _, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
            }
        ''',
        'code/go/symmetric/main.go': '''
            // Static fixture with a dummy key; never a production configuration.
            package main

            import "crypto/aes"

            func main() {
                key := make([]byte, 16)
                _, _ = aes.NewCipher(key)
            }
        ''',
        'code/go/pqc/main.go': '''
            // A declared migration target; no cryptography is implemented here.
            package main

            const target = "mlkem768"

            func main() { println(target) }
        ''',
    }
    for path, content in code.items():
        write(path, content)

    account, region = '123456789012', 'eu-west-1'
    kms = []
    for index, (alias, spec) in enumerate([('legacy-signing', 'RSA_2048'), ('device-signing', 'ECC_NIST_P256'),
                                          ('symmetric-storage', 'SYMMETRIC_DEFAULT'), ('missing-key-spec', None)], 1):
        key_id = f'00000000-0000-4000-8000-{index:012d}'
        key = {'KeyId': key_id, 'KeyArn': f'arn:aws:kms:{region}:{account}:key/{key_id}', 'AliasName': f'alias/demo-{alias}',
               'KeyUsage': 'ENCRYPT_DECRYPT' if index >= 3 else 'SIGN_VERIFY', 'Origin': 'AWS_KMS',
               'KeyRotationStatus': 'ENABLED' if index == 3 else 'NOT_APPLICABLE'}
        if spec is not None:
            key['KeySpec'] = spec
        kms.append(key)
    certificates = [{'CertificateArn': f'arn:aws:acm:{region}:{account}:certificate/00000000-0000-4000-8000-{index:012d}',
                     'DomainName': domain, 'KeyAlgorithm': algorithm, 'SignatureAlgorithm': signature,
                     'Type': 'IMPORTED', 'Status': 'ISSUED'}
                    for index, domain, algorithm, signature in [(1, 'legacy.example.test', 'RSA_2048', 'SHA256WITHRSA'),
                                                                (2, 'portal.example.test', 'EC_prime256v1', 'ECDSA_WITH_SHA256')]]
    listeners = [{'ListenerArn': f'arn:aws:elasticloadbalancing:{region}:{account}:listener/app/demo/0000000000000001/{index:016d}',
                  'Protocol': protocol, 'Port': port, 'SslPolicy': policy,
                  'Certificates': [{'CertificateArn': certificates[0]['CertificateArn']}] if protocol == 'HTTPS' else []}
                 for index, protocol, port, policy in [(1, 'HTTPS', 443, 'ELBSecurityPolicy-TLS13-1-2-2021-06'),
                                                       (2, 'HTTPS', 8443, 'ELBSecurityPolicy-2016-08'), (3, 'HTTP', 80, None)]]
    cloud = {'kms_key_inventory.json': {'Keys': kms}, 'acm_certificates.json': {'Certificates': certificates},
             'load_balancer_listeners.json': {'LoadBalancers': [{'LoadBalancerName': 'demo-edge', 'Listeners': listeners}]}}
    for name, data in cloud.items():
        write('cloud/' + name, json.dumps({'Account': account, 'Region': region, 'Synthetic': True, **data}, indent=2) + '\n')

    captures = {
        'legacy_tls.pcap': tls_session(1, 0x002f) + tls_session(2, 0xc030) + tls_session(3, 0x1302, 29),
        'hybrid_safe_tls.pcap': tls_session(4, 0x1302, 0x11ec),
        'hybrid_aes128_tls.pcap': tls_session(5, 0x1301, 0x11ec),
        'clienthello_only.pcap': tls_session(6, 0x1302, 29, server=False),
        'non_tls.pcap': [Ether(src='02:00:00:00:00:01', dst='02:00:00:00:00:02') /
                         IP(src='192.0.2.100', dst='198.51.100.53') / UDP(sport=53000, dport=53) /
                         DNS(id=1, rd=1, qd=DNSQR(qname='demo.example.test'))],
    }
    (PACK / 'network').mkdir(exist_ok=True)
    for name, packets in captures.items():
        for index, packet in enumerate(packets):
            packet.time = 1700000000 + index / 10
        wrpcap(str(PACK / 'network' / name), packets)

    with tempfile.TemporaryDirectory() as folder:
        output = Path(folder) / 'reports.json'
        analyze(PACK, output)
        reports = json.loads(output.read_text())
    counts = {kind: dict(Counter(c.get('risk', c.get('quantumRiskAssessment', {}).get('tier', 'Unknown')).upper()
                                 for c in report['components'])) for kind, report in reports.items()}
    expected = {'network': {'CRITICAL': 3, 'MEDIUM': 1, 'SAFE': 1, 'UNKNOWN': 1},
                'code': {'CRITICAL': 7, 'MEDIUM': 3, 'SAFE': 3}, 'cloud': {'CRITICAL': 6, 'MEDIUM': 1, 'SAFE': 1}}
    assert counts == expected, f'Scanner output changed: {counts}'
    manifest = {'description': 'Expected output of the current QuantumTrace scanners; not a security certification.',
                'totalFindings': sum(sum(count.values()) for count in counts.values()), 'riskCounts': counts,
                'findings': {kind: [{'source': c.get('source'), 'name': c.get('name'),
                                     'risk': c.get('risk', c.get('quantumRiskAssessment', {}).get('tier'))}
                                    for c in report['components']] for kind, report in reports.items()}}
    (HERE / 'expected_results.json').write_text(json.dumps(manifest, indent=2) + '\n')
    with zipfile.ZipFile(HERE / 'quantumtrace_demo.zip', 'w', zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(PACK.rglob('*')):
            if path.is_file():
                archive.write(path, str(path.relative_to(HERE)))
    print(json.dumps({'verifiedRiskCounts': counts, 'zip': str(HERE / 'quantumtrace_demo.zip')}, indent=2))


if __name__ == '__main__':
    generate()
