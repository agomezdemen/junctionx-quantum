# Drag-and-drop test pack

Drop **`quantumtrace_demo/`** into the application's upload area, use **Browse folder**, or upload **`quantumtrace_demo.zip`**. All 18 files will belong to one source. You can also upload its `network/`, `cloud/`, or `code/` subfolders separately to test source switching.

Upload the demo folder or ZIP, not this entire `test_data/` directory: the generator and expected-results file are supporting material, not scanner inputs. Fixtures live outside `input_files/` so they enter the application only when you upload them.

Everything is synthetic. Captures use documentation IP addresses; cloud records use example account IDs and domains. The generator writes PCAPs offline and does not transmit packets or contact AWS. Code is for static inspection and is not executed by the scanner.

## Expected dashboard results

These counts were verified against the current scanners:

| Report | Findings | Critical | Medium | Safe | Unknown |
| --- | ---: | ---: | ---: | ---: | ---: |
| Network traffic | 6 | 3 | 1 | 1 | 1 |
| Application code | 13 | 7 | 3 | 3 | 0 |
| Cloud posture | 8 | 6 | 1 | 1 | 0 |
| All reports | **27** | **16** | **5** | **5** | **1** |

For the **all-reports file-based donut**, expect 16 represented files: 7 Critical (43.75%), 4 Medium (25%), 4 Safe (25%), and 1 Unknown (6.25%). The UI rounds percentages to one decimal place. The two negative-control files have no findings and are excluded from this donut. Switching the donut to findings gives the 27-finding totals above.

`expected_results.json` lists the expected source path, finding name, and risk for each result. These expectations describe the current classifier's behavior, not a certification of the examples' security.

## Packet captures

| File in `network/` | Scenario | Expected result |
| --- | --- | --- |
| `legacy_tls.pcap` | RSA + AES-128-CBC/SHA-1; ECDHE-RSA + AES-256-GCM/SHA-384; TLS 1.3 AES-256-GCM + classical X25519 | 3 Critical sessions |
| `hybrid_safe_tls.pcap` | TLS 1.3 AES-256-GCM/SHA-384 + X25519MLKEM768 | 1 Safe session |
| `hybrid_aes128_tls.pcap` | TLS 1.3 AES-128-GCM/SHA-256 + X25519MLKEM768 | 1 Medium session |
| `clienthello_only.pcap` | Client advertises a suite/group, but there is no ServerHello | 1 Unknown session |
| `non_tls.pcap` | A DNS query with no TLS | 0 sessions |

The captures contain synthetic TCP setup and TLS hello messages with dummy key-share bytes, not completed cryptographically valid TLS connections. They test parsing/classification rather than real key establishment. TLS 1.3 authentication is unrecorded; it should appear Unknown individually without making the otherwise Safe hybrid session Unknown overall.

## AWS-style JSON

Keep the supplied filenames: the cloud scanner recognizes them by name. These are synthetic combined inventory exports in the scanner's expected format, rather than raw responses from one AWS API call.

- `cloud/kms_key_inventory.json`: RSA and elliptic-curve signing keys (2 Critical), a symmetric storage key (1 Safe), and an entry missing its key specification (1 Medium under the current scanner's inconclusive rule).
- `cloud/acm_certificates.json`: RSA and elliptic-curve certificates (2 Critical).
- `cloud/load_balancer_listeners.json`: modern and legacy HTTPS policies (2 Critical), plus a plain HTTP listener that the TLS scanner ignores.

## Code fixtures

Python, Java, and Go each include legacy algorithms, AES use, and a declared post-quantum migration target. Repeated `main.py` and `main.go` filenames in different directories exercise folder-path preservation.

| Language | Critical | Medium | Safe |
| --- | ---: | ---: | ---: |
| Python | 2 | 1 | 1 |
| Java | 3 | 1 | 1 |
| Go | 2 | 1 | 1 |

`code/python/no_crypto.py` is a negative control with no findings. The post-quantum examples declare algorithm names in configuration; they do not implement those algorithms. The current regex scanner labels those keyword matches Safe. It also labels the AES examples Medium without resolving their actual key sizes. These fixtures make those scanner limitations visible.

## Regenerate and verify

From the repository root, with the existing requirements installed:

```sh
.venv/bin/python -m test_data.generate_fixtures
```

This regenerates the fixture files, verifies their risk totals using the actual scan pipeline, writes `expected_results.json`, and rebuilds the ZIP. It does not change the application's database or existing uploaded sources.
