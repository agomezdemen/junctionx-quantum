# qqqq project

## Frontend

From the repository root, install the existing scanner dependencies and run the local API/frontend server (no frontend build step):

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python server.py
```

Open **http://localhost:8000/frontend/**. The server serves both the frontend and `/api/sources` on the same origin and stores results in `quantumtrace.db`. Use `--db /path/to/database.db` or `--port 8001` to override the defaults. A plain `python3 -m http.server` does not provide the API.

The sidebar separates the workspace into four pages:

- **Input sources** (`#/inputs`, the default): the QuantumTrace welcome page; drop files, import GitHub/GitLab repositories, and open an added source's analysis.
- **Risk analysis** (`#/analysis`): select a source and explore its risk metrics, charts, inventory, and individual findings.
- **Why QuantumTrace** (`#/about`): an introduction to quantum risk, “harvest now, decrypt later,” and cryptographic discovery, with links to NIST's explanations and migration guidance.
- **About us** (`#/team`): the project's purpose and team: Alejandro Gomez De Mendieta, Afonso Silva, and Diogo Vieira.

Pages have distinct bookmarkable URLs and support browser Back/Forward. Navigation stays within the app so added sources, uploaded files, filters, and ongoing analysis polling survive page changes; a full browser refresh restores saved sources and resumes polling unfinished analyses.

Use the sun/moon button in the header to switch between light and dark themes. The first visit follows the system preference; an explicit choice is saved in `localStorage` under `quantumtrace-theme`. Theme initialization runs before the stylesheet to avoid a flash. If storage is unavailable, switching still works for the current page. Colors, surfaces, type, controls, and severity styles share the tokens at the top of `frontend/styles.css`; charts use those same theme tokens without refetching data. Chart bars expose occurrence counts on hover or keyboard focus (Escape dismisses the tooltip). The inventory scrolls within its panel with sticky column headings, and the risk donut's methodology expands beneath its legend.

Switch between **Network traffic**, **Application code**, and **Cloud posture** to view the selected source’s reports from the database. The server seeds **Sample workspace** once from `pipeline/cbom_network_classified.json`, `pipeline/cbom_code.json`, and `pipeline/cbom_cloud.json`. Network sessions show individual algorithm ratings; code findings show language, file/line, and code evidence; cloud assets show key, certificate, and TLS policy properties. Search, risk filters, language/asset-type filters, and details apply to the selected report. **Export source CBOM** exports all available reports for the selected source, independently of the current report tab or filters. Code and cloud ratings and explanations are displayed as supplied by their scanners, without applying the network classifier. Reload to fetch the latest saved results; editing sample JSON files does not replace an already seeded database sample.

The repository/source selector scopes metrics, tables, charts, details, and exports together. The built-in **Sample workspace** holds the supplied JSON reports. Added repositories each have their own results; every file upload creates a separate source containing all files selected together. Sources, upload metadata, and results persist in SQLite. On reload, the frontend lists saved sources and loads their reports by server ID, without uploading files or cloning repositories again. Removing a source from the tab stops its polling but does not delete saved data or cancel a running server job; that source returns on reload.

Drop files, folders, or a mixture into the upload area, or use **Browse files** / **Browse folder**. Nested paths are preserved, including matching filenames in different directories. Each selection becomes one source; a single folder uses its folder name. Uploads skip `.git`, `node_modules`, `.venv`, `venv`, and `__pycache__` directories and enforce the existing 2,000-file / 50 MiB limits. Empty folders have no files to upload. ZIP uploads continue to extract on the server. For a complete example, select or drop `test_data/quantumtrace_demo/`.

The visualization section's report-type selector defaults to all reports **within the selected source**. Its risk donut can count unique source files represented in the reports or individual findings. File ratings use the precedence Critical, High, Unknown, Medium, Low, Safe; files without findings are not listed by the scanners and cannot be counted. Encryption and key-exchange bars count structured algorithm occurrences (a hybrid counts once); a separate bar chart preserves the code/cloud scanners' untyped algorithm labels. Charts are independent of inventory search/risk filters.

Adding a repository or dropping/selecting files immediately submits an analysis request. The server queues analysis automatically; there is no manual Analyze step. Processing, completion, and error states are per source, and switching sources does not interrupt another source's analysis. Connection failures show an explicit error with a retry action and no substitute sample results. Failed analyses can be retried through the API. Scanning and database access run on the server.

The visual system pairs locally hosted IBM Plex Mono headings with IBM Plex Sans body text. It uses a 12-column grid, a 4:8 risk/algorithm layout, asymmetric input sections, and numbered editorial rows for the explainer. Warm white and ink surfaces share a single teal accent; severity colors remain reserved for risk data. Subtle circuit traces animate continuously behind the sidebar and input introduction, with static traces for reduced-motion preferences. The Why QuantumTrace page adapts the project PDF introduction, explains Shor’s and Grover’s algorithms with NIST references, and uses tinted reading panels. Font sources and licensing are in `frontend/fonts/`; there are no external font dependencies.

### Analysis API contract

`frontend/source-api.mjs` uses these existing same-origin endpoints in `server.py`:

- `GET /api/sources`: return `{ "sources": [...] }` with each saved source’s `id`, `name`, `kind`, `url`, `files` metadata, `status`, and optional `error`. The frontend restores this list on startup.
- `POST /api/sources`: create a source and immediately analyze it. For repositories, accept JSON `{ "clientSourceId": "<stable-client-id>", "repositoryUrl": "https://github.com/team/project.git" }`; the backend clones it into its own directory under `input_files/`. For uploads, accept multipart `clientSourceId`, repeated `files` fields, and `paths` containing a JSON array of relative paths in the same order as the files. Deduplicate creation by `clientSourceId` so retrying a failed connection cannot create duplicate sources/jobs.
- Return `{ "id": "<source-id>", "status": "pending" | "processing" | "ready" | "failed", "reports": { ... }, "error": "optional error" }`. When ready, `reports` must be an object whose optional `network`, `code`, and `cloud` keys contain the respective existing CBOM shapes (`metadata`, `components`). An omitted category means this source has no findings in that category, never a fallback to sample data.
- `GET /api/sources/<source-id>`: return the same response shape. The frontend polls pending jobs every 1.5 seconds and refreshes all views automatically on completion. Connection retries with a known server ID resume polling instead of creating another job.
- `POST /api/sources/<source-id>/retry`: explicitly retry a failed analysis, retaining its source ID and stored inputs. Loading a saved failed source does not automatically restart it.
- `GET /api/sources/<source-id>/cbom`: read the selected source and its report/component records from SQLite and generate a CycloneDX 1.7 CBOM with content type `application/vnd.cyclonedx+json`. Returns 404 for a missing source and 409 unless analysis is ready. No browser reports, scanner JSON files, or uploaded files are used to build this export.

The backend owns source identity, cloning, scanners, and persistence in the respective analysis tables. Responses must contain **only that source's** results. The frontend neither chooses nor creates database tables. The existing `analysis_source` table identifies sources, `source_report` preserves report metadata, and analysis rows are scoped by `source_id`. This integration adds no tables and keeps the scanner output intact.

The handler’s input layout remains organized by `input_files/sample-repos/`, `input_files/network-capture/`, and `input_files/cloud-posture/`. File filtering and routing into those folders are owned by the separate handler work. The existing server currently stages new sources under `input_files/sources/<id>/input`; this frontend/database integration does not change that routing. Keep the API response shape above when connecting repository-specific file tables, so the frontend remains independent of storage layout.

### CBOM export

**Export source CBOM** downloads `<source-name>-cbom.cdx.json`. The backend generates it from the database on each request using `pipeline/export_cbom.py`. It follows the [CycloneDX 1.7 JSON specification](https://cyclonedx.org/docs/1.7/json/): `bomFormat: "CycloneDX"`, a fresh UUID serial number, export timestamp, source identity, tool metadata, unique component references, cryptographic asset types, and relationships between protocols, keys, certificates, and algorithms. Paths, line numbers, and snippets use standard evidence occurrences. A hybrid exchange links to its constituent algorithms.

The scanner's full original evidence, report metadata, and risk assessments are retained in `quantumtrace:*` properties. These are application extensions, not standard vulnerability ratings or proof of NIST security levels. Missing certificate dates, negotiated versions, and algorithm parameters stay absent. Code scanner `keySize` values come from a generic number-matching heuristic, so they remain in scanner evidence rather than being exported as verified algorithm parameters. Inventory completeness is marked `unknown`. This is a schema-conformant inventory of observed findings, not a claim that the scanners discover every cryptographic asset. Component counts can exceed finding counts because protocols and their algorithms are separate assets.

Run the frontend and database/API integration checks (the latter use a disposable database and input directory):

```sh
node --test frontend/*.test.mjs
.venv/bin/python -m unittest test_server test_cbom -v
```

The optional official-schema check needs a test-only validator and local copies of the two official schemas; no validator is required to run the application:

```sh
.venv/bin/python -m pip install jsonschema
mkdir -p /tmp/quantumtrace-cbom-schemas
curl -fL https://cyclonedx.org/schema/bom-1.7.schema.json -o /tmp/quantumtrace-cbom-schemas/bom-1.7.schema.json
curl -fL https://cyclonedx.org/schema/cryptography-defs.schema.json -o /tmp/quantumtrace-cbom-schemas/cryptography-defs.schema.json
CBOM_SCHEMA_DIR=/tmp/quantumtrace-cbom-schemas .venv/bin/python -m unittest test_cbom -v
```
