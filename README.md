# qqqq project

## Frontend

From the repository root, serve the project with Python (no packages or build step needed):

```sh
python3 -m http.server 8000 --bind 127.0.0.1
```

Open **http://localhost:8000/frontend/**. Serve the repository root, since the dashboard loads `pipeline/cbom_network_classified.json` directly as a sample report.

The sidebar separates the workspace into four pages:

- **Input sources** (`#/inputs`, the default): the QuantumTrace welcome page; drop files, import GitHub/GitLab repositories, and open an added source's analysis.
- **Risk analysis** (`#/analysis`): select a source and explore its risk metrics, charts, inventory, and individual findings.
- **Why QuantumTrace** (`#/about`): an introduction to quantum risk, “harvest now, decrypt later,” and cryptographic discovery, with links to NIST's explanations and migration guidance.
- **About us** (`#/team`): the project's purpose and team: Alejandro Gomez De Mendieta, Afonso Silva, and Diogo Vieira.

Pages have distinct bookmarkable URLs and support browser Back/Forward. Navigation stays within the app so added sources, uploaded files, filters, and ongoing analysis polling survive page changes; a full browser refresh still clears this tab's sources.

Use the sun/moon button in the header to switch between light and dark themes. The first visit follows the system preference; an explicit choice is saved in `localStorage` under `quantumtrace-theme`. Theme initialization runs before the stylesheet to avoid a flash. If storage is unavailable, switching still works for the current page. Colors, surfaces, type, controls, and severity styles share the tokens at the top of `frontend/styles.css`; charts use those same theme tokens without refetching data. Chart bars expose occurrence counts on hover or keyboard focus (Escape dismisses the tooltip). The inventory scrolls within its panel with sticky column headings, and the risk donut's methodology expands beneath its legend.

Switch between **Network traffic**, **Application code**, and **Cloud posture** to view the existing `pipeline/cbom_network_classified.json`, `pipeline/cbom_code.json`, and `pipeline/cbom_cloud.json` reports. Network sessions show individual algorithm ratings; code findings show language, file/line, and code evidence; cloud assets show key, certificate, and TLS policy properties. Search, risk filters, language/asset-type filters, details, and JSON export apply to the selected report. Code and cloud ratings and explanations are displayed as supplied by their scanners, without applying the network classifier. Refresh to load regenerated report files.

The repository/source selector scopes metrics, tables, charts, details, and exports together. The built-in **Sample workspace** holds the supplied JSON reports. Added repositories each have their own results; every file upload creates a separate source containing all files selected together. Sources and uploaded file objects live in this tab and are cleared on refresh. Removing a source from the tab stops its polling but does not delete backend files/results or cancel a running server job.

The visualization section's report-type selector defaults to all reports **within the selected source**. Its risk donut can count unique source files represented in the reports or individual findings. File ratings use the precedence Critical, High, Unknown, Medium, Low, Safe; files without findings are not listed by the scanners and cannot be counted. Encryption and key-exchange bars count structured algorithm occurrences (a hybrid counts once); a separate bar chart preserves the code/cloud scanners' untyped algorithm labels. Charts are independent of inventory search/risk filters.

Adding a repository or dropping/selecting files immediately submits an analysis request. There is no queue or manual Analyze button. Processing, completion, and error states are per source, and switching sources does not interrupt another source's analysis. Until the backend below is implemented, new sources explicitly show that analysis is unavailable and display no sample results. No scanner, database, or server code is implemented by the frontend.

The visual system pairs locally hosted IBM Plex Mono headings with IBM Plex Sans body text. It uses a 12-column grid, a 4:8 risk/algorithm layout, asymmetric input sections, and numbered editorial rows for the explainer. Warm white and ink surfaces share a single teal accent; severity colors remain reserved for risk data. Subtle circuit traces animate continuously behind the sidebar and input introduction, with static traces for reduced-motion preferences. The Why QuantumTrace page adapts the project PDF introduction, explains Shor’s and Grover’s algorithms with NIST references, and uses tinted reading panels. Font sources and licensing are in `frontend/fonts/`; there are no external font dependencies.

### Analysis API contract

`frontend/source-api.mjs` expects these same-origin endpoints (a proposed contract for the backend):

- `POST /api/sources`: create a source and immediately analyze it. For repositories, accept JSON `{ "clientSourceId": "<stable-client-id>", "repositoryUrl": "https://github.com/team/project.git" }`; the backend clones it into its own directory under `input_files/`. For uploads, accept multipart `clientSourceId` and repeated `files` fields. Deduplicate creation by `clientSourceId` so retrying a failed connection cannot create duplicate sources/jobs.
- Return `{ "id": "<source-id>", "status": "pending" | "processing" | "ready" | "failed", "reports": { ... }, "error": "optional error" }`. When ready, `reports` must be an object whose optional `network`, `code`, and `cloud` keys contain the respective existing CBOM shapes (`metadata`, `components`). An omitted category means this source has no findings in that category, never a fallback to sample data.
- `GET /api/sources/<source-id>`: return the same response shape. The frontend polls pending jobs every 1.5 seconds and refreshes all views automatically on completion. Connection retries with a known server ID resume polling instead of creating another job.

The backend owns source identity, cloning, scanners, and persistence in the respective analysis tables. Responses must contain **only that source's** results. The frontend neither chooses nor creates database tables. Reloading/listing persisted sources can be connected when the backend provides that API.

Run the frontend logic checks with:

```sh
node frontend/model.test.mjs
node frontend/source-api.test.mjs
node frontend/theme.test.mjs
```
