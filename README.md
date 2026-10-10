# qqqq project

## Frontend

From the repository root, serve the project with Python (no packages or build step needed):

```sh
python3 -m http.server 8000 --bind 127.0.0.1
```

Open **http://localhost:8000/frontend/**. Serve the repository root, since the dashboard loads `pipeline/cbom_network_classified.json` directly as a sample report.

The frontend supports drag-and-drop or file selection, a queue of validated GitHub/GitLab HTTPS repository URLs (including GitLab subgroups), removal/reset of staged inputs, searchable risk-filtered sessions, session details, and JSON export.

This is a frontend-only preview. Files and repository URLs are staged in memory for the current tab; refreshing clears them. Uploading, cloning into `input_files/`, analysis, and deleting input files on disk need a backend. The reset button currently clears only the browser queue. The sample report remains visible independently of the queue. No database integration is implemented.

When connecting the backend, replace the sample fetch in `frontend/app.mjs` with the report API, and connect the staged `File` objects, repository URLs, and reset/analysis actions to the corresponding endpoints. The report view currently expects the JSON's `metadata` and `components` structure. SQLite access and `git clone` belong on that backend.

Run the frontend logic checks with:

```sh
node frontend/model.test.mjs
```
