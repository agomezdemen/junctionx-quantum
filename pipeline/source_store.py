"""Source-scoped SQLite storage, retaining the complete scanner evidence."""
import json
import sqlite3
from contextlib import contextmanager

from pipeline.database import init_db

TABLES = {"network": "network_session", "code": "code_classification", "cloud": "cloud_classification"}


class SourceStore:
    def __init__(self, path):
        self.path = str(path)
        init_db(self.path)
        with self.connect() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS analysis_source (
                    id TEXT PRIMARY KEY, client_id TEXT UNIQUE, name TEXT NOT NULL,
                    kind TEXT NOT NULL, url TEXT, files_json TEXT NOT NULL DEFAULT '[]',
                    status TEXT NOT NULL, error TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS source_report (
                    source_id TEXT NOT NULL REFERENCES analysis_source(id),
                    kind TEXT NOT NULL, header_json TEXT NOT NULL,
                    PRIMARY KEY (source_id, kind)
                );
                CREATE TABLE IF NOT EXISTS cloud_classification (
                    id INTEGER PRIMARY KEY, asset_type TEXT, name TEXT, risk TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                );
            """)
            for table in TABLES.values():
                columns = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
                for column in ("source_id", "component_json"):
                    if column not in columns:
                        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} TEXT")
                conn.execute(f"CREATE INDEX IF NOT EXISTS {table}_source ON {table}(source_id)")
            # Keep rows created by the original database helpers visible.
            if any(conn.execute(f"SELECT 1 FROM {table} WHERE source_id IS NULL LIMIT 1").fetchone() for table in TABLES.values()):
                conn.execute("INSERT OR IGNORE INTO analysis_source(id,name,kind,status) VALUES('legacy','Existing database','database','ready')")
                for kind, table in TABLES.items():
                    conn.execute(f"UPDATE {table} SET source_id='legacy' WHERE source_id IS NULL")
                    conn.execute("INSERT OR IGNORE INTO source_report VALUES('legacy', ?, '{}')", (kind,))
            conn.execute("UPDATE analysis_source SET status='failed', error='Analysis was interrupted by a server restart. Retry this source.' WHERE status IN ('pending','processing')")

    @contextmanager
    def connect(self):
        conn = sqlite3.connect(self.path, timeout=15)
        conn.row_factory = sqlite3.Row
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def create(self, source):
        with self.connect() as conn:
            conn.execute("""INSERT INTO analysis_source(id,client_id,name,kind,url,files_json,status)
                VALUES(?,?,?,?,?,?,?)""", (source["id"], source.get("clientSourceId"), source["name"], source["kind"],
                                          source.get("url"), json.dumps(source.get("files", [])), source.get("status", "pending")))

    def find_client(self, client_id):
        with self.connect() as conn:
            row = conn.execute("SELECT id FROM analysis_source WHERE client_id=?", (client_id,)).fetchone()
        return self.get(row[0]) if row else None

    def list(self):
        with self.connect() as conn:
            return [self.describe(row) for row in conn.execute("SELECT * FROM analysis_source ORDER BY created_at, rowid")]

    @staticmethod
    def describe(row):
        return {"id": row["id"], "name": row["name"], "kind": row["kind"], "url": row["url"],
                "files": json.loads(row["files_json"]), "status": row["status"], "error": row["error"],
                "createdAt": row["created_at"]}

    def get(self, source_id):
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM analysis_source WHERE id=?", (source_id,)).fetchone()
            if row is None:
                return None
            source = self.describe(row)
            if source["status"] == "ready":
                source["reports"] = {}
                for report in conn.execute("SELECT * FROM source_report WHERE source_id=?", (source_id,)):
                    kind = report["kind"]
                    header = json.loads(report["header_json"])
                    header["components"] = [json.loads(r["component_json"]) if r["component_json"] else legacy_component(kind, r)
                                            for r in conn.execute(f"SELECT * FROM {TABLES[kind]} WHERE source_id=? ORDER BY id", (source_id,))]
                    source["reports"][kind] = header
            return source

    def status(self, source_id, status, error=None):
        with self.connect() as conn:
            conn.execute("UPDATE analysis_source SET status=?,error=? WHERE id=?", (status, error, source_id))

    def save_reports(self, source_id, reports):
        # Report replacement and readiness commit together; retries cannot duplicate findings.
        with self.connect() as conn:
            for table in TABLES.values():
                conn.execute(f"DELETE FROM {table} WHERE source_id=?", (source_id,))
            conn.execute("DELETE FROM source_report WHERE source_id=?", (source_id,))
            for kind, report in reports.items():
                conn.execute("INSERT INTO source_report VALUES(?,?,?)", (source_id, kind, json.dumps({k: v for k, v in report.items() if k != "components"})))
                for component in report["components"]:
                    values = classification_columns(kind, component)
                    values.update(source_id=source_id, component_json=json.dumps(component))
                    conn.execute(f"INSERT INTO {TABLES[kind]} ({','.join(values)}) VALUES ({','.join('?' for _ in values)})", tuple(values.values()))
            conn.execute("UPDATE analysis_source SET status='ready',error=NULL WHERE id=?", (source_id,))

    def delete(self, source_id):
        with self.connect() as conn:
            for table in TABLES.values():
                conn.execute(f"DELETE FROM {table} WHERE source_id=?", (source_id,))
            conn.execute("DELETE FROM source_report WHERE source_id=?", (source_id,))
            conn.execute("DELETE FROM analysis_source WHERE id=?", (source_id,))


def classification_columns(kind, component):
    props = component.get("cryptoProperties", {})
    assessment = component.get("quantumRiskAssessment", {})
    if kind == "network":
        evidence = component.get("evidence", {})
        values = {"client_endpoint": evidence.get("client") or "Not recorded", "server_endpoint": evidence.get("server") or "Not recorded",
                  "protocol": props.get("protocol"), "conclusion": component.get("risk") or "UNKNOWN"}
        for field, column in (("encryption", "encryption"), ("hash", "hash"), ("keyExchange", "key_exchange"), ("authentication", "authentication")):
            details = props.get(field, {})
            values[column + "_algorithm"] = details.get("algorithm")
            values[column + "_risk"] = details.get("risk")
        return values
    if kind == "code":
        return {"file_path": component.get("source") or "Not recorded", "language": props.get("language") or "Unknown",
                "library": props.get("library") or "Not recorded", "primitive": props.get("detectedAlgorithm") or "Unknown",
                "risk": assessment.get("tier") or "UNKNOWN", "key_size": props.get("keySizeBits"), "line_number": component.get("line"),
                "nist_standard": assessment.get("nistStandard"), "suggestion": assessment.get("suggestion"), "code_snippet": component.get("codeSnippet")}
    return {"asset_type": component.get("type"), "name": component.get("name"), "risk": assessment.get("tier")}


def legacy_component(kind, row):
    if kind == "network":
        props = {"protocol": row["protocol"]}
        for field, column in (("encryption", "encryption"), ("hash", "hash"), ("keyExchange", "key_exchange"), ("authentication", "authentication")):
            props[field] = {"algorithm": row[column + "_algorithm"], "risk": row[column + "_risk"]}
        return {"type": "network-session", "name": f"TLS session {row['id']}", "risk": row["conclusion"],
                "evidence": {"client": row["client_endpoint"], "server": row["server_endpoint"]}, "cryptoProperties": props}
    if kind == "code":
        return {"type": "application-code", "name": f"{row['file_path']}:{row['line_number']}", "source": row["file_path"],
                "line": row["line_number"], "codeSnippet": row["code_snippet"],
                "cryptoProperties": {"language": row["language"], "library": row["library"], "detectedAlgorithm": row["primitive"], "keySizeBits": row["key_size"]},
                "quantumRiskAssessment": {"tier": row["risk"], "suggestion": row["suggestion"], "nistStandard": row["nist_standard"]}}
    return {"type": row["asset_type"], "name": row["name"], "quantumRiskAssessment": {"tier": row["risk"]}}
