import sqlite3

DB_FILE = "quantumtrace.db"


def init_db(db_path: str = DB_FILE) -> None:
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS qr_classification(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_type TEXT NOT NULL,
                file_path TEXT,
                language TEXT,
                library TEXT,
                primitive TEXT NOT NULL,
                risk TEXT NOT NULL,
                key_size INTEGER,
                line_number INTEGER,
                nist_standard TEXT,
                suggestion TEXT,
                code_snippet TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()


def add_classification(classification: dict, db_path: str = DB_FILE) -> None:
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO qr_classification(source_type, file_path, language, library, primitive, risk, key_size, line_number, nist_standard, suggestion,
            code_snippet) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) 
        """,
            (
                classification.get("source_type"),
                classification.get("file_path"),
                classification.get("language"),
                classification.get("library"),
                classification.get("primitive"),
                classification.get("risk"),
                classification.get("key_size"),
                classification.get("line_number"),
                classification.get("nist_standard"),
                classification.get("suggestion"),
                classification.get("code_snippet"),
            ),
        )
        conn.commit()
