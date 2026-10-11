import sqlite3

DB_FILE = "quantumtrace.db"


def init_db(db_path: str = DB_FILE) -> None:
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS code_classification (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT NOT NULL,
                language TEXT NOT NULL,
                primitive TEXT NOT NULL,
                risk TEXT NOT NULL,
                key_size INTEGER,
                line_number INTEGER,
                suggestion TEXT,
                code_snippet TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS network_session (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_endpoint TEXT NOT NULL,
                server_endpoint TEXT NOT NULL,
                protocol TEXT,
                encryption_algorithm TEXT,
                encryption_risk TEXT,
                hash_algorithm TEXT,
                hash_risk TEXT,
                key_exchange_algorithm TEXT,
                key_exchange_risk TEXT,
                authentication_algorithm TEXT,
                authentication_risk TEXT,
                conclusion TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            ) """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cloud_infrastructure (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                resource_type TEXT,       
                provider TEXT,
                encryption_algorithm TEXT,
                key_management TEXT,       
                risk_level TEXT,          
                conclusion TEXT           
            ) """)

        conn.commit()


def add_code_classification(classification: dict, db_path: str = DB_FILE) -> None:
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO code_classification (file_path, language, primitive, risk, key_size, line_number, suggestion,
            code_snippet) VALUES (?, ?, ?, ?, ?, ?, ?, ?) 
        """,
            (
                classification.get("file_path"),
                classification.get("language"),
                classification.get("primitive"),
                classification.get("risk"),
                classification.get("key_size"),
                classification.get("line_number"),
                classification.get("suggestion"),
                classification.get("code_snippet"),
            ),
        )
        conn.commit()


def add_network_session(session: dict, db_path: str = DB_FILE) -> None:
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO network_session (
                client_endpoint, server_endpoint, protocol,
                encryption_algorithm, encryption_risk,
                hash_algorithm, hash_risk,
                key_exchange_algorithm, key_exchange_risk,
                authentication_algorithm, authentication_risk,
                conclusion
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                session.get("client_endpoint"),
                session.get("server_endpoint"),
                session.get("protocol"),
                session.get("encryption_algorithm"),
                session.get("encryption_risk"),
                session.get("hash_algorithm"),
                session.get("hash_risk"),
                session.get("key_exchange_algorithm"),
                session.get("key_exchange_risk"),
                session.get("authentication_algorithm"),
                session.get("authentication_risk"),
                session.get("conclusion"),
            ),
        )
        conn.commit()


def add_cloud_component(data: dict, db_path: str = DB_FILE) -> None:
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
                INSERT INTO cloud_infrastructure (
                resource_type, provider, encryption_algorithm, 
                key_management, risk_level, conclusion
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                data.get("resource_type"),
                data.get("provider"),
                data.get("encryption_algorithm"),
                data.get("key_management"),
                data.get("risk_level"),
                data.get("conclusion"),
            ),
        )
        conn.commit()
