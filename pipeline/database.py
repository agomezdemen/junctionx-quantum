import sqlite3

DB_FILE = "quantumtrace.db"

def get_connection():
    return sqlite3.connect(DB_FILE)


def init_db(db_path: str = DB_FILE) -> None:
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        
        # 1. Tabela de Fontes
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS input_sources (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                target_path TEXT,
                source_type TEXT NOT NULL,         -- "upload" ou "git_repo"
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                total_assets INTEGER DEFAULT 0,
                risk_score REAL DEFAULT 0.0
            ) 
        """)
        
        # 2. Classificação de Código (com source_id)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS code_classification (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_id INTEGER,
                file_path TEXT NOT NULL,
                language TEXT NOT NULL,
                primitive TEXT NOT NULL,
                risk TEXT NOT NULL,
                key_size INTEGER,
                line_number INTEGER,
                suggestion TEXT,
                code_snippet TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(source_id) REFERENCES input_sources(id)
            )
        """)

        # 3. Sessões de Rede (com source_id)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS network_session (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_id INTEGER,
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
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(source_id) REFERENCES input_sources(id)
            ) 
        """)

        # 4. Infraestrutura Cloud (com source_id)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cloud_infrastructure (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_id INTEGER,
                resource_type TEXT,       
                provider TEXT,
                encryption_algorithm TEXT,
                key_management TEXT,       
                risk_level TEXT,          
                conclusion TEXT,
                FOREIGN KEY(source_id) REFERENCES input_sources(id)
            ) 
        """)

        conn.commit()


def create_source(name: str, target_path: str, source_type: str, db_path: str = DB_FILE) -> int:
    init_db(db_path)
    with sqlite3.connect(db_path) as conn:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO input_sources (name, target_path, source_type) VALUES (?, ?, ?)",
            (name, target_path, source_type)
        )
        source_id = cur.lastrowid
        conn.commit()
    return source_id


def add_code_classification(classification: dict, db_path: str = DB_FILE) -> None:
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO code_classification (
                source_id, file_path, language, primitive, risk, key_size, line_number, suggestion, code_snippet
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) 
            """,
            (
                classification.get("source_id"),
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
                source_id, client_endpoint, server_endpoint, protocol,
                encryption_algorithm, encryption_risk,
                hash_algorithm, hash_risk,
                key_exchange_algorithm, key_exchange_risk,
                authentication_algorithm, authentication_risk,
                conclusion
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                session.get("source_id"),
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
                source_id, resource_type, provider, encryption_algorithm, 
                key_management, risk_level, conclusion
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                data.get("source_id"),
                data.get("resource_type"),
                data.get("provider"),
                data.get("encryption_algorithm"),
                data.get("key_management"),
                data.get("risk_level"),
                data.get("conclusion"),
            ),
        )
        conn.commit()