from database import (
    add_cloud_component,
    add_code_classification,
    add_network_session,
    init_db,
)

def load_network_session(cbom: dict, source_id: int = None):
    init_db()
    for component in cbom.get("components", []):
        if component.get("type") != "network-session":
            continue

        evidence = component.get("evidence", {})
        props = component.get("cryptoProperties", {})
        enc_props = props.get("encryption", {})
        hash_props = props.get("hash", {})
        key_props = props.get("keyExchange", {})
        aut_props = props.get("authentication", {})

        session_data = {
            "source_id": source_id,
            "client_endpoint": evidence.get("client"),
            "server_endpoint": evidence.get("server"),
            "protocol": props.get("protocol"),
            "encryption_algorithm": enc_props.get("algorithm"),
            "encryption_risk": enc_props.get("risk"),
            "hash_algorithm": hash_props.get("algorithm"),
            "hash_risk": hash_props.get("risk"),
            "key_exchange_algorithm": key_props.get("algorithm"),
            "key_exchange_risk": key_props.get("risk"),
            "authentication_algorithm": aut_props.get("algorithm"),
            "authentication_risk": aut_props.get("risk"),
            "conclusion": component.get("risk"),
        }
        add_network_session(session_data)

    print("Successfully loaded network sessions into the database!")

def load_cloud_infrastructure(cbom: dict, source_id: int = None):
    init_db()
    for component in cbom.get("components", []):
        props = component.get("cryptoProperties", {})
        assessment = component.get("quantumRiskAssessment", {})

        algorithm = (
            props.get("keySpec")
            or props.get("keyAlgorithm")
            or props.get("sslPolicy")
            or "Unknown"
        )
        arn = component.get("arn", "")
        provider = "AWS" if "arn:aws" in arn else "Unknown Provider"

        component_data = {
            "source_id": source_id,
            "resource_type": f"{component.get('type', 'resource')} ({component.get('name', 'unnamed')})",
            "provider": provider,
            "encryption_algorithm": algorithm,
            "key_management": props.get("origin") or props.get("type", "Unknown"),
            "risk_level": assessment.get("tier", "UNKNOWN").upper(),
            "conclusion": assessment.get("reason", "No assessment provided."),
        }
        add_cloud_component(component_data)

    print("Successfully loaded cloud infrastructure into the database!")

def load_code_classification(cbom: dict, source_id: int = None):
    init_db()
    for component in cbom.get("components", []):
        props = component.get("cryptoProperties", {})
        assessment = component.get("quantumRiskAssessment", {})

        code_data = {
            "source_id": source_id,
            "file_path": component.get("source", "Unknown Path"),
            "language": props.get("language", "Unknown"),
            "primitive": props.get("detectedAlgorithm", "Unknown"),
            "risk": assessment.get("tier", "UNKNOWN").upper(),
            "key_size": props.get("keySize"),
            "line_number": component.get("line"),
            "suggestion": assessment.get("reason"),
            "code_snippet": component.get("codeSnippet", ""),
        }
        add_code_classification(code_data)

    print("Successfully loaded code classification into the database!")
