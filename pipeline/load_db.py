from database import add_network_session, init_db


def load_network_session(cbom: dict):
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

    print("Successfully loaded sessions into the database!")
