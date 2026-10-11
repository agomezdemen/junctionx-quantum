import json
import os

from load_db import (
    load_cloud_infrastructure,
    load_code_classification,
    load_network_session,
)


def load_json_file(file_path: str) -> dict:
    with open(file_path, "r") as f:
        return json.load(f)


def ingest_cbom_file(file_path: str):
    if not os.path.exists(file_path):
        return

    cbom_dict = load_json_file(file_path)
    components = cbom_dict.get("components", {})

    if not components:
        return

    first_type = components[0].get("type", "")

    if first_type == "application-code":
        load_code_classification(cbom_dict)

    elif first_type == "network-session":
        load_network_session(cbom_dict)

    else:
        load_cloud_infrastructure(cbom_dict)


if __name__ == "__main__":
    import glob

    files_to_load = glob.glob("*.json")

    if not files_to_load:
        print("No json files in this directory")

    else:
        for cbom_file in files_to_load:
            ingest_cbom_file(cbom_file)

    for cbom_file in files_to_load:
        ingest_cbom_file(cbom_file)
