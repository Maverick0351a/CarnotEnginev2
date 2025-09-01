#!/usr/bin/env python3
import sys, json
from jsonschema import validate, Draft202012Validator

"""
Usage:
  python ops/validate_schema.py schema/ccm.schema.json integrations/runtime/artifacts/runtime.ccm.json
"""

def main(schema_path, doc_path):
    with open(schema_path, 'r') as f:
        schema = json.load(f)
    with open(doc_path, 'r') as f:
        doc = json.load(f)
    Draft202012Validator.check_schema(schema)
    validate(doc, schema)
    print(f"OK {doc_path} validates against {schema_path}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("usage: validate_schema.py <schema.json> <doc.json>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])
