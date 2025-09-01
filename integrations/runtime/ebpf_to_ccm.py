#!/usr/bin/env python3
import json, sys, os, datetime
from jsonschema import validate

def iso(t):
    try:
        return datetime.datetime.fromisoformat(t.replace('Z','+00:00'))
    except Exception:
        return None

def load_schema(path):
    with open(path,'r') as f: return json.load(f)

def main(inp, outp):
    obs = []
    with open(inp,'r') as f:
        for line in f:
            if not line.strip(): continue
            obs.append(json.loads(line))
    doc = {"version":"2.1","observations":obs}
    schema = load_schema(os.path.join(os.path.dirname(__file__), "../../schema/ccm.schema.json").replace('/integrations/runtime/../','/schema/'))
    validate(doc, schema)
    os.makedirs(os.path.dirname(outp), exist_ok=True)
    with open(outp,'w') as f: json.dump(doc, f, indent=2)
    print(f"Wrote CCM with {len(obs)} observations -> {outp}")

if __name__ == "__main__":
    if len(sys.argv)<3:
        print("usage: ebpf_to_ccm.py <runtime.jsonl> <runtime.ccm.json>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])
