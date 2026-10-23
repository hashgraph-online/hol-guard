"""Negative grading control: missing Fahrenheit offset and wrong reverse formula.

Stage only inside the explicitly declared isolated Linux grading worker.
"""
import argparse
import json

parser = argparse.ArgumentParser()
parser.add_argument("value", type=float)
parser.add_argument("--from", dest="source", required=True)
parser.add_argument("--to", dest="target", required=True)
parser.add_argument("--json", action="store_true")
args = parser.parse_args()
print(json.dumps({"value": args.value * 9 / 5, "unit": args.target}))
