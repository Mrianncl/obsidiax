import sys
import os
import json

# add project root to Python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app import analyze_email # type: ignore

with open("tests/emails.json", "r", encoding="utf-8") as f:
    emails = json.load(f)
print("Running evaluation...\n")
valid = 0
total = len(emails)
for e in emails:
    result = analyze_email(e["text"])
    ok = isinstance(result, dict) and "risk_score" in result and "risk_level" in result
    valid += 1 if ok else 0
    print(
        f'ID {e["id"]} | label={e["label"]} | '
        f'risk_score={result.get("risk_score")} | '
        f'risk_level={result.get("risk_level")}'
    )
print(f"\nJSON validity rate: {valid}/{total}")
