import json
import re
import requests
import os
API_URL = "https://api.airia.ai/v2/PipelineExecution/03e44d6f-167f-4c46-be5a-d9d6ab3fa100"
API_KEY = os.getenv("AIRIA_API_KEY", "")

HEADERS = {
    "X-API-Key": API_KEY,
    "Content-Type": "application/json",
}
FALLBACK = {
    "risk_score": 0,
    "risk_level": "Low",
    "key_indicators": ["Formatting/parse error"],
    "explanation": "Model returned an output that could not be parsed as valid JSON.",
    "recommended_action": "Review email manually.",
    "story_narrative": "The system could not produce a structured report for this email.",
    "attacker_persona": {
        "persona_name": "Unknown",
        "traits": [],
        "evidence": ["Fallback used"]
    }
}
def invoke_airia(user_input: str) -> dict:
    payload = {"userInput": user_input, "asyncOutput": False}
    r = requests.post(API_URL, json=payload, headers=HEADERS, timeout=60)
    r.raise_for_status()
    return r.json()
def extract_json_from_text(text: str) -> dict:
    """
    Try strict JSON parse.
    If model wrapped JSON with extra text, try to extract the first {...} block.
    """
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # 2) extract first JSON object block
    m = re.search(r"\{[\s\S]*\}", text)
    if not m:
        raise json.JSONDecodeError("No JSON object found", text, 0)
    return json.loads(m.group(0))
def analyze_email(email_content: str) -> dict:
    prompt = (
        "You are Obsidiax, an email phishing risk analyzer.\n"
        "Return ONLY valid JSON. No markdown. No extra text.\n"
        "Use this exact schema:\n"
        "{\n"
        '  "risk_score": 0-100,\n'
        '  "risk_level": "Low"|"Medium"|"High"|"Critical",\n'
        '  "key_indicators": ["..."],\n'
        '  "explanation": "...",\n'
        '  "recommended_action": "...",\n'
        '  "story_narrative": "...",\n'
        '  "attacker_persona": {\n'
        '    "persona_name": "...",\n'
        '    "traits": ["..."],\n'
        '    "evidence": ["..."]\n'
        "  }\n"
        "}\n\n"
        "Email:\n"
        f"{email_content}\n"
    )
    raw = invoke_airia(prompt)
    model_text = raw.get("result", "")
    if not isinstance(model_text, str):
        return FALLBACK
    try:
        cleaned = extract_json_from_text(model_text)
        if "risk_score" not in cleaned or "risk_level" not in cleaned:
            return FALLBACK
        return cleaned
    except Exception:
        return FALLBACK
if __name__ == "__main__":
    print("Paste the full email content. When done, type END on a new line, then press Enter:\n")
    lines = []
    while True:
        line = input()
        if line.strip() == "END":
            break
        lines.append(line)
    email_content = "\n".join(lines).strip()
    if not email_content:
        print("No email pasted. Exiting.")
    else:
        result = analyze_email(email_content)
        print(json.dumps(result, indent=2))

