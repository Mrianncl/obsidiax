from flask import Flask, request, render_template_string
import requests
import json
import re
import os
import time
import hashlib

app = Flask(__name__)
API_URL = "https://api.airia.ai/v2/PipelineExecution/03e44d6f-167f-4c46-be5a-d9d6ab3fa100"
API_KEY = os.getenv("AIRIA_API_KEY", "")
HEADERS = {
    "X-API-KEY": API_KEY,
    "Content-Type": "application/json"
}
HTML = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Obsidiax – Phishing Risk Analyzer</title>
  <style>
    body {
      font-family: Arial, sans-serif;
      margin: 30px;
      max-width: 900px;
      background: #f9fafb;
    }
    textarea {
      width: 100%;
      height: 200px;
      font-family: monospace;
      padding: 10px;
    }
    button {
      padding: 10px 18px;
      margin-top: 10px;
      background: #111827;
      color: white;
      border: none;
      border-radius: 6px;
      cursor: pointer;
    }
    .card {
      background: white;
      border-radius: 10px;
      padding: 16px;
      margin-top: 20px;
      box-shadow: 0 4px 12px rgba(0,0,0,0.08);
    }
    .risk {
      font-size: 22px;
      font-weight: bold;
    }
    .critical { color: #dc2626; }
    .high { color: #ea580c; }
    .medium { color: #ca8a04; }
    .low { color: #16a34a; }
    ul { margin-left: 18px; }
    pre {
      background: #111827;
      color: #e5e7eb;
      padding: 12px;
      border-radius: 8px;
      overflow-x: auto;
    }
  </style>
</head>
<body>
  <h2> Obsidiax : Autonomous Phishing Detection</h2>
  <form method="POST">
    <textarea name="email_content" placeholder="Paste the email here...">{{ email_content }}</textarea><br>
    <button type="submit" onclick="this.disabled=true; this.innerText='Analyzing...'; this.form.submit();">
        Analyze Email
    </button>
    {% if result and result.error %}
  <div class="card">
    <h3 style="color:#dc2626;">Error</h3>
    <pre>{{ result.error }}</pre>
  </div>
{% endif %}
  </form>
  {% if result %}
    <div class="card">
      <div class="risk {{ result.risk_level | lower }}">
        Risk Score: {{ result.risk_score }} / 100 ({{ result.risk_level }})
      </div>
    </div>
    <div class="card">
      <h3>Key Indicators</h3>
      <ul>
        {% for item in result.key_indicators %}
          <li>{{ item }}</li>
        {% endfor %}
      </ul>
    </div>
    <div class="card">
      <h3>Explanation</h3>
      <p>{{ result.explanation }}</p>
    </div>
    <div class="card">
      <h3>Attack Story</h3>
      <p>{{ result.story_narrative }}</p>
    </div>
    <div class="card">
      <h3>Attacker Persona: {{ result.attacker_persona.persona_name }}</h3>
      <b>Traits:</b>
      <ul>
        {% for t in result.attacker_persona.traits %}
          <li>{{ t }}</li>
        {% endfor %}
      </ul>
      <b>Evidence:</b>
      <ul>
        {% for e in result.attacker_persona.evidence %}
          <li>{{ e }}</li>
        {% endfor %}
      </ul>
    </div>
    <div class="card">
      <h3>Raw JSON (for logs / automation)</h3>
      <pre>{{ result_json }}</pre>
    </div>
  {% endif %}
</body>
</html>
"""

FALLBACK_JSON = {
    "risk_score": 0,
    "risk_level": "Low",
    "key_indicators": ["Insufficient data"],
    "explanation": "The email content could not be analyzed.",
    "recommended_action": "Verify the message manually through official channels.",
    "story_narrative": "The system could not extract enough information to evaluate this email safely.",
    "attacker_persona": {
        "persona_name": "Unknown",
        "traits": ["No data"],
        "evidence": ["Analysis failed"]
    }
}
def build_prompt(email_text: str) -> str:
    return f"""
CRITICAL OUTPUT RULE:
Return ONLY ONE valid JSON object.
The very first character must be {{and the very last character must be}}.
Do not wrap in ``` or add markdown.
No headings, no commentary, no extra text.
All fields must be present even if you must  write "Unknown".


You are Obsidiax, an autonomous cybersecurity agent specializing in phishing detection.

Your task:
- Analyze the given email content.
- Decide how likely it is to be a phishing attempt.
- Explain your reasoning USING ONLY FIELDS INSIDE THE JSON.
- Suggest what the user should do next.
- Create a short attack story to help humans understand what is happening.
- Identify whether this email matches a recurring attacker persona.

Analyze the following email:
{email_text}

FINAL OUTPUT REQUIREMENT:
Return EXACTLY the JSON object below.

{{
  "risk_score": 0,
  "risk_level": "Low",
  "key_indicators": ["...", "..."],
  "explanation": "...",
  "recommended_action": "...",
  "story_narrative": "5–7 sentences written like a short story explaining the attack.",
  "attacker_persona": {{
    "persona_name": "...",
    "traits": ["...", "..."],
    "evidence": ["why this persona was chosen"]
  }}
}}
""".strip()

CACHE = {}  # simple in-memory cache

def _hash_email(prompt: str) -> str:
    return hashlib.sha256(prompt.encode("utf-8")).hexdigest()

def invoke_airia(prompt: str) -> str:
    if not API_KEY:
        raise RuntimeError("AIRIA_API_KEY is not set.")

    # caching reduces cost + helps with rate limits
    key = _hash_email(prompt)
    if key in CACHE:
        return CACHE[key]

    payload = {"userInput": prompt, "asyncOutput": False}

    max_attempts = 3
    backoff = 1.5
    last_err = None

    for attempt in range(1, max_attempts + 1):
        try:
            t0 = time.time()
            r = requests.post(API_URL, json=payload, headers=HEADERS, timeout=60)
            latency = time.time() - t0

            if r.status_code == 429:
                raise RuntimeError(f"Rate limited (429). Try again later. Latency={latency:.2f}s")

            r.raise_for_status()
            data = r.json()

            if "result" not in data:
                raise RuntimeError(f"Airia response missing 'result': {data}")

            result = data["result"] or ""
            CACHE[key] = result
            return result

        except Exception as e:
            last_err = e
            if attempt < max_attempts:
                time.sleep(backoff)
                backoff *= 2
            else:
                raise RuntimeError(f"Airia API failed after {max_attempts} attempts: {last_err}")
def extract_json(text: str) -> dict:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    match = re.search(r"\{[\s\S]*\}", text)
    if match:
        return json.loads(match.group(0))
    return FALLBACK_JSON
def preprocess_email(text: str) -> str:
    text = text.strip()
    text = re.sub(r'\r\n', '\n', text)
    text = re.sub(r'\n{3,}', '\n\n', text)
    return text[:8000]  # prevent huge input
def validate_output(parsed: dict) -> dict:
    if not isinstance(parsed, dict):
        return FALLBACK_JSON

    required = ["risk_score", "risk_level", "key_indicators", "explanation",
                "recommended_action", "story_narrative", "attacker_persona"]
    for k in required:
        if k not in parsed:
            return FALLBACK_JSON

    # clamp score 0-100
    try:
        score = int(parsed["risk_score"])
        parsed["risk_score"] = max(0, min(100, score))
    except:
        return FALLBACK_JSON

    return parsed
def analyze_email(email_text: str) -> dict:
    try:
        email_text = preprocess_email(email_text)
        prompt = build_prompt(email_text)
        raw_output = invoke_airia(prompt)
        parsed = extract_json(raw_output)
        parsed = validate_output(parsed)
        return parsed
    except Exception as e:
        fb = dict(FALLBACK_JSON)
        fb["error"] = str(e)
        return fb

@app.route("/", methods=["GET", "POST"])
def home():
    email_content = ""
    result = None
    result_json = ""
    if request.method == "POST":
        email_content = request.form.get("email_content", "")
        if email_content.strip():
            result = analyze_email(email_content)
            result_json = json.dumps(result, indent=2)
    return render_template_string(
        HTML,
        email_content=email_content,
        result=result,
        result_json=result_json
    )
if __name__ == "__main__":
    app.run(debug=True)
