from flask import Flask, request, render_template
import subprocess, os, time, json
import urllib.request

from langchain_ollama import ChatOllama
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
import concurrent.futures


app = Flask(__name__)

def generate_ai_report(vuln_name, description):
    prompt = ChatPromptTemplate.from_messages([
        ("system", """You are an expert in cybersecurity. Write a brief Executive Report for this vulnerability.
        Format strictly like this:
        Business Impact: [1 sentence impact]
        Recommendation: [1 sentence how to fix]
        DO NOT use any markdown formatting, asterisks (**), or bold text."""),
        ("human", "Vulnerability: {name}\nDetails: {desc}")
    ])

    llm = ChatOllama(
        base_url="https://childish-squire-observer.ngrok-free.dev",
        model="llama3.2:1b",
        temperature=0
    )

    chain = prompt | llm | StrOutputParser()
    
    try:
        result = chain.invoke({"name": vuln_name, "desc": description})
        return result.replace("**", "")
    except Exception as e:
        return "AI Error: Make sure Ngrok and Ollama are running locally."

AI_BASE_URL = "https://childish-squire-observer.ngrok-free.dev"

def is_ai_online():
    try:
        urllib.request.urlopen(AI_BASE_URL, timeout=3)
        return True
    except:
        return False

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    target = request.form["target"]

    os.makedirs("results", exist_ok=True)
    output = f"results/output_{int(time.time())}.jsonl"

    cmd = [
    "nuclei",
    "-u", target,
    "-t", "/root/nuclei-templates/http/misconfiguration/http-missing-security-headers.yaml",
    "-jsonl",
    "-o", output,
    "-c", "1",
    "-rl", "1",
    "-timeout", "10",
    "-retries", "0",
    "-silent",
    "-duc"
]

    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=40)
    except Exception as e:
        return f"Scan error: {e}"

    findings = []

    if os.path.exists(output):
        with open(output) as f:
            for line in f:
                if line.strip():
                    findings.append(json.loads(line))
    
    severity_counts = {"info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0, "unknown": 0}
    for f in findings:
        sev = f.get("info", {}).get("severity", "unknown").lower()
        if sev in severity_counts:
            severity_counts[sev] += 1
        else:
            severity_counts["unknown"] += 1
    
    if findings:
        ai_status = is_ai_online()

        def process_ai_for_item(item):
            name = item.get("info", {}).get("name", "Unknown")
            desc = item.get("info", {}).get("description", "")
            if ai_status:
                item["ai_report"] = generate_ai_report(name, desc)
            else:
                item["ai_report"] = "AI is currently offline (Local host is down). No report generated."
            return item

        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            findings = list(executor.map(process_ai_for_item, findings))

    return render_template(
        "index.html",
        target=target,
        findings=findings,
        stderr=r.stderr,
        chart_data=severity_counts
    )

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
