from flask import Flask, request, render_template
import subprocess, os, time, json

app = Flask(__name__)

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
