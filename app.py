from flask import Flask, request, render_template
import requests
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

app = Flask(__name__)

# SSL Check
def check_ssl(url):
    try:
        response = requests.get(f"http://{url}", timeout=5)
        if response.url.startswith("https://"):
            return "Secure (HTTPS enabled)", 50
        return "Warning: No HTTPS detected", 0
    except:
        return "Error: Couldn’t reach site", 0

# Headers Check
def check_headers(url):
    try:
        response = requests.get(f"https://{url}", timeout=5)
        headers = response.headers
        if "X-Content-Type-Options" in headers:
            return "Security headers present", 30
        return "Missing key security headers", 0
    except:
        return "Error checking headers", 0

# Generate PDF Report
def create_report(results, score, filename="static/report.pdf"):
    c = canvas.Canvas(filename, pagesize=letter)
    c.drawString(100, 750, "HoggeCyber Cybersecurity Health Report")
    c.drawString(100, 730, f"Score: {score}/100")
    y = 700
    for check, result in results.items():
        c.drawString(100, y, f"{check}: {result}")
        y -= 20
    c.save()
    return filename

@app.route("/", methods=["GET", "POST"])
def health_check():
    if request.method == "POST":
        url = request.form["url"]
        results = {}
        total_score = 0
        
        ssl_result, ssl_score = check_ssl(url)
        headers_result, headers_score = check_headers(url)
        
        results["SSL Status"] = ssl_result
        results["Security Headers"] = headers_result
        total_score = ssl_score + headers_score
        
        report_path = create_report(results, total_score)
        return render_template("results.html", results=results, score=total_score, report=report_path)
    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True)