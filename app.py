from flask import Flask, request, render_template
import requests
import dns.resolver
import socket
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

app = Flask(__name__)

# Existing checks (unchanged)
def check_ssl(url):  # Same as before
    try:
        response = requests.get(f"http://{url}", timeout=5)
        if response.url.startswith("https://"):
            return "Secure (HTTPS enabled)", 25
        return "Warning: No HTTPS detected", 0
    except:
        return "Error: Couldn’t reach site", 0

def check_headers(url):  # Same as before
    try:
        response = requests.get(f"https://{url}", timeout=5)
        headers = response.headers
        if "X-Content-Type-Options" in headers:
            return "Security headers present", 25
        return "Missing key security headers", 0
    except:
        return "Error checking headers", 0

def check_spf(url):  # Same as before
    try:
        answers = dns.resolver.resolve(url, 'TXT')
        for rdata in answers:
            if "v=spf1" in rdata.to_text():
                return "SPF record found (email spoofing protection)", 25
        return "No SPF record detected", 0
    except:
        return "Error checking DNS", 0

def check_password(password):  # Same as before
    if not password:
        return "No password provided", 0
    score = 0
    if len(password) >= 8: score += 10
    if any(c.isupper() for c in password): score += 5
    if any(c.isdigit() for c in password): score += 5
    if any(c in "!@#$%^&*" for c in password): score += 5
    return "Strong password" if score >= 20 else "Moderate password" if score >= 10 else "Weak password", min(score, 25)

# New Port Scanning Check
def check_ports(url):
    try:
        ip = socket.gethostbyname(url)
        open_ports = []
        for port in [80, 443]:  # Check common ports
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        if len(open_ports) == 1 and 443 in open_ports:
            return "Only HTTPS (443) open—secure setup", 25
        elif open_ports:
            return f"Open ports detected: {open_ports}—potential risk", 10
        return "No common ports open", 20
    except:
        return "Error scanning ports", 0

def create_report(results, score, filename="static/report.pdf"):  # Same as before
    c = canvas.Canvas(filename, pagesize=letter)
    c.setFillColorRGB(0, 0.2, 0.4)
    c.setFont("Helvetica-Bold", 16)
    c.drawString(100, 750, "HoggeCyber Cybersecurity Health Report")
    c.setFont("Helvetica", 12)
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
        password = request.form.get("password", "")
        results = {}
        total_score = 0
        
        ssl_result, ssl_score = check_ssl(url)
        headers_result, headers_score = check_headers(url)
        spf_result, spf_score = check_spf(url)
        pwd_result, pwd_score = check_password(password)
        ports_result, ports_score = check_ports(url)
        
        results["SSL Status"] = ssl_result
        results["Security Headers"] = headers_result
        results["SPF Record"] = spf_result
        results["Password Strength"] = pwd_result
        results["Open Ports"] = ports_result
        
        total_score = int(ssl_score + headers_score + spf_score + pwd_score + ports_score)
        
        report_path = create_report(results, total_score)
        return render_template("results.html", results=results, score=total_score, report=report_path)
    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True)