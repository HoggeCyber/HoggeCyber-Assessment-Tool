from flask import Flask, request, render_template
import requests
import dns.resolver
import socket
import ssl
import datetime
import whois
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from virustotal_python import Virustotal
from dotenv import load_dotenv
import os
import logging

# Setup logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# SSL Check
def check_ssl(url):
    try:
        response = requests.get(f"http://{url}", timeout=5)
        if response.url.startswith("https://"):
            return "Secure (HTTPS enabled)", 25
        return "Warning: No HTTPS detected", 0
    except Exception as e:
        logger.error(f"SSL check failed for {url}: {e}")
        return "Error: Couldn’t reach site", 0

# Security Headers Check
def check_headers(url):
    try:
        response = requests.get(f"https://{url}", timeout=5)
        headers = response.headers
        if "X-Content-Type-Options" in headers:
            return "Security headers present", 25
        return "Missing key security headers", 0
    except Exception as e:
        logger.error(f"Headers check failed for {url}: {e}")
        return "Error checking headers", 0

# SPF Record Check
def check_spf(url):
    try:
        answers = dns.resolver.resolve(url, 'TXT')
        for rdata in answers:
            if "v=spf1" in rdata.to_text():
                return "SPF record found (email spoofing protection)", 25
        return "No SPF record detected", 0
    except Exception as e:
        logger.error(f"SPF check failed for {url}: {e}")
        return "Error checking DNS", 0

# DMARC Record Check
def check_dmarc(url):
    try:
        answers = dns.resolver.resolve(url, 'TXT')
        for rdata in answers:
            if "v=DMARC1" in rdata.to_text():
                return "DMARC record found (email authentication enabled)", 25
        return "No DMARC record detected", 0
    except Exception as e:
        logger.error(f"DMARC check failed for {url}: {e}")
        return "Error checking DMARC", 0

# DKIM Record Check
def check_dkim(url):
    try:
        answers = dns.resolver.resolve(f"default._domainkey.{url}", 'TXT')
        for rdata in answers:
            if "v=DKIM1" in rdata.to_text():
                return "DKIM record found (email signing enabled)", 25
        return "No DKIM record detected", 0
    except dns.resolver.NXDOMAIN:
        return "No DKIM record configured", 0
    except Exception as e:
        logger.error(f"DKIM check failed for {url}: {e}")
        return "Error checking DKIM", 0

# Password Strength Check
def check_password(password):
    if not password:
        return "No password provided", 0
    score = 0
    if len(password) >= 8:
        score += 10
    if any(c.isupper() for c in password):
        score += 5
    if any(c.isdigit() for c in password):
        score += 5
    if any(c in "!@#$%^&*" for c in password):
        score += 5
    if score >= 20:
        return "Strong password", 25
    elif score >= 10:
        return "Moderate password strength", 10
    return "Weak password", 0

# Port Scanning Check
def check_ports(url):
    try:
        ip = socket.gethostbyname(url)
        open_ports = []
        for port in [80, 443]:
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
    except Exception as e:
        logger.error(f"Port scan failed for {url}: {e}")
        return "Error scanning ports", 0

# Phishing Risk Check
def check_phishing(url):
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        logger.error("VirusTotal API key not set in environment")
        return "VirusTotal API key not configured", 0
    try:
        vt = Virustotal(API_KEY=api_key, API_VERSION="v3")
        resp = vt.request("urls", data={"url": f"https://{url}"}, method="POST")
        url_id = resp.data["id"]
        analysis = vt.request(f"analyses/{url_id}")
        stats = analysis.data["attributes"]["stats"]
        if stats["malicious"] > 0 or stats["suspicious"] > 0:
            return "Domain flagged as risky by VirusTotal", 0
        return "No phishing/malware flags detected", 25
    except Exception as e:
        logger.error(f"Phishing check failed for {url}: {e}")
        return "Error checking phishing status", 0

# SSL Certificate Expiry Check
def check_ssl_expiry(url):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((url, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=url) as ssock:
                cert = ssock.getpeercert()
                expiry_date = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                days_left = (expiry_date - datetime.datetime.utcnow()).days
                if days_left > 90:
                    return f"SSL certificate valid ({days_left} days left)", 25
                elif days_left > 30:
                    return f"SSL certificate nearing expiry ({days_left} days left)", 10
                return f"SSL certificate expires soon ({days_left} days left)", 0
    except Exception as e:
        logger.error(f"SSL expiry check failed for {url}: {e}")
        return "Error checking SSL expiry", 0

# WHOIS Privacy Check
def check_whois_privacy(url):
    try:
        w = whois.whois(url)
        if not w.registrar or "redacted" in str(w.registrant_name).lower() or "privacy" in str(w.registrar).lower():
            return "WHOIS data is private", 25
        return "WHOIS data is public", 10  # Public data isn’t inherently bad, but less secure
    except Exception as e:
        logger.error(f"WHOIS check failed for {url}: {e}")
        return "Error checking WHOIS privacy", 0

# Generate PDF Report
def create_report(results, score, filename="static/report.pdf"):
    c = canvas.Canvas(filename, pagesize=letter)
    c.setFillColorRGB(0, 0.2, 0.4)
    c.setFont("Helvetica-Bold", 16)
    c.drawString(100, 750, "HoggeCyber Cybersecurity Health Report")
    c.setFont("Helvetica", 12)
    c.drawString(100, 730, f"Score: {score}/250")  # Updated for 10 checks
    y = 700
    for check, result in results.items():
        c.drawString(100, y, f"{check}: {result}")
        y -= 20
    c.save()
    return filename

# Main Route
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
        dmarc_result, dmarc_score = check_dmarc(url)
        dkim_result, dkim_score = check_dkim(url)
        pwd_result, pwd_score = check_password(password)
        ports_result, ports_score = check_ports(url)
        phishing_result, phishing_score = check_phishing(url)
        ssl_expiry_result, ssl_expiry_score = check_ssl_expiry(url)
        whois_result, whois_score = check_whois_privacy(url)
        
        results["SSL Status"] = ssl_result
        results["Security Headers"] = headers_result
        results["SPF Record"] = spf_result
        results["DMARC Record"] = dmarc_result
        results["DKIM Record"] = dkim_result
        results["Password Strength"] = pwd_result
        results["Open Ports"] = ports_result
        results["Phishing Risk"] = phishing_result
        results["SSL Expiry"] = ssl_expiry_result
        results["WHOIS Privacy"] = whois_result
        
        total_score = int(ssl_score + headers_score + spf_score + dmarc_score + 
                         dkim_score + pwd_score + ports_score + phishing_score + 
                         ssl_expiry_score + whois_score)
        
        logger.debug(f"Total score for {url}: {total_score}/250")
        report_path = create_report(results, total_score)
        return render_template("results.html", results=results, score=total_score, report=report_path)
    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True)