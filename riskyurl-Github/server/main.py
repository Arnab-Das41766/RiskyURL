from flask import Flask, request, send_file
from flask_cors import CORS
from script.sqlinjectionchecker import sql_injection_checker
from script.xss2 import xss_checker
from script.csrf import csrf_checker
from script.header2 import header_checker
from script.SSLTLS import ssltls_checker
from script.directory_fuzzing import check_directory_fuzzing
import io
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

app = Flask(__name__)
CORS(app, resources={r"/scan": {"origins": "*"}})

# Global variable to store the last scan result
last_scan_result = {}

@app.route("/scan", methods=["POST"])
def scan():
    global last_scan_result
    data = request.get_json()
    print(data)
    if not data or "url" not in data:
        return {"error": "Invalid request. 'url' is required."}, 400

    url = data["url"]
    try:
        sql_check = sql_injection_checker(url)
        xss_check = xss_checker(url)
        csrf_check = csrf_checker(url)
        header_check = header_checker(url)
        ssltls_check = ssltls_checker(url)
        dir_fuzz_check = check_directory_fuzzing(url)

        # Store results for report generation
        last_scan_result = {
            "url": url,
            "sql_injection_check": sql_check,
            "xss_check": xss_check,
            "csrf_check": csrf_check,
            "header_check": header_check,
            "ssltls_check": ssltls_check,
            "directory_fuzzing": dir_fuzz_check
        }

        return last_scan_result, 200
    except Exception as e:
        return {"error": str(e)}, 500

@app.route("/download_report", methods=["GET"])
def download_report():
    global last_scan_result
    if not last_scan_result:
        return {"error": "No scan performed yet."}, 400

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    # Custom Styles
    title_style = styles['Title']
    heading_style = styles['Heading2']
    normal_style = styles['Normal']
    
    # Title
    story.append(Paragraph("Security Scan Report", title_style))
    story.append(Spacer(1, 12))
    story.append(Paragraph(f"Target URL: {last_scan_result.get('url', 'Unknown')}", normal_style))
    story.append(Spacer(1, 24))

    # Summary Table
    story.append(Paragraph("Executive Summary", heading_style))
    story.append(Spacer(1, 12))

    summary_data = [["Vulnerability Type", "Status"]]
    
    # Helper to determine status
    def get_status(is_vuln):
        return "VULNERABLE" if is_vuln else "SECURE"

    # SQLi Status
    sqli = last_scan_result.get("sql_injection_check", {})
    is_sqli_vuln = sqli.get("vulnerable", False)
    summary_data.append(["SQL Injection", get_status(is_sqli_vuln)])

    # XSS Status
    xss = last_scan_result.get("xss_check", {})
    is_xss_vuln = (len(xss.get("reflected", [])) > 0 or 
                   len(xss.get("stored", [])) > 0 or 
                   len(xss.get("dom", [])) > 0)
    summary_data.append(["Cross-Site Scripting (XSS)", get_status(is_xss_vuln)])

    # CSRF Status
    csrf = last_scan_result.get("csrf_check", {})
    is_csrf_vuln = csrf.get("vulnerable", False)
    summary_data.append(["CSRF", get_status(is_csrf_vuln)])

    # Headers Status
    headers = last_scan_result.get("header_check", {})
    is_headers_vuln = any(v is False for v in headers.values()) if headers else False
    summary_data.append(["Security Headers", get_status(is_headers_vuln)])

    # SSL Status
    ssl = last_scan_result.get("ssltls_check", {})
    is_ssl_vuln = not (ssl.get("tls_1_2_supported") or ssl.get("tls_1_3_supported")) or \
                  not ssl.get("certificate_valid") or \
                  not ssl.get("connection_secure")
    summary_data.append(["SSL/TLS Security", get_status(is_ssl_vuln)])

    # Directory Fuzzing Status
    dir_fuzz = last_scan_result.get("directory_fuzzing", {})
    is_dir_vuln = dir_fuzz.get("vulnerable", False)
    summary_data.append(["Directory Fuzzing", get_status(is_dir_vuln)])

    # Create Summary Table
    table = Table(summary_data, colWidths=[300, 100])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
    ]))
    
    # Color code rows based on status
    for i, row in enumerate(summary_data[1:], start=1):
        if row[1] == "VULNERABLE":
            table.setStyle(TableStyle([('TEXTCOLOR', (1, i), (1, i), colors.red)]))
        else:
            table.setStyle(TableStyle([('TEXTCOLOR', (1, i), (1, i), colors.green)]))

    story.append(table)
    story.append(Spacer(1, 24))

    # Detailed Findings
    story.append(Paragraph("Detailed Findings", heading_style))
    story.append(Spacer(1, 12))

    # SQLi Details
    story.append(Paragraph("SQL Injection", styles['Heading3']))
    if is_sqli_vuln:
        story.append(Paragraph("The following SQL injection types were detected:", normal_style))
        if sqli.get("error_based"): story.append(Paragraph("- Error-Based SQLi", normal_style))
        if sqli.get("boolean_based"): story.append(Paragraph("- Boolean-Based SQLi", normal_style))
        if sqli.get("time_based"): story.append(Paragraph("- Time-Based SQLi", normal_style))
        if sqli.get("union_based"): story.append(Paragraph("- Union-Based SQLi", normal_style))
    else:
        story.append(Paragraph("No SQL injection vulnerabilities detected.", normal_style))
    story.append(Spacer(1, 12))

    # XSS Details
    story.append(Paragraph("Cross-Site Scripting (XSS)", styles['Heading3']))
    if is_xss_vuln:
        if xss.get("reflected"):
            story.append(Paragraph("Reflected XSS Payloads:", styles['Heading4']))
            for p in xss["reflected"]:
                story.append(Paragraph(f"- {p}", normal_style))
        if xss.get("stored"):
            story.append(Paragraph("Stored XSS Forms:", styles['Heading4']))
            for f in xss["stored"]:
                story.append(Paragraph(f"- Action: {f.get('form_action')} | Payload: {f.get('payload')}", normal_style))
        if xss.get("dom"):
            story.append(Paragraph("DOM XSS Patterns:", styles['Heading4']))
            for p in xss["dom"]:
                story.append(Paragraph(f"- {p}", normal_style))
    else:
        story.append(Paragraph("No XSS vulnerabilities detected.", normal_style))
    story.append(Spacer(1, 12))

    # CSRF Details
    story.append(Paragraph("CSRF", styles['Heading3']))
    if is_csrf_vuln:
        story.append(Paragraph("The following CSRF issues were detected:", normal_style))
        if csrf.get("get_based"): story.append(Paragraph("- GET-Based CSRF", normal_style))
        if csrf.get("post_based"): story.append(Paragraph("- POST-Based CSRF", normal_style))
        if csrf.get("json_based"): story.append(Paragraph("- JSON-Based CSRF", normal_style))
        if csrf.get("token_missing"): story.append(Paragraph("- Missing Anti-CSRF Token", normal_style))
        if csrf.get("origin_validation_missing"): story.append(Paragraph("- Missing Origin/Referer Validation", normal_style))
    else:
        story.append(Paragraph("No CSRF vulnerabilities detected.", normal_style))
    story.append(Spacer(1, 12))

    # Headers Details
    story.append(Paragraph("Security Headers", styles['Heading3']))
    if headers:
        header_data = [["Header", "Present"]]
        for h, present in headers.items():
            header_data.append([h, "Yes" if present else "No"])
        
        h_table = Table(header_data, colWidths=[200, 100])
        h_table.setStyle(TableStyle([
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
        ]))
        story.append(h_table)
    else:
        story.append(Paragraph("No header data available.", normal_style))
    story.append(Spacer(1, 12))

    # SSL Details
    story.append(Paragraph("SSL/TLS Configuration", styles['Heading3']))
    if ssl:
        story.append(Paragraph(f"TLS 1.2 Supported: {ssl.get('tls_1_2_supported')}", normal_style))
        story.append(Paragraph(f"TLS 1.3 Supported: {ssl.get('tls_1_3_supported')}", normal_style))
        story.append(Paragraph(f"Certificate Valid: {ssl.get('certificate_valid')}", normal_style))
        story.append(Paragraph(f"Connection Secure: {ssl.get('connection_secure')}", normal_style))
    else:
        story.append(Paragraph("No SSL/TLS data available.", normal_style))

    # Directory Fuzzing Details
    story.append(Paragraph("Directory Fuzzing", styles['Heading3']))
    if is_dir_vuln:
        story.append(Paragraph("The following sensitive files/directories were found:", normal_style))
        for path in dir_fuzz.get("found_paths", []):
            story.append(Paragraph(f"- {path}", normal_style))
    else:
        story.append(Paragraph("No sensitive directories found.", normal_style))
    story.append(Spacer(1, 12))

    doc.build(story)
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name="scan_report.pdf", mimetype="application/pdf")

def main():
    app.run(debug=True)

if __name__ == "__main__":
    main()
