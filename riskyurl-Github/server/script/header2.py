import requests
import time
from urllib.parse import urlparse
from collections import OrderedDict

# Security headers with importance ratings (1-3) and vulnerabilities
SECURITY_HEADERS = OrderedDict([
    ("Content-Security-Policy", {
        "importance": 3,
        "description": "Prevents XSS by declaring allowed dynamic resources",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
        "vulnerability": "Cross-site Scripting (XSS)"
    }),
    ("Strict-Transport-Security", {
        "importance": 3,
        "description": "Enforces HTTPS and protects against downgrade attacks",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
        "vulnerability": "SSL Stripping / Downgrade attacks"
    }),
    ("X-Frame-Options", {
        "importance": 2,
        "description": "Protects against clickjacking attacks",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
        "vulnerability": "Clickjacking"
    }),
    ("X-Content-Type-Options", {
        "importance": 2,
        "description": "Prevents MIME-sniffing and content-type attacks",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
        "vulnerability": "MIME Sniffing / Content-Type Confusion"
    }),
    ("Referrer-Policy", {
        "importance": 1,
        "description": "Controls referrer information sent with requests",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
        "vulnerability": "Information Leakage"
    }),
    ("Permissions-Policy", {
        "importance": 2,
        "description": "Restricts browser features (camera, mic, etc.)",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
        "vulnerability": "Excessive Browser Feature Access"
    }),
    ("Cross-Origin-Embedder-Policy", {
        "importance": 2,
        "description": "Prevents insecure third-party content embedding",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy",
        "vulnerability": "Spectre-like side-channel attacks"
    }),
    ("Cross-Origin-Opener-Policy", {
        "importance": 2,
        "description": "Isolates browsing context against Spectre-like attacks",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy",
        "vulnerability": "Cross-origin attack surface exposure"
    }),
    ("Cross-Origin-Resource-Policy", {
        "importance": 1,
        "description": "Controls cross-origin resource sharing",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy",
        "vulnerability": "Unauthorized Cross-Origin Resource Access"
    })
])

def validate_url(url):
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    try:
        result = urlparse(url)
        if not all([result.scheme, result.netloc]):
            raise ValueError("Invalid URL structure")
        return url
    except:
        raise ValueError("Invalid URL format")

def show_progress(current, total, message=""):
    bar_length = 30
    progress = float(current) / total
    block = int(round(bar_length * progress))
    progress_percent = round(progress * 100, 1)
    progress_bar = "[" + "=" * block + " " * (bar_length - block) + "]"
    print(f"\r{progress_bar} {progress_percent}% {message}", end="")
    if current == total:
        print()

def scan_headers(url):
    try:
        print(f"\n🔍 Scanning {url} for security headers...\n")
        show_progress(0, 3, "Testing connection...")

        try:
            response = requests.get(
                url,
                timeout=10,
                allow_redirects=True,
                headers={'User-Agent': 'SecurityHeadersScanner/1.0'}
            )
            response.raise_for_status()
            show_progress(1, 3, "Connection successful")
        except requests.RequestException as e:
            show_progress(3, 3, "Failed!")
            print(f"\n[X] Connection failed: {str(e)}")
            return

        show_progress(2, 3, "Collecting headers...")
        headers = {k.lower(): v for k, v in response.headers.items()}
        show_progress(3, 3, "Headers collected")
        time.sleep(0.5)

        print("\n\n=== 🛡️ Security Header Analysis ===")
        print("Importance: 🔴 Critical (3) | 🟠 Important (2) | 🔵 Recommended (1)\n")

        missing_count = 0
        present_count = 0

        for header, info in SECURITY_HEADERS.items():
            header_lower = header.lower()
            importance_icons = {3: "🔴", 2: "🟠", 1: "🔵"}

            if header_lower in headers:
                present_count += 1
                print(f"{importance_icons[info['importance']]} {header}: PRESENT ✅")
                print(f"   Value: {headers[header_lower]}")
                print(f"   Purpose: {info['description']}")
                print(f"   Reference: {info['reference']}\n")
            else:
                missing_count += 1
                print(f"⚫ {header}: MISSING ❌")
                print(f"   Importance: {'★' * info['importance']}")
                print(f"   Risk: {info['description']}")
                print(f"   Vulnerable to: {info['vulnerability']}")
                print(f"   Reference: {info['reference']}\n")

        print("\n=== 📊 Scan Summary ===")
        print(f"Total security headers checked: {len(SECURITY_HEADERS)}")
        print(f"Headers present: {present_count} ✅")
        print(f"Headers missing: {missing_count} ❌")

        security_score = int((present_count / len(SECURITY_HEADERS)) * 100)
        print(f"\nSecurity Header Score: {security_score}%")

        if security_score >= 80:
            print("🟢 Excellent security headers implementation! Hacker tears incoming.")
        elif security_score >= 50:
            print("🟠 Moderate security — add the missing headers before someone adds your server to their resume.")
        else:
            print("🔴 Poor security — your site’s basically a CTF challenge right now.")

        print("\n💡 Recommendation: Implement all missing headers, starting with the critical ones (marked 🔴).")

    except Exception as e:
        print(f"\n[!] An unexpected error occurred: {str(e)}")

def header_checker(url: str):
    result = {"status": "success", "data": []}
    try:
        url = url.strip()
        validated_url = validate_url(url)
        result["data"].append(f"Validated URL: {validated_url}")
    except ValueError as e:
        result["status"] = "error"
        result["data"].append(f"Invalid URL: {str(e)}")
        return result

    try:
        scan_headers(validated_url)
        result["data"].append("Scan completed successfully.")
    except Exception as e:
        result["status"] = "error"
        result["data"].append(f"An error occurred during scanning: {str(e)}")
    
    return result
