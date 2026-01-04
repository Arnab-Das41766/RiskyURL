# import socket
# import ssl
# import OpenSSL
# import idna
# from datetime import datetime
# from urllib.parse import urlparse
# import re
# import time
# import sys


# # Beautify progress bar (yes, we're dramatic here)
# def show_progress(message):
#     print(f"🔄 {message}...")
#     time.sleep(0.8)


# # Fix users who type 'https://https://something'
# def extract_hostname(url):
#     url = url.strip()
#     url = url.replace("https://https://", "https://").replace(
#         "http://http://", "http://"
#     )
#     url = url.replace("https://http://", "http://").replace(
#         "http://https://", "https://"
#     )

#     if not url.startswith("http://") and not url.startswith("https://"):
#         url = "https://" + url

#     parsed = urlparse(url)
#     return parsed.hostname


# # Validate if it looks like a domain and not a dragon
# def is_valid_hostname(hostname):
#     if not hostname:
#         return False
#     return re.match(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z]{2,})+$", hostname)


# # The grand scanner
# def ssl_tls_scan(host):
#     show_progress("Sanitizing hostname")
#     hostname = idna.encode(host).decode()

#     port = 443
#     result = {
#         "host": host,
#         "tls_versions": [],
#         "vulnerabilities": [],
#         "cert_issues": [],
#     }

#     context = ssl.create_default_context()

#     try:
#         show_progress("Establishing connection")
#         try:
#             with socket.create_connection((hostname, port), timeout=5) as sock:
#                 with context.wrap_socket(sock, server_hostname=hostname) as ssock:
#                     cert = ssock.getpeercert()
#                     cipher = ssock.cipher()
#                     protocol = ssock.version()
#                     result["tls_versions"].append(protocol)

#                     show_progress("Checking TLS version")
#                     if protocol not in ["TLSv1.2", "TLSv1.3"]:
#                         result["vulnerabilities"].append(
#                             f"⚠️ Weak or outdated TLS version in use: {protocol}"
#                         )

#                     show_progress("Inspecting certificate expiry")
#                     notAfter = datetime.strptime(
#                         cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
#                     )
#                     if notAfter < datetime.utcnow():
#                         result["cert_issues"].append("❌ Certificate has expired.")

#                     show_progress("Validating common name")
#                     common_names = [
#                         entry[0][1]
#                         for entry in cert.get("subject", [])
#                         if entry[0][0] == "commonName"
#                     ]
#                     if hostname not in common_names and not any(
#                         hostname.endswith(cn.lstrip("*.")) for cn in common_names
#                     ):
#                         result["cert_issues"].append(
#                             f"❌ Certificate common name mismatch. Expected: {hostname}, Found: {common_names}"
#                         )
#         except socket.timeout:
#             result["vulnerabilities"].append("❌ Socket Error: Connection timed out.")
#         except ssl.SSLError as e:
#             result["vulnerabilities"].append(f"❌ SSL Error: {e}")
#         except Exception as e:
#             result["vulnerabilities"].append(f"❌ General Error: {e}")

#     except ssl.SSLError as e:
#         result["vulnerabilities"].append(f"❌ SSL Error: {e}")
#     except socket.error as e:
#         result["vulnerabilities"].append(f"❌ Socket Error: {e}")
#     except Exception as e:
#         result["vulnerabilities"].append(f"❌ General Error: {e}")

#     return result


# # Beautify output
# def print_report(scan):
#     print("\n" + "=" * 50)
#     print(f"🔍 Final Report for: {scan['host']}")
#     print("=" * 50)

#     print(f"\n🧾 Supported TLS Versions: {', '.join(scan['tls_versions']) or 'None'}")

#     if scan["cert_issues"]:
#         print("\n📛 Certificate Issues Found:")
#         for issue in scan["cert_issues"]:
#             print("  -", issue)
#     else:
#         print("\n✅ No certificate issues detected.")

#     if scan["vulnerabilities"]:
#         print("\n🚨 SSL/TLS Vulnerabilities Detected:")
#         for vuln in scan["vulnerabilities"]:
#             print("  -", vuln)
#     else:
#         print("\n✅ No SSL/TLS misconfigurations detected.")

#     print("\n🔚 Scan complete.\n")


# # ======================= MAIN =======================
# def ssltls_checker(url: str):
#     host = extract_hostname(url)

#     if not is_valid_hostname(host):
#         return {
#             "error": "Invalid hostname. Please enter a proper domain like example.com"
#         }

#     scan_result = ssl_tls_scan(host)
#     print_report(scan_result)
#     return {
#         "host": scan_result["host"],
#         "tls_versions": scan_result["tls_versions"],
#         "cert_issues": scan_result["cert_issues"],
#         "vulnerabilities": scan_result["vulnerabilities"],
#     }








import socket
import ssl
import OpenSSL
import idna
from datetime import datetime
from urllib.parse import urlparse
import re
import time


def show_progress(message):
    print(f"🔄 {message}...")
    time.sleep(0.8)


def extract_hostname(url):
    url = url.strip()
    url = url.replace("https://https://", "https://").replace("http://http://", "http://")
    url = url.replace("https://http://", "http://").replace("http://https://", "https://")

    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    parsed = urlparse(url)
    return parsed.hostname


def is_valid_hostname(hostname):
    if not hostname:
        return False
    return re.match(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z]{2,})+$", hostname)


def ssl_tls_scan(host):
    show_progress("Sanitizing hostname")
    hostname = idna.encode(host).decode()

    port = 443
    result = {
        "host": host,
        "tls_versions": [],
        "vulnerabilities": [],
        "cert_issues": [],
    }

    context = ssl.create_default_context()

    try:
        show_progress("Establishing connection")
        try:
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    protocol = ssock.version()
                    result["tls_versions"].append(protocol)

                    show_progress("Checking TLS version")
                    if protocol not in ["TLSv1.2", "TLSv1.3"]:
                        result["vulnerabilities"].append(f"⚠️ Weak or outdated TLS version in use: {protocol}")

                    show_progress("Inspecting certificate expiry")
                    notAfter = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                    if notAfter < datetime.utcnow():
                        result["cert_issues"].append("❌ Certificate has expired.")

                    show_progress("Validating common name")
                    common_names = [
                        entry[0][1]
                        for entry in cert.get("subject", [])
                        if entry[0][0] == "commonName"
                    ]
                    if hostname not in common_names and not any(
                        hostname.endswith(cn.lstrip("*.")) for cn in common_names
                    ):
                        result["cert_issues"].append(
                            f"❌ Certificate common name mismatch. Expected: {hostname}, Found: {common_names}"
                        )
        except socket.timeout:
            result["vulnerabilities"].append("❌ Socket Error: Connection timed out.")
        except ssl.SSLError as e:
            result["vulnerabilities"].append(f"❌ SSL Error: {e}")
        except Exception as e:
            result["vulnerabilities"].append(f"❌ General Error: {e}")

    except ssl.SSLError as e:
        result["vulnerabilities"].append(f"❌ SSL Error: {e}")
    except socket.error as e:
        result["vulnerabilities"].append(f"❌ Socket Error: {e}")
    except Exception as e:
        result["vulnerabilities"].append(f"❌ General Error: {e}")

    return result


def print_report(scan):
    print("\n" + "=" * 50)
    print(f"🔍 Final Report for: {scan['host']}")
    print("=" * 50)

    print(f"\n🧾 Supported TLS Versions: {', '.join(scan['tls_versions']) or 'None'}")

    if scan["cert_issues"]:
        print("\n📛 Certificate Issues Found:")
        for issue in scan["cert_issues"]:
            print("  -", issue)
    else:
        print("\n✅ No certificate issues detected.")

    if scan["vulnerabilities"]:
        print("\n🚨 SSL/TLS Vulnerabilities Detected:")
        for vuln in scan["vulnerabilities"]:
            print("  -", vuln)
    else:
        print("\n✅ No SSL/TLS misconfigurations detected.")

    print("\n🔚 Scan complete.\n")


# ======================= MAIN =======================
def ssltls_checker(url: str):
    host = extract_hostname(url)

    if not is_valid_hostname(host):
        return {
            "error": "Invalid hostname. Please enter a proper domain like example.com"
        }

    scan_result = ssl_tls_scan(host)
    print_report(scan_result)

    # Match frontend expectation
    result_for_frontend = {
        "tls_1_2_supported": "TLSv1.2" in scan_result["tls_versions"],
        "tls_1_3_supported": "TLSv1.3" in scan_result["tls_versions"],
        "certificate_valid": len(scan_result["cert_issues"]) == 0,
        "connection_secure": len(scan_result["vulnerabilities"]) == 0,
    }

    print("[✅] ssltls_check summary for frontend:", result_for_frontend)

    return {
        "host": scan_result["host"],
        "tls_versions": scan_result["tls_versions"],
        "cert_issues": scan_result["cert_issues"],
        "vulnerabilities": scan_result["vulnerabilities"],
        "ssltls_check": result_for_frontend,
    }
