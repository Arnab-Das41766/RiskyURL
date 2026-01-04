# 🛡️ RiskyURL – Web Security Misconfiguration Scanner

## 📌 Overview

**RiskyURL** is a cybersecurity project designed to help **developers identify common web application security mistakes** and insecure configurations early in the development process.

It performs automated checks for frequently exploited vulnerabilities such as SQL injection, XSS, CSRF, insecure headers, SSL/TLS issues, and exposed directories, and generates a **downloadable security report** for review.

---

## ✨ Features

### 🔍 Vulnerability Checks
- Error-based SQL Injection  
- Boolean-based SQL Injection  
- Time-based SQL Injection  
- Union-based SQL Injection  
- Reflected XSS  
- Stored XSS  
- DOM-based XSS  
- CSRF checks  

### 🛠️ Security Analysis
- HTTP security header analysis  
- SSL/TLS configuration validation  
- Directory fuzzing for exposed endpoints  

### 📄 Reporting
- Automatically generated scan results  
- **Downloadable security report (PDF)**  
- Clear overview of detected issues for developers  

---

## 📂 Project Structure

```
riskyurl/
├── client/
│   ├── index.html
│   ├── script.js
│   └── styles.css
├── server/
│   ├── main.py
│   ├── script/
│   ├── reports/
│   ├── pyproject.toml
│   └── .python-version
├── .gitignore
└── README.md
```

> ⚠️ Generated files such as virtual environments, build artifacts, videos, and reports are intentionally excluded from the repository.

---

## 🚀 How It Works

RiskyURL sends controlled test requests to a target URL and analyzes responses for indicators of insecure behavior or misconfiguration.

Once the scan is complete:
1. Detected issues are categorized
2. Results are compiled into a structured format
3. A **downloadable report** is generated for auditing and remediation purposes

---

## 🧑‍💻 Running the Project Locally

### Backend
```bash
cd server
python main.py
```

### Frontend
Open `client/index.html` in a browser or serve it using any static server.

---

## 🎯 Use Cases

- Catch **basic security errors** during development  
- Learn how common web vulnerabilities are identified  
- Demonstrate secure coding awareness  
- Educational and portfolio-ready cybersecurity project  

---

## ⚠️ Ethical Use & Disclaimer

> **DISCLAIMER:**  
> This project is intended strictly for **educational and defensive security testing**.  
> Only test applications you own or have explicit permission to test.  
> The author is not responsible for misuse or illegal use of this tool.

---

## 👤 Author

**Arnab Das**  
**Koushal Singh** 
Cybersecurity Enthusiast | Web Security & Red Team Research  

> *Secure code is not optional — it’s essential.*
