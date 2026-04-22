<p align="center">
  <img src="Documents/banner.png" alt="NileDefender" width="600"/>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.13-blue?logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/flask-3.0-green?logo=flask&logoColor=white"/>
  <img src="https://img.shields.io/badge/react-19-61DAFB?logo=react&logoColor=white"/>
  <img src="https://img.shields.io/badge/docker-ready-blue?logo=docker&logoColor=white"/>
  <img src="https://img.shields.io/badge/selenium-4.x-orange?logo=selenium&logoColor=white"/>
</p>

<p align="center"><b>Automated recon & vulnerability scanning from a real-time web dashboard.</b></p>

---

## What is NileDefender?

NileDefender is a web-based security tool that automates the full penetration testing pipeline:

**Subdomain discovery → Endpoint crawling → Vulnerability scanning → AI Report Generation**

It works on both **remote domains** (`example.com`) and **local targets** (`http://localhost/bWAPP/`), with a modern dark-themed dashboard that shows results in real-time via WebSocket.

---

## Features

| Feature | Description |
|---|---|
| 🔍 **Subdomain Enumeration** | Passive (CT logs, APIs) + Active (DNS brute-force) |
| 🕷️ **URL Crawling** | Discover endpoints and extract GET/POST parameters |
| 🖥️ **Local App Crawling** | Selenium-based crawler for localhost apps with auto-login |
| 💉 **SQL Injection Scanner** | Powered by sqlmap |
| 📂 **Path Traversal Scanner** | Custom payload-based LFI/directory traversal detection |
| 📝 **HTML Injection Scanner** | Payload reflection analysis |
| ⚡ **Real-time Updates** | WebSocket (Socket.IO) for live scan progress |
| 🤖 **AI Report Generation** | Groq LLM generates professional PDF security reports |
| 📊 **Data Export** | JSON/CSV export of all scan data |
| 🎨 **React Dashboard** | Modern dark navy + teal themed SPA |

---

## Tested On

NileDefender has been tested against the following vulnerable web applications:

| Target | Type | Description |
|---|---|---|
| **[bWAPP](http://www.yoursite.com/bWAPP/)** | Local (Docker/VM) | Buggy Web Application — 100+ vulnerabilities |
| **[DVWA](https://github.com/digininja/DVWA)** | Local (Docker/VM) | Damn Vulnerable Web Application — multiple security levels |
| **Remote Domains** | Remote | Any public domain for subdomain enumeration & scanning |

---

## Quick Start

### Option 1: Docker (Recommended)

```bash
git clone https://github.com/AbdelhamedRagheb/NileDefender.git
cd NileDefender
sudo docker compose up -d --build
```

Open → http://localhost:5000

### Option 2: Virtual Environment

```bash
git clone https://github.com/AbdelhamedRagheb/NileDefender.git
cd NileDefender

# Backend
python3.13 -m venv my-env
source my-env/bin/activate
pip install -r requirements.txt

# Frontend
cd frontend
npm install
npm run build
cd ..

# Run
python server.py
```

Open → http://localhost:5000

> 📖 See [install.txt](install.txt) for full installation details.

---

## Architecture

```
React SPA (Vite) → Flask REST API + Socket.IO → Scanner Modules → SQLite DB
```

| Layer | Tech |
|---|---|
| **Frontend** | React 19, Vite 8, Socket.IO Client |
| **Backend** | Flask, Flask-SocketIO, SQLAlchemy |
| **Scanners** | sqlmap, custom Path Traversal & HTMLi modules |
| **Recon** | Subdomain enum, URL crawler, Selenium local crawler |
| **AI Reports** | Groq LLM (llama-3.3-70b) → WeasyPrint PDF |
| **Database** | SQLite |

---

## Screenshots

<p align="center">
  <img src="Documents/Icon.png" alt="NileDefender Icon" width="150"/>
</p>

---

## License

This project is for educational and authorized security testing purposes only.

