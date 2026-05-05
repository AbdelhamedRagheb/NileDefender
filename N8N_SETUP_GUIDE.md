# 🚀 NileDefender AI IDOR Agent — Setup Guide

## Prerequisites

**Linux:**
```bash
sudo apt install docker.io docker-compose -y
sudo systemctl start docker
```

**Windows / Mac:**
- Install [Docker Desktop](https://www.docker.com/products/docker-desktop/) and start it

**Also required:**
- OpenAI API Key (explained in Step 4)

---

## Step 1: Add your API Keys

Open `config.ini` and fill in your **Groq API Key** (for AI report generation):

```ini
groq = YOUR_GROQ_API_KEY_HERE
```

> The `N8N_WEBHOOK_URL` is already set correctly — don't change it.

---

## Step 2: Start the project

```bash
docker compose up -d --build
```

Wait 2–3 minutes, then open:
- **Dashboard:** http://localhost:5000
- **n8n:** http://localhost:5677

---

## Step 3: Create an n8n account

When you first open http://localhost:5677 you'll see a registration page.

1. Enter any **First Name / Last Name**
2. Enter any **Email** (doesn't have to be real)
3. Choose a **Password**
4. Click **Get started**
5. On the next page click **Skip** or **Get started for free**

---

## Step 4: Import the Workflow

1. From the left sidebar click **Workflows**
2. Click **Add Workflow** or the **+** button
3. Click **...** (three dots) → **Import from file**
4. Select the file **`agent_idor_workflow.json`** (included in the project)
5. Press **Save** (Ctrl+S)

---

## Step 5: Add your OpenAI API Key

### a) Get your API Key
- Go to https://platform.openai.com/api-keys
- Click **Create new secret key**
- Copy the key (starts with `sk-...`)

### b) Add the key inside the Workflow
1. Open the imported Workflow
2. Click on the **AI Agent** node
3. Under **Chat Model** click **Create new credential**
4. Paste the API Key in the **API Key** field
5. Click **Save**

---

## Step 6: Activate the Workflow

Click the **Inactive** toggle (top right) to switch it to **Active** ✅

---

## ✅ You're ready!

Now run a **Full Scan** from the Dashboard on any target:

- Static scanners run first (HTML Injection, XSS, SQLi...)
- The AI Agent automatically activates and tests for IDOR
- When finished, the scan status changes to **Completed** automatically

---

## 🔧 Troubleshooting

```bash
# View NileDefender logs
docker logs niledefender -f

# View n8n logs
docker logs n8n -f

# Rebuild after code changes
docker compose up -d --build
```

---

## ⚠️ Important

- The Workflow **must be Active** in n8n before running any scan
- The `config.ini` file is excluded from Git — never commit your real API keys
- If a scan stays **Running** for more than 10 minutes, it will auto-complete (safety timeout)
