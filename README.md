# 🛡️ CVE Discord Bot

This is a Python-powered Discord bot that monitors the National Vulnerability Database (NVD) for newly published CVEs (Common Vulnerabilities and Exposures) and posts alerts in a Discord channel. Optionally, it can also summarize CVEs using the OpenAI API.

---

## 📦 Features

- 🔔 Real-time CVE alerts posted in Discord
- 💬 Optional OpenAI-powered CVE summaries
- 🌐 Uses the NVD API to stay up to date
- 🧠 Built with Python, `discord.py`, `requests`, and `openai`

---

## ⚙️ Setup Instructions

### 1. Clone this repo:
```bash
1.
git clone https://github.com/JJ-890/CVE_Bot.git
2.
cd CVE_Bot
3.
pip install -r requirements.txt
4.
DISCORD_TOKEN=your_discord_token
OPENAI_API_KEY=your_openai_api_key
5. Run the bot
python main.py
