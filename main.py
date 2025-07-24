import os
import sys
import json
import signal
import logging
from datetime import datetime, timedelta

import discord
from discord.ext import commands, tasks
import aiohttp
from tenacity import retry, wait_exponential, stop_after_attempt, retry_if_exception_type
try:
    import openai
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False

# Config validation
DISCORD_TOKEN = os.getenv('DISCORD_TOKEN')
CHANNEL_ID = os.getenv('DISCORD_CHANNEL_ID')
ALERT_CHANNEL_ID = os.getenv('ALERT_CHANNEL_ID')  # optional: channel to send alerts
CVE_API_URL = os.getenv('CVE_API_URL', 'https://services.nvd.nist.gov/rest/json/cves/2.0')
OPENAI_API_KEY = os.getenv('OPEN_AI_API_KEY')

if not DISCORD_TOKEN or not CHANNEL_ID:
    logging.error("DISCORD_TOKEN and DISCORD_CHANNEL_ID must be set.")
    sys.exit(1)

channel_id = int(CHANNEL_ID)
alert_channel_id = int(ALERT_CHANNEL_ID) if ALERT_CHANNEL_ID else None

if OPENAI_API_KEY and OPENAI_AVAILABLE:
    openai.api_key = OPENAI_API_KEY

# Logging setup
logger = logging.getLogger('cve_bot')
logger.setLevel(logging.INFO)
handler = logging.FileHandler('discord.log', encoding='utf-8')
formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

# State
posted_cves = set()
POSTED_FILE = 'posted_cves.json'
last_run_time: datetime | None = None
last_error: str | None = None
error_count = 0
posted_count_last_run = 0

# Discord bot setup
intents = discord.Intents.default()
bot = commands.Bot(command_prefix='!', intents=intents)

# HTTP session reuse
session: aiohttp.ClientSession | None = None

def load_posted_cves() -> set[str]:
    try:
        with open(POSTED_FILE, 'r') as f:
            return set(json.load(f))
    except Exception:
        return set()

def save_posted_cves(cves: set[str]) -> None:
    with open(POSTED_FILE, 'w') as f:
        json.dump(list(cves), f)

@retry(wait=wait_exponential(multiplier=1, min=4, max=60),
       stop=stop_after_attempt(5),
       retry=retry_if_exception_type(aiohttp.ClientError),
       reraise=True)
async def fetch_json(url: str, params: dict) -> dict:
    assert session is not None
    async with session.get(url, params=params, timeout=10) as resp:
        resp.raise_for_status()
        return await resp.json()

async def fetch_and_post_cves() -> int:
    global last_run_time, last_error, error_count, posted_count_last_run
    start = datetime.utcnow()
    params = {
        'lastModStartDate': (start - timedelta(minutes=5)).strftime('%Y-%m-%dT%H:%M:%S.000Z'),
        'lastModEndDate': start.strftime('%Y-%m-%dT%H:%M:%S.000Z'),
        'resultsPerPage': 100
    }
    try:
        data = await fetch_json(CVE_API_URL, params)
        vulnerabilities = data.get('vulnerabilities', [])
        new = [v for v in vulnerabilities if (cid := v.get('cve', {}).get('id')) and cid not in posted_cves]
        channel = bot.get_channel(channel_id)
        if channel is None:
            raise RuntimeError(f"Channel {channel_id} not found")
        for v in new:
            cve = v['cve']
            cid = cve['id']
            descs = cve.get('descriptions', [])
            description = next((d['value'] for d in descs if d.get('lang') == 'en'), '')
            # Optional LLM summarization
            if OPENAI_API_KEY and OPENAI_AVAILABLE and description:
                try:
                    resp = await openai.ChatCompletion.acreate(
                        model='gpt-3.5-turbo',
                        messages=[
                            {'role':'system','content':'Summarize in 2-3 sentences.'},
                            {'role':'user','content':description}
                        ],
                        max_tokens=150
                    )
                    summary = resp.choices[0].message.content.strip()
                except Exception as e:
                    logger.error(f"LLM summarization failed: {e}")
                    summary = (description[:300] + '…') if len(description) > 300 else description
            else:
                summary = (description[:300] + '…') if len(description) > 300 else description
            # CVSS severity
            metrics = cve.get('metrics', {})
            cvss_score = None
            for m in metrics.get('cvssMetricV31', []):
                cvss_score = m.get('cvssData', {}).get('baseScore')
                break
            # Embed coloring
            if cvss_score is not None:
                if cvss_score >= 9:
                    color = discord.Color.red()
                elif cvss_score >= 7:
                    color = discord.Color.orange()
                elif cvss_score >= 4:
                    color = discord.Color.gold()
                else:
                    color = discord.Color.green()
            else:
                color = discord.Color.default()
            embed = discord.Embed(
                title=cid,
                url=f"https://nvd.nist.gov/vuln/detail/{cid}",
                description=summary,
                color=color
            )
            if cvss_score is not None:
                embed.add_field(name='CVSS v3', value=str(cvss_score))
            await channel.send(embed=embed)
            posted_cves.add(cid)
            logger.info(f"Posted CVE {cid}")
        save_posted_cves(posted_cves)
        last_run_time = datetime.utcnow()
        posted_count_last_run = len(new)
        return len(new)
    except Exception as e:
        error_count += 1
        last_error = str(e)
        logger.error(f"Error in fetch_and_post_cves: {e}")
        if alert_channel_id:
            alert_ch = bot.get_channel(alert_channel_id)
            if alert_ch:
                await alert_ch.send(f":warning: Error fetching CVEs: {e}")
        return 0

@tasks.loop(minutes=1)
async def cve_loop() -> None:
    await fetch_and_post_cves()

@bot.command(name='cve_status')
async def cve_status(ctx: commands.Context) -> None:
    """Show last run stats and errors."""
    msg = f"Last run: {last_run_time or 'never'} UTC\n"
    msg += f"Posted in last run: {posted_count_last_run}\n"
    msg += f"Total errors: {error_count}\n"
    if last_error:
        msg += f"Last error: {last_error}"
    await ctx.send(msg)

@bot.command(name='cve_fetch')
async def cve_fetch(ctx: commands.Context) -> None:
    """Manually trigger CVE fetching."""
    count = await fetch_and_post_cves()
    await ctx.send(f"Fetched and posted {count} new CVE(s).")

@bot.event
async def on_ready() -> None:
    global session, posted_cves
    session = aiohttp.ClientSession()
    posted_cves = load_posted_cves()
    logger.info(f"Bot ready, loaded {len(posted_cves)} posted CVEs.")
    print(f"Logged in as {bot.user}")
    if not cve_loop.is_running():
        cve_loop.start()
        print("CVE loop has started")
        
async def shutdown() -> None:
    logger.info("Shutting down...")
    cve_loop.cancel()
    if session:
        await session.close()
    save_posted_cves(posted_cves)
    await bot.close()

def _signal_handler(sig, frame) -> None:
    import asyncio
    asyncio.create_task(shutdown())

signal.signal(signal.SIGINT, _signal_handler)
signal.signal(signal.SIGTERM, _signal_handler)

bot.run(DISCORD_TOKEN, log_handler=handler, log_level=logging.DEBUG)


