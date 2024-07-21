import discord
from discord.ext import commands, tasks
import random
import aiohttp
import os
from datetime import datetime, timedelta
import asyncio

intents = discord.Intents.default()
intents.messages = True
intents.message_content = True
intents.guilds = True
intents.members = True

bot = commands.Bot(command_prefix="!", intents=intents)

# API Key for various services
MALWARE_API_KEY = 'YOUR_MALWARE_API_KEY'
SHODAN_API_KEY = '00paMztMpZxsmjmoUfZ71B0BY9hZBM9R'
BREACH_API_URL = 'https://haveibeenpwned.com/api/v3/breaches'
BREACH_API_KEY = 'YOUR_BREACH_API_KEY'
HAVEIBEENPWNED_API_KEY = 'YOUR_HAVEIBEENPWNED_API_KEY'

# Cache for data breach results to improve performance
breach_cache = {}
breach_cache_time = timedelta(hours=1)

# Event when the bot is ready
@bot.event
async def on_ready():
    print(f'Bot telah masuk sebagai {bot.user}')
    daily_security_tip.start()
    security_reminder.start()

# List of security tips
security_tips = [
    "Gunakan kata sandi yang kuat dan unik untuk setiap akun.",
    "Aktifkan otentikasi dua faktor (2FA) di mana pun memungkinkan.",
    "Jangan mengklik tautan yang mencurigakan atau tidak dikenal.",
    "Selalu perbarui perangkat lunak Anda untuk menutup celah keamanan.",
    "Hindari menggunakan jaringan Wi-Fi publik untuk transaksi sensitif.",
    "Gunakan perangkat lunak antivirus dan pastikan itu selalu diperbarui.",
    "Jangan membagikan informasi pribadi Anda di media sosial.",
    "Pastikan firewall Anda diaktifkan.",
    "Hindari membuka lampiran email dari pengirim yang tidak dikenal.",
    "Gunakan VPN saat mengakses internet melalui jaringan Wi-Fi publik."
]

# Task to send daily security tips
@tasks.loop(hours=24)
async def daily_security_tip():
    channel = bot.get_channel(1264720097964986469)  # Replace with your channel ID
    if channel:
        await channel.send(random.choice(security_tips))

# Task to send periodic security reminders
@tasks.loop(hours=12)
async def security_reminder():
    channel = bot.get_channel(1264719979484545094)  # Replace with your channel ID
    if channel:
        await channel.send("🔐 Ingatlah untuk memeriksa pengaturan keamanan akun Anda secara berkala!")

@bot.command()
async def security_tip(ctx):
    await ctx.send(random.choice(security_tips))

@bot.command()
async def add_security_tip(ctx, *, tip):
    security_tips.append(tip)
    await ctx.send("Tip keamanan baru telah ditambahkan.")

# Event when a message is sent
@bot.event
async def on_message(message):
    if message.author == bot.user:
        return

    if "http" in message.content:
        await message.channel.send(f"@{message.author}, pastikan Anda memeriksa tautan tersebut sebelum mengkliknya.")
        await scan_url(message)

    if message.attachments:
        for attachment in message.attachments:
            await scan_file(attachment)

    await bot.process_commands(message)

# Scan URL for malware
async def scan_url(message):
    url = message.content
    headers = {
        'x-apikey': MALWARE_API_KEY
    }
    async with aiohttp.ClientSession() as session:
        async with session.get(f'https://www.virustotal.com/api/v3/urls/{url}', headers=headers) as response:
            if response.status == 200:
                result = await response.json()
                positives = result['data']['attributes']['last_analysis_stats']['malicious']
                if positives > 0:
                    await message.channel.send(f"⚠️ Tautan tersebut terdeteksi sebagai berbahaya! ⚠️")
                else:
                    await message.channel.send(f"Tautan tersebut aman.")
            else:
                await message.channel.send(f"Tidak dapat memindai tautan saat ini.")

# Scan file for malware
async def scan_file(attachment):
    file_url = attachment.url
    headers = {
        'x-apikey': MALWARE_API_KEY
    }
    async with aiohttp.ClientSession() as session:
        async with session.get(file_url) as response:
            file_content = await response.read()
            files = {'file': file_content}
            async with session.post('https://www.virustotal.com/api/v3/files', headers=headers, data=files) as scan_response:
                if scan_response.status == 200:
                    result = await scan_response.json()
                    positives = result['data']['attributes']['last_analysis_stats']['malicious']
                    if positives > 0:
                        await attachment.channel.send(f"⚠️ File {attachment.filename} terdeteksi sebagai berbahaya! ⚠️")
                    else:
                        await attachment.channel.send(f"File {attachment.filename} aman.")
                else:
                    await attachment.channel.send(f"Tidak dapat memindai file saat ini.")

# Command to check recent activities
@bot.command()
async def recent_activities(ctx):
    log_file = "audit_log.txt"
    if os.path.exists(log_file):
        with open(log_file, "r") as f:
            await ctx.send(f.read())
    else:
        await ctx.send("Tidak ada aktivitas terbaru.")

# Command to get information about recent breaches
@bot.command()
async def recent_breaches(ctx):
    current_time = datetime.now()
    if "breaches" in breach_cache and current_time - breach_cache["time"] < breach_cache_time:
        breaches = breach_cache["breaches"]
    else:
        headers = {
            'hibp-api-key': BREACH_API_KEY
        }
        async with aiohttp.ClientSession() as session:
            async with session.get(BREACH_API_URL, headers=headers) as response:
                if response.status == 200:
                    breaches = await response.json()
                    breach_cache["breaches"] = breaches
                    breach_cache["time"] = current_time
                else:
                    await ctx.send("Tidak dapat mengambil informasi pelanggaran data saat ini.")
                    return

    message = "🔓 Recent Data Breaches:\n"
    for breach in breaches[:5]:  # Get top 5 breaches
        message += f"**{breach['Name']}**: {breach['Description']}\n"
    await ctx.send(message)

# Command to get information from Shodan
@bot.command()
async def shodan_info(ctx, ip):
    async with aiohttp.ClientSession() as session:
        async with session.get(f'https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}') as response:
            if response.status == 200:
                data = await response.json()
                message = f"🔍 Informasi Shodan untuk {ip}:\n"
                message += f"Organization: {data.get('org', 'N/A')}\n"
                message += f"Operating System: {data.get('os', 'N/A')}\n"
                message += f"Open Ports: {', '.join(str(port) for port in data.get('ports', []))}\n"
                await ctx.send(message)
            else:
                await ctx.send("Tidak dapat mengambil informasi dari Shodan saat ini.")

# Command to check if an email has been involved in a data breach
@bot.command()
async def check_email(ctx, email):
    headers = {
        'hibp-api-key': HAVEIBEENPWNED_API_KEY,
        'User-Agent': 'Mozilla/5.0'
    }
    async with aiohttp.ClientSession() as session:
        async with session.get(f'https://haveibeenpwned.com/api/v3/breachedaccount/{email}', headers=headers) as response:
            if response.status == 200:
                breaches = await response.json()
                if breaches:
                    message = f"🔓 Email {email} telah ditemukan dalam pelanggaran data berikut:\n"
                    for breach in breaches:
                        message += f"**{breach['Name']}**: {breach['Description']}\n"
                    await ctx.send(message)
                else:
                    await ctx.send(f"Email {email} aman.")
            else:
                await ctx.send("Tidak dapat memeriksa email saat ini.")

# Event to verify new users
@bot.event
async def on_member_join(member):
    await member.send(f"Selamat datang di server! Mohon verifikasi diri Anda dengan mengirimkan pesan ke admin.")
    log_action(f"User {member.name} has joined the server.")

# Log actions
def log_action(action):
    with open("audit_log.txt", "a") as f:
        f.write(f"{datetime.now()} - {action}\n")

# Example of logging a command
@bot.command()
async def ping(ctx):
    await ctx.send('Pong!')
    log_action("ping command used")

# Run the bot
bot.run('MTI2NDcxODE4MzM5OTY4NjIzNg.GtTL8W._DrAS44Ls7CKmSEJqcW9wr7Qr3Csl6-GcdPavw')
