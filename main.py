import asyncio
import re
import os
from datetime import datetime, timedelta
from typing import Dict, Any, Optional

import asyncssh
from astrbot.api.event import filter, AstrMessageEvent
from astrbot.api.star import Star, register, Context
from astrbot.api import logger

DEFAULT_WHITELIST = [
    "ls", "cat", "head", "tail", "grep", "find", "wc", "sort", "uniq",
    "df", "du", "free", "top", "htop", "ps", "uptime", "uname", "whoami",
    "id", "hostname", "date", "cal", "echo", "pwd", "env", "printenv",
    "file", "stat", "which", "whereis", "type", "lsblk", "lscpu", "lsof",
    "netstat", "ss", "ip", "ifconfig", "ping", "traceroute", "dig", "nslookup",
    "journalctl", "dmesg", "systemctl status", "service --status-all",
    "docker ps", "docker images", "docker logs", "docker stats", "docker inspect",
    "git status", "git log", "git diff", "git branch", "git remote",
    "pip list", "pip show", "npm list", "node -v", "python --version",
    "crontab -l", "last", "w", "who", "history",
    "nginx -t", "nginx -T", "curl", "wget",
    "tar", "zip", "unzip", "gzip", "gunzip", "cp", "mv", "mkdir", "touch",
    "apt list", "yum list", "dpkg -l", "rpm -qa",
    "sed", "awk", "cut", "tr", "tee", "xargs", "less", "more", "diff",
    "screen -ls", "tmux ls", "pm2 list", "pm2 logs", "supervisorctl status",
    "cd", "source", "export", "alias", "chmod", "chown",
    "systemctl start", "systemctl stop", "systemctl restart", "systemctl enable", "systemctl disable",
    "nano", "vim", "vi",
    "pip install", "npm install", "apt install", "apt update", "apt upgrade",
    "yum install", "yum update",
    "git pull", "git push", "git clone", "git checkout", "git merge", "git add", "git commit",
]

BLOCKED_PATTERNS = [
    r"rm\s+.*-r", r"rm\s+.*-f", r"rm\s+-\w*r",
    r"mkfs", r"dd\s+if=", r"shutdown", r"reboot", r"init\s+0", r"poweroff",
    r":\(\)\s*\{\s*:\s*\|\s*:\s*\&\s*\}\s*;",
    r"wget\s+.*\|.*sh", r"curl\s+.*\|.*sh",
    r">\s*/dev/sd[a-z]", r">\s*/dev/nvme",
    r"chmod\s+-R\s+777",
    r"kill\s+-9\s+-1",
    r"useradd", r"usermod", r"groupadd",
    r"iptables", r"ufw",
    r"rm\s+-", r"rm\s+/",
    r"python\d*\s+-[ci]\b", r"perl\s+-e", r"ruby\s+-e",
    r"php\s+-r\b", r"node\s+(-e|-p)\b",
    r"nc\s+-[lp]", r"ncat", r"socat",
    r"crontab\s+-[re]",
    r"passwd",
    r"visudo", r"sudoers",
    r"eval\s+", r"\bexec\s+",
]

SENSITIVE_PATTERNS = [
    (re.compile(r"(password|passwd|pwd)\s*[=:]\s*\S+", re.IGNORECASE), r"\1=***"),
    (re.compile(r"(token|api_key|apikey|secret|access_key|secret_key)\s*[=:]\s*\S+", re.IGNORECASE), r"\1=***"),
    (re.compile(r"(Authorization|Bearer)\s+\S+", re.IGNORECASE), r"\1 ***"),
    (re.compile(r"-----BEGIN\s+\w+\s+(?:PRIVATE\s+)?KEY-----[\s\S]*?-----END\s+\w+\s+(?:PRIVATE\s+)?KEY-----"), "***PRIVATE_KEY***"),
    (re.compile(r"(?<!\w)[A-Za-z0-9+/]{40,}={0,2}(?!\w)"), "***BASE64***"),
    (re.compile(r"mysql://\S+|postgres://\S+|redis://\S+|mongodb://\S+", re.IGNORECASE), "***DB_URI***"),
]


def _sanitize(text: str) -> str:
    for pattern, replacement in SENSITIVE_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def _split_command(command: str) -> list:
    """按 shell 分隔符拆分命令为子命令列表，跳过引号内的内容喵

    分隔符包括: ; && || | 换行，以及 # 开头的注释喵
    """
    parts = []
    current = []
    quote = None  # 当前未闭合的引号类型喵
    i = 0
    while i < len(command):
        ch = command[i]
        if quote:
            if ch == quote:
                quote = None
            current.append(ch)
        elif ch in ('"', "'"):
            quote = ch
            current.append(ch)
        elif ch == '#':
            # 注释开始，后面的内容直接丢弃喵
            break
        elif ch in (';', '|', '&', '\n'):
            # && 和 || 是双字符分隔符，跳过第二个字符喵
            if ch in ('&', '|') and i + 1 < len(command) and command[i + 1] == ch:
                i += 1
            parts.append(''.join(current))
            current = []
        else:
            current.append(ch)
        i += 1
    parts.append(''.join(current))
    return [p.strip() for p in parts if p.strip()]


def _get_known_hosts_path(config: dict) -> str:
    path = config.get("known_hosts_path", "")
    if not path:
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "known_hosts")
    return path


def _ensure_known_hosts_file(path: str):
    if not os.path.exists(path):
        # dirname 对裸文件名会返回空串，需要兜底跳过建目录喵
        dir_name = os.path.dirname(path)
        if dir_name:
            os.makedirs(dir_name, exist_ok=True)
        with open(path, 'w') as f:
            pass
        logger.info(f"SSH Plugin: Created known_hosts file: {path}")


def _host_in_known_hosts(path: str, host: str, port: int) -> bool:
    """检查指定主机的条目是否已存在于 known_hosts 中喵"""
    host_entry = f"[{host}]:{port}" if port != 22 else host
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                # 每行格式: 主机条目 密钥类型 密钥内容，行首可能带 @revoked/@cert 前缀喵
                fields = line.split()
                if fields and fields[0].lstrip('@') == host_entry:
                    return True
    except FileNotFoundError:
        pass
    return False


async def _tofu_scan_host_key(host: str, port: int, known_hosts_path: str, timeout: int = 10):
    _ensure_known_hosts_file(known_hosts_path)

    file_size = os.path.getsize(known_hosts_path)
    # TOFU 按主机条目判断，而非整个文件非空才扫描喵
    # 这样连接新主机（换了 IP/端口）也能自动完成首次信任喵
    if file_size > 0 and _host_in_known_hosts(known_hosts_path, host, port):
        return

    logger.info(f"SSH Plugin: host entry not found, scanning host key from {host}:{port} (TOFU)...")
    try:
        server_key = await asyncio.wait_for(
            asyncssh.get_server_host_key(host, port),
            timeout=timeout
        )
        if server_key is not None:
            key_data = server_key.export_public_key('openssh')
            if isinstance(key_data, bytes):
                key_data = key_data.decode('ascii').strip()

            host_entry = f"[{host}]:{port}" if port != 22 else host
            line = f"{host_entry} {key_data}\n"

            with open(known_hosts_path, 'a') as f:
                f.write(line)
            logger.info(f"SSH Plugin: TOFU - Saved host key for {host}:{port} to {known_hosts_path}")
        else:
            logger.error(f"SSH Plugin: Failed to retrieve host key from {host}:{port}")
    except Exception as e:
        logger.error(f"SSH Plugin: TOFU host key scan failed: {type(e).__name__}: {e}")


@register("astrbot_plugin_ssh", "星见雅（xinjianya）", "远程SSH执行器", "v1.5.0")
class SSHPlugin(Star):
    def __init__(self, context: Context, config: dict):
        super().__init__(context)
        self.config = config
        self.sessions: Dict[str, Any] = {}  # user_id -> {conn, process, stdin, stdout, last_active, history}
        self.lock = asyncio.Lock()
        self.pending_confirms: Dict[str, Dict[str, Any]] = {}
        
        # Start cleanup task and store reference
        self.cleanup_task = asyncio.create_task(self._cleanup_sessions())

    async def terminate(self):
        """Plugin lifecycle hook for cleanup."""
        if self.cleanup_task:
            self.cleanup_task.cancel()
            try:
                await self.cleanup_task
            except asyncio.CancelledError:
                pass
        
        # Close all sessions
        async with self.lock:
            for user_id, session in self.sessions.items():
                await self._close_session(session)
            self.sessions.clear()

    async def _close_session(self, session: Dict[str, Any]):
        """Helper to close a session properly."""
        try:
            if "process" in session:
                session["process"].close()
                # await session["process"].wait_closed() # Optional, might block
            if "conn" in session:
                session["conn"].close()
                await session["conn"].wait_closed()
        except Exception as e:
            logger.warning(f"Error closing SSH session: {e}")

    async def _cleanup_sessions(self):
        """Clean up idle sessions every minute."""
        while True:
            try:
                await asyncio.sleep(60)
                now = datetime.now()
                idle_timeout = self.config.get("idle_timeout", 30)

                # 顺带清理过期的待确认命令，防止残留喵
                expired = [
                    uid for uid, p in self.pending_confirms.items()
                    if now - p["time"] > timedelta(seconds=30)
                ]
                for uid in expired:
                    self.pending_confirms.pop(uid, None)

                # Snapshot keys to avoid holding lock during cleanup iteration
                async with self.lock:
                    user_ids = list(self.sessions.keys())
                
                for user_id in user_ids:
                    # Check timeout with minimal lock holding
                    session = None
                    async with self.lock:
                        if user_id in self.sessions:
                            if now - self.sessions[user_id]['last_active'] > timedelta(minutes=idle_timeout):
                                session = self.sessions.pop(user_id)
                    
                    if session:
                        await self._close_session(session)
                        logger.info(f"Closed idle SSH session for user {user_id}")
                        
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in cleanup task: {e}")

    def _check_command(self, command: str) -> str:
        if self.config.get("enable_dangerous_commands", False):
            return "allow"

        # 先对完整命令做黑名单检查，防止拆分破坏匹配喵
        for pattern in BLOCKED_PATTERNS:
            if re.search(pattern, command, re.IGNORECASE):
                return "blocked"

        whitelist = self.config.get("command_whitelist", [])
        if not whitelist:
            whitelist = DEFAULT_WHITELIST

        # 命令替换语法无法安全拆分检查，一律要求人工确认喵
        if "$(" in command or "`" in command:
            return "confirm"

        # 按 ; && || | 换行 拆分子命令，逐条检查，防止拼接绕过喵
        for sub_cmd in _split_command(command):
            result = self._check_single_command(sub_cmd, whitelist)
            if result != "allow":
                # 任一子命令命中黑名单或不在白名单，整体不放行喵
                return result

        return "allow"

    def _check_single_command(self, command: str, whitelist: list) -> str:
        """检查单条子命令：黑名单直接拦截，白名单带边界匹配喵"""
        for pattern in BLOCKED_PATTERNS:
            if re.search(pattern, command, re.IGNORECASE):
                return "blocked"

        cmd_base = command.strip().split()[0] if command.strip() else ""

        for allowed in whitelist:
            allowed_parts = allowed.strip().split()
            if not allowed_parts:
                continue
            if cmd_base == allowed_parts[0]:
                if len(allowed_parts) == 1:
                    return "allow"
                prefix = allowed.strip()
                # 前缀匹配必须带空格边界，防止 docker psx 冒充 docker ps 喵
                if command == prefix or command.startswith(prefix + " "):
                    return "allow"

        return "confirm"

    async def _get_or_create_session(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get existing session or create a new one."""
        # Fast path: check if session exists
        async with self.lock:
            if user_id in self.sessions:
                self.sessions[user_id]['last_active'] = datetime.now()
                return self.sessions[user_id]
        
        # Slow path: connect without holding the main lock (to allow concurrency)
        host = self.config.get("host", "127.0.0.1")
        port = self.config.get("port", 22)
        username = self.config.get("username", "root")
        password = self.config.get("password", "")
        private_key_content = self.config.get("private_key", "").strip()
        timeout = self.config.get("timeout", 10)
        
        known_hosts_path = _get_known_hosts_path(self.config)
        await _tofu_scan_host_key(host, port, known_hosts_path, timeout)

        logger.info(f"SSH Plugin: Connecting to {username}@{host}:{port} with known_hosts: {known_hosts_path}")

        try:
            client_keys = None
            if private_key_content:
                try:
                    client_keys = [asyncssh.import_private_key(private_key_content)]
                    logger.info("SSH Plugin: Using private key for authentication.")
                except Exception as key_err:
                    logger.error(f"SSH Plugin: Failed to import private key: {key_err}")
                    # Fallback to password if import fails? Or fail early?
                    # Let's try to continue with password if available
            
            conn = await asyncssh.connect(
                host,
                port=port,
                username=username,
                password=password if not client_keys else None,
                client_keys=client_keys,
                known_hosts=known_hosts_path,
                login_timeout=timeout
            )
            
            # Open interactive shell
            process = await conn.create_process(term_type='xterm', term_size=(80, 24))
            
            # Consume banner
            try:
                await asyncio.wait_for(process.stdout.read(4096), timeout=1.0)
            except Exception:
                pass

            session_data = {
                "conn": conn,
                "process": process,
                "stdin": process.stdin,
                "stdout": process.stdout,
                "last_active": datetime.now(),
                "history": []
            }

            # Store session (check again if created concurrently)
            async with self.lock:
                if user_id in self.sessions:
                    # Another task created it, close ours
                    await self._close_session(session_data)
                    return self.sessions[user_id]
                self.sessions[user_id] = session_data
            
            logger.info(f"SSH Plugin: Connected to {host} successfully.")
            return session_data
            
        except Exception as e:
            logger.error(f"SSH connection failed for {user_id}: {e}")
            raise

    def _clean_ansi(self, text: str) -> str:
        """Strip ANSI escape codes from text."""
        # 1. CSI: Control Sequence Introducer (ESC [ ...)
        text = re.sub(r'\x1B\[[0-?]*[ -/]*[@-~]', '', text)
        # 2. OSC: Operating System Command (ESC ] ... BEL/ST)
        # Matches ESC ] followed by anything until BEL (\x07) or ST (ESC \)
        text = re.sub(r'\x1B\].*?(?:\x07|\x1B\\)', '', text)
        # 3. Other simple escapes if needed (like \x1B(B for charset)
        text = re.sub(r'\x1B[ -/]+[@-~]', '', text)
        return text

    async def _execute_interactive(self, session: Dict[str, Any], cmd: str) -> str:
        stdin = session['stdin']
        stdout = session['stdout']
        
        max_bytes = self.config.get("max_output_bytes", 32768)
        max_exec_time = self.config.get("max_exec_time", 30)
        truncated = False
        total_bytes = 0
        start_time = datetime.now()

        stdin.write(cmd + '\n')
        await asyncio.sleep(0.5)
        
        raw_chunks = []
        try:
            while True:
                elapsed = (datetime.now() - start_time).total_seconds()
                if elapsed >= max_exec_time:
                    truncated = True
                    logger.warning(f"SSH Plugin: Command exceeded max exec time ({max_exec_time}s), truncating.")
                    break

                try:
                    data = await asyncio.wait_for(stdout.read(4096), timeout=1.0)
                    if not data: break

                    chunk_size = len(data)
                    if total_bytes + chunk_size > max_bytes:
                        remaining = max_bytes - total_bytes
                        if remaining > 0:
                            raw_chunks.append(data[:remaining])
                            total_bytes += remaining
                        truncated = True
                        logger.warning(f"SSH Plugin: Output exceeded max bytes ({max_bytes}), truncating.")
                        break

                    raw_chunks.append(data)
                    total_bytes += chunk_size
                except asyncio.TimeoutError:
                    break
        except Exception as e:
            logger.error(f"Error reading SSH output: {e}")

        # 远端 shell 已退出时抛错，让上层清理死会话喵
        if not raw_chunks and session["process"].exit_status is not None:
            raise ConnectionError("远端 Shell 进程已退出")

        full_text = ""
        if raw_chunks:
            if isinstance(raw_chunks[0], bytes):
                full_bytes = b"".join(raw_chunks)
                full_text = full_bytes.decode('utf-8', errors='replace')
            else:
                full_text = "".join(raw_chunks)
        
        full_text = self._clean_ansi(full_text)
        full_text = full_text.replace('\r\n', '\n').replace('\r', '\n')
        
        lines = full_text.split('\n')
        if len(lines) > 50:
            lines = lines[-50:]
            truncated = True
            
        final_result = "\n".join(lines) if lines else "(无新输出)"

        if truncated:
            final_result += "\n\n⚠️ 输出已截断（超出限制：最大 {}KB / {}s）".format(max_bytes // 1024, max_exec_time)
        
        if self.config.get("enable_history", True):
            session['history'].append({
                "cmd": _sanitize(cmd),
                "output": _sanitize(final_result),
                "time": datetime.now()
            })
            if len(session['history']) > 100:
                session['history'].pop(0)
            
        session['last_active'] = datetime.now()
        return final_result

    @filter.permission_type(filter.PermissionType.ADMIN)
    @filter.command("ssh")
    async def ssh_cmd(self, event: AstrMessageEvent, *, cmd: str = ""):
        """执行 SSH 命令。
        用法: 
        /ssh <命令>  - 执行命令
        /ssh log    - 查看最近日志
        /ssh out    - 断开连接
        /ssh yes    - 确认执行待确认命令
        /ssh no     - 取消待确认命令
        """
        user_id = event.get_sender_id()

        # Robust command parsing
        raw_msg = event.message_str.strip()
        logger.info(f"SSH Plugin: Received command from {user_id}: '{_sanitize(cmd)}'")

        # Regex extract if argument parsing failed
        match = re.match(r'^/?ssh\s+(.*)', raw_msg, re.IGNORECASE)
        if match:
            cmd = match.group(1).strip()
        else:
             # Fallback: if raw_msg is just "/ssh", cmd might be empty
             if not cmd and raw_msg.lower().replace("/", "") == "ssh":
                 pass
             elif not cmd:
                 parts = raw_msg.split(" ", 1)
                 if len(parts) > 1:
                     cmd = parts[1].strip()

        if not cmd:
            yield event.plain_result("请输入命令。用法: /ssh <命令> | /ssh log | /ssh out")
            return

        # Sub-command dispatch
        if cmd == "out" or cmd == "disconnect":
            async for result in self._handle_out(event, user_id):
                yield result
            return
            
        if cmd == "log":
            async for result in self._handle_log(event, user_id):
                yield result
            return

        if cmd == "yes" or cmd == "no":
            async for result in self._handle_confirm(event, user_id, cmd == "yes"):
                yield result
            return

        check_result = self._check_command(cmd)

        if check_result == "blocked":
            yield event.plain_result(f"🚫 命令被拦截: 检测到高危操作，已阻止执行。\n命令: {_sanitize(cmd)}")
            return

        if check_result == "confirm":
            self.pending_confirms[user_id] = {
                "cmd": cmd,
                "time": datetime.now()
            }
            yield event.plain_result(
                f"⚠️ 该命令不在白名单中，需要二次确认：\n"
                f"命令: {_sanitize(cmd)}\n\n"
                f"发送 /ssh yes 确认执行，/ssh no 取消。\n"
                f"（30秒内有效）"
            )
            return

        async for result in self._do_execute(event, user_id, cmd):
            yield result

    async def _handle_confirm(self, event: AstrMessageEvent, user_id: str, confirmed: bool):
        pending = self.pending_confirms.pop(user_id, None)
        if not pending:
            yield event.plain_result("⚠️ 当前没有待确认的命令。")
            return

        if datetime.now() - pending["time"] > timedelta(seconds=30):
            yield event.plain_result("⏰ 确认已超时，请重新发送命令。")
            return

        if not confirmed:
            yield event.plain_result("✅ 已取消执行。")
            return

        cmd = pending["cmd"]
        async for result in self._do_execute(event, user_id, cmd):
            yield result

    async def _do_execute(self, event: AstrMessageEvent, user_id: str, cmd: str):
        try:
            session = await self._get_or_create_session(user_id)
        except Exception as e:
            logger.error(f"SSH Plugin: Connection failed for {user_id}: {e}")
            yield event.plain_result("❌ SSH 连接失败，请检查服务器配置。详见日志。")
            return

        yield event.plain_result(f"执行中...")
        try:
            result = await self._execute_interactive(session, cmd)
        except Exception as e:
            # 会话已失效（如 SSH 连接断开），清理死会话避免后续命令持续失败喵
            logger.error(f"SSH Plugin: Session dead for {user_id}: {e}")
            async with self.lock:
                # 仅当映射里还是这个会话对象时才移除，避免误删并发新建的会话喵
                if self.sessions.get(user_id) is session:
                    del self.sessions[user_id]
            await self._close_session(session)
            yield event.plain_result("❌ SSH 会话已断开，已自动清理，请重新执行命令。")
            return

        if result and result.strip() != "(无新输出)":
            try:
                url = await self.text_to_image(result)
                yield event.image_result(url)
            except Exception:
                yield event.plain_result(f"💻 终端输出:\n{result}")
        else:
            yield event.plain_result(f"💻 终端输出:\n{result}")

    async def _handle_out(self, event: AstrMessageEvent, user_id: str):
        # 锁内只取走会话，关闭与发消息放到锁外，避免阻塞其他用户喵
        async with self.lock:
            session = self.sessions.pop(user_id, None)

        if session:
            await self._close_session(session)
            yield event.plain_result("🔌 已断开 SSH 连接。")
        else:
            yield event.plain_result("⚠️ 当前没有活跃的 SSH 连接。")

    async def _handle_log(self, event: AstrMessageEvent, user_id: str):
        if not self.config.get("enable_history", True):
            yield event.plain_result("⚠️ 历史记录已关闭。")
            return

        session = None
        async with self.lock:
            session = self.sessions.get(user_id)
            
        if not session:
            yield event.plain_result("⚠️ 当前没有活跃的 SSH 连接。")
            return
            
        history = session.get("history", [])
        if not history:
            yield event.plain_result("📜 暂无执行记录。")
            return
            
        log_size = self.config.get("log_size", 5)
        log_text = f"📜 SSH 执行记录 (最近 {log_size} 条):\n"
        
        for record in history[-log_size:]:
            time_str = record["time"].strftime("%H:%M:%S")
            cmd_str = record["cmd"]
            out_preview = record["output"].replace('\n', ' ')
            if len(out_preview) > 50:
                out_preview = out_preview[:50] + "..."
            log_text += f"[{time_str}] $ {cmd_str}\n   -> {out_preview}\n"
        
        yield event.plain_result(log_text)

    @filter.permission_type(filter.PermissionType.ADMIN)
    @filter.llm_tool(name="ssh_exec")
    async def ssh_tool(self, event: AstrMessageEvent, command: str) -> str:
        """
        Execute a whitelisted command on the remote SSH server (Interactive Shell).
        Commands not in whitelist or matching blocked patterns will be rejected.
        
        Args:
            command (string): The command to execute.
        """
        check_result = self._check_command(command)
        if check_result == "blocked":
            return f"🚫 命令被拦截: 检测到高危操作，已阻止执行。\n命令: {_sanitize(command)}"
        if check_result == "confirm":
            return f"⚠️ 该命令不在白名单中，LLM 无法自动执行非白名单命令，请通过 /ssh {_sanitize(command)} 手动执行并确认。"

        user_id = event.get_sender_id()
        
        try:
            session = await self._get_or_create_session(user_id)
        except Exception as e:
            logger.error(f"SSH Plugin: LLM tool connection failed for {user_id}: {e}")
            return "SSH 连接失败，请检查服务器配置。"

        return await self._execute_interactive(session, command)
