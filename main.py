import asyncio
import re
from datetime import datetime, timedelta
from typing import Dict, Any, Optional

import asyncssh
from astrbot.api.event import filter, AstrMessageEvent
from astrbot.api.star import Star, register, Context
from astrbot.api import logger

@register("astrbot_plugin_ssh", "5060ti个马力的6999", "远程SSH执行器", "v1.2.0")
class SSHPlugin(Star):
    def __init__(self, context: Context, config: dict):
        super().__init__(context)
        self.config = config
        self.sessions: Dict[str, Any] = {}  # user_id -> {conn, process, stdin, stdout, last_active, history}
        self.lock = asyncio.Lock()
        
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

    def _is_safe_command(self, command: str) -> bool:
        """Check if command is safe to execute."""
        # Allow dangerous commands if explicitly enabled in config (default False)
        if self.config.get("enable_dangerous_commands", False):
            return True

        # Expanded blacklist
        blocked_patterns = [
            r"rm\s+.*-r", r"rm\s+.*-f", r"rm\s+-\w*r", # rm -rf variants
            r"mkfs", r"dd\s+if=", r"shutdown", r"reboot", r"init\s+0", r"poweroff",
            r":\(\)\s*\{\s*:\s*\|\s*:\s*\&\s*\}\s*;", # fork bomb
            r"wget\s+.*\|.*sh", r"curl\s+.*\|.*sh", # pipe to shell
            r">\s*/dev/sd[a-z]", r">\s*/dev/nvme", # overwrite disk
            r"chmod\s+-R\s+777", r"chown\s+-R",
            r"kill\s+-9\s+-1", # kill all
            r"useradd", r"usermod", r"groupadd", # user management
            r"iptables", r"ufw", # firewall
        ]
        
        # Check for dangerous patterns
        for pattern in blocked_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                return False
        return True

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
        timeout = self.config.get("timeout", 10)
        known_hosts = self.config.get("known_hosts_path", None) # Default to None (insecure but standard for plugins)
        
        logger.info(f"SSH Plugin: Connecting to {username}@{host}:{port} ...")
        
        try:
            conn = await asyncssh.connect(
                host,
                port=port,
                username=username,
                password=password,
                known_hosts=known_hosts,
                login_timeout=timeout
            )
            
            # Open interactive shell
            process = await conn.create_process(term_type='xterm', term_size=(80, 24))
            
            # Consume banner
            try:
                await asyncio.wait_for(process.stdout.read(4096), timeout=1.0)
            except (asyncio.TimeoutError, Exception):
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
        """Send command to interactive shell and read output."""
        stdin = session['stdin']
        stdout = session['stdout']
        
        # Send command
        stdin.write(cmd + '\n')
        
        # Read output with timeout
        # We wait a bit for output to appear, then read until it pauses
        await asyncio.sleep(0.5)
        
        raw_chunks = []
        try:
            while True:
                try:
                    data = await asyncio.wait_for(stdout.read(4096), timeout=1.0)
                    if not data: break
                    # Collect raw bytes (or str if asyncssh decided to decode)
                    # asyncssh create_process default encoding is None -> bytes
                    # If encoding was set, it's str. We didn't set encoding=... in create_process call above (default bytes)
                    # Wait, create_process(..., encoding=None) returns bytes.
                    # But if we received bytes, we append bytes.
                    raw_chunks.append(data)
                except asyncio.TimeoutError:
                    break
        except Exception as e:
            logger.error(f"Error reading SSH output: {e}")
            
        # Combine chunks
        full_text = ""
        if raw_chunks:
            # Check type of first chunk
            if isinstance(raw_chunks[0], bytes):
                # Join bytes then decode
                full_bytes = b"".join(raw_chunks)
                full_text = full_bytes.decode('utf-8', errors='replace')
            else:
                # Join strings
                full_text = "".join(raw_chunks)
        
        # Clean ANSI codes from the complete string to ensure sequences aren't split
        full_text = self._clean_ansi(full_text)
        
        # Convert CRLF to LF to fix double spacing or weird line endings
        full_text = full_text.replace('\r\n', '\n').replace('\r', '\n')
        
        # Limit lines
        lines = full_text.split('\n')
        if len(lines) > 50:
            lines = lines[-50:]
            
        final_result = "\n".join(lines) if lines else "(无新输出)"
        
        # Record history
        session['history'].append({
            "cmd": cmd,
            "output": final_result,
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
        """
        user_id = event.get_sender_id()

        # Robust command parsing
        raw_msg = event.message_str.strip()
        # Mask sensitive info in logs (simple heuristic)
        log_cmd = cmd
        if any(s in cmd.lower() for s in ["pass", "token", "key", "secret"]):
            log_cmd = "***"
        logger.info(f"SSH Plugin: Received command from {user_id}: '{log_cmd}'")

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

        # Execute normal command
        try:
            session = await self._get_or_create_session(user_id)
        except Exception as e:
            yield event.plain_result(f"❌ 连接失败: {e}")
            return

        yield event.plain_result(f"执行中...")
        result = await self._execute_interactive(session, cmd)
        
        # Convert to image if enabled/needed (e.g. long output)
        # Here we follow previous logic: text to image for result
        if result and result.strip() != "(无新输出)":
            try:
                url = await self.text_to_image(result)
                yield event.image_result(url)
            except:
                yield event.plain_result(f"💻 终端输出:\n{result}")
        else:
            yield event.plain_result(f"💻 终端输出:\n{result}")

    async def _handle_out(self, event: AstrMessageEvent, user_id: str):
        async with self.lock:
            if user_id in self.sessions:
                await self._close_session(self.sessions[user_id])
                del self.sessions[user_id]
                yield event.plain_result("🔌 已断开 SSH 连接。")
            else:
                yield event.plain_result("⚠️ 当前没有活跃的 SSH 连接。")

    async def _handle_log(self, event: AstrMessageEvent, user_id: str):
        # Read-only access to session, check if exists
        # We need lock to ensure session doesn't vanish, but we can just check
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

    # Register aliases for subcommands to ensure they appear in help system if supported
    # Note: These are fallback handlers if the user types /ssh_log directly
    @filter.permission_type(filter.PermissionType.ADMIN)
    @filter.command("ssh_log") 
    async def ssh_log_cmd(self, event: AstrMessageEvent):
        """查看 SSH 日志"""
        async for result in self._handle_log(event, event.get_sender_id()):
            yield result

    @filter.permission_type(filter.PermissionType.ADMIN)
    @filter.command("ssh_out")
    async def ssh_out_cmd(self, event: AstrMessageEvent):
        """断开 SSH 连接"""
        async for result in self._handle_out(event, event.get_sender_id()):
            yield result

    @filter.permission_type(filter.PermissionType.ADMIN)
    @filter.llm_tool(name="ssh_exec")
    async def ssh_tool(self, event: AstrMessageEvent, command: str) -> str:
        """
        Execute a command on the remote SSH server (Interactive Shell).
        Only allowed for non-dangerous commands.
        
        Args:
            command (string): The command to execute.
        """
        if not self._is_safe_command(command):
            return "❌ Command blocked: Potential high-risk command detected."

        user_id = event.get_sender_id()
        
        try:
            session = await self._get_or_create_session(user_id)
        except Exception as e:
            return f"Error connecting to SSH: {e}"

        return await self._execute_interactive(session, command)
