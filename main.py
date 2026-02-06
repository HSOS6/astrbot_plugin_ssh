import asyncio
import logging
import re
from datetime import datetime, timedelta
from typing import Dict, Any, Optional

import asyncssh
from astrbot.api.event import filter, AstrMessageEvent
from astrbot.api.star import Star, register, Context
from astrbot.api import logger

@register("astrbot_plugin_ssh", "5060ti个马力的6999", "远程SSH执行器", "v1.0.Beta")
class SSHPlugin(Star):
    def __init__(self, context: Context, config: dict):
        super().__init__(context)
        self.config = config
        self.sessions: Dict[str, Any] = {}  # user_id -> {conn, last_active, cwd}
        self.lock = asyncio.Lock()
        
        # Start cleanup task
        asyncio.create_task(self._cleanup_sessions())

    async def _cleanup_sessions(self):
        """Clean up idle sessions every minute."""
        while True:
            await asyncio.sleep(60)
            now = datetime.now()
            
            # Get timeout config dynamically
            idle_timeout = self.config.get("idle_timeout", 30)
            
            async with self.lock:
                to_remove = []
                for user_id, session in self.sessions.items():
                    if now - session['last_active'] > timedelta(minutes=idle_timeout):
                        try:
                            session['conn'].close()
                        except Exception as e:
                            logger.error(f"Error closing SSH session for {user_id}: {e}")
                        to_remove.append(user_id)
                        logger.info(f"Closed idle SSH session for user {user_id}")
                
                for uid in to_remove:
                    del self.sessions[uid]

    def _is_safe_command(self, command: str) -> bool:
        """Check if command is safe to execute."""
        blocked_patterns = [
            r"rm\s+.*-r", r"rm\s+.*-f",  # rm -rf variants
            r"mkfs", r"dd\s+if=", r"shutdown", r"reboot", r"init\s+0",
            r":\(\)\s*\{\s*:\s*\|\s*:\s*\&\s*\}\s*;", # fork bomb
            r"wget\s+.*\|.*sh", r"curl\s+.*\|.*sh", # pipe to shell
            r">/dev/sda", # overwrite disk
        ]
        for pattern in blocked_patterns:
            if re.search(pattern, command):
                return False
        return True

    async def _get_or_create_session(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get existing session or create a new one."""
        async with self.lock:
            if user_id in self.sessions:
                self.sessions[user_id]['last_active'] = datetime.now()
                return self.sessions[user_id]
            
            # Create new connection
            host = self.config.get("host", "127.0.0.1")
            port = self.config.get("port", 22)
            username = self.config.get("username", "root")
            password = self.config.get("password", "")
            timeout = self.config.get("timeout", 10)
            
            logger.info(f"SSH Plugin: Connecting to {username}@{host}:{port} ...")
            
            try:
                conn = await asyncssh.connect(
                    host,
                    port=port,
                    username=username,
                    password=password,
                    known_hosts=None,
                    login_timeout=timeout
                )
                self.sessions[user_id] = {
                    "conn": conn,
                    "last_active": datetime.now(),
                    "cwd": "~"
                }
                logger.info(f"SSH Plugin: Connected to {host} successfully.")
                return self.sessions[user_id]
            except Exception as e:
                logger.error(f"SSH connection failed for {user_id} ({username}@{host}:{port}): {e}")
                raise e

    async def _execute_command(self, session: Dict[str, Any], cmd: str) -> str:
        """Execute command in the session context."""
        conn = session['conn']
        cwd = session['cwd']
        
        # Construct command to preserve CWD
        marker = "___PWD_MARKER___"
        full_cmd = f"cd {cwd} && {cmd}; echo '{marker}'; pwd"
        
        try:
            result = await conn.run(full_cmd, check=False)
            output = result.stdout
            
            # Parse new CWD
            if marker in output:
                parts = output.split(marker)
                actual_output = parts[0].strip()
                new_cwd = parts[1].strip()
                session['cwd'] = new_cwd
                output = actual_output
            
            if result.stderr:
                output += f"\nSTDERR:\n{result.stderr}"
                
            session['last_active'] = datetime.now()
            return output if output.strip() else "(No output)"
            
        except Exception as e:
            return f"Execution error: {e}"

    @filter.permission_type(filter.PermissionType.ADMIN)
    @filter.command("ssh")
    async def ssh_cmd(self, event: AstrMessageEvent, *, cmd: str = ""):
        """执行 SSH 命令。用法: /ssh <命令> 或 /ssh disconnect"""
        user_id = event.get_sender_id()

        if cmd == "disconnect":
            async with self.lock:
                if user_id in self.sessions:
                    try:
                        self.sessions[user_id]["conn"].close()
                    except:
                        pass
                    del self.sessions[user_id]
                    yield event.plain_result("✅ 已断开 SSH 连接。")
                else:
                    yield event.plain_result("♨️ 当前没有活跃的 SSH 连接。")
            return

        if not cmd:
            yield event.plain_result("💫 请输入命令！用法: /ssh <命令>")
            return

        # Ensure connection
        try:
            session = await self._get_or_create_session(user_id)
        except ValueError:
            yield event.plain_result("❌ 插件未配置，请在Astrbot中配置 SSH 连接信息。")
            return
        except Exception as e:
            yield event.plain_result(f"❌ 连接失败惹: {e}")
            return

        # Execute
        yield event.plain_result(f"执行中，请稍后...")
        result = await self._execute_command(session, cmd)
        yield event.plain_result(result)

    @filter.permission_type(filter.PermissionType.ADMIN)
    @filter.llm_tool(name="ssh_exec")
    async def ssh_tool(self, event: AstrMessageEvent, command: str) -> str:
        """
        Execute a command on the remote SSH server. 
        Only allowed for non-dangerous commands.
        State (like current directory) is preserved between calls.
        
        Args:
            command (string): The command to execute.
        """
        # Safety check
        if not self._is_safe_command(command):
            return "❌ Command blocked: Potential high-risk command detected."

        user_id = event.get_sender_id()
        
        try:
            session = await self._get_or_create_session(user_id)
        except Exception as e:
            return f"Error connecting to SSH: {e}"

        # Execute
        return await self._execute_command(session, command)
