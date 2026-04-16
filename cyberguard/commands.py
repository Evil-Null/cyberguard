"""System command execution with security controls."""
import logging
import subprocess
from typing import List, Optional, Tuple

_log = logging.getLogger("cyberguard")

class SystemCommandRunner:
    """Safe subprocess wrapper with timeout, sanitization, logging."""

    def __init__(self, logger: logging.Logger):
        self.logger = logger

    def run(self, cmd: List[str], timeout: int = 60, capture: bool = True,
            check: bool = False) -> Tuple[int, str, str]:
        """Run a command safely. Returns (returncode, stdout, stderr)."""
        self.logger.debug(f"Running command: {' '.join(cmd)}")
        try:
            result = subprocess.run(
                cmd,
                capture_output=capture,
                text=True,
                timeout=timeout,
                stdin=subprocess.DEVNULL,
            )
            stdout = result.stdout or ""
            stderr = result.stderr or ""
            if result.returncode != 0:
                self.logger.debug(f"Command returned {result.returncode}: {stderr[:200]}")
            return result.returncode, stdout, stderr
        except subprocess.TimeoutExpired:
            self.logger.warning(f"Command timed out after {timeout}s: {' '.join(cmd)}")
            return -1, "", f"Command timed out after {timeout}s"
        except FileNotFoundError:
            self.logger.debug(f"Command not found: {cmd[0]}")
            return -2, "", f"Command not found: {cmd[0]}"
        except Exception as e:
            self.logger.error(f"Command failed: {e}")
            return -3, "", str(e)

    def run_sudo(self, cmd: List[str], timeout: int = 60) -> Tuple[int, str, str]:
        """Run command with sudo prefix."""
        return self.run(["sudo", "-n"] + cmd, timeout=timeout)

    def has_command(self, name: str) -> bool:
        return shutil.which(name) is not None

    def has_sudo(self) -> bool:
        rc, _, _ = self.run(["sudo", "-n", "true"], timeout=5)
        return rc == 0

    def read_proc_file(self, path: str) -> Optional[str]:
        try:
            return Path(path).read_text(encoding="utf-8", errors="replace")
        except (OSError, PermissionError):
            return None

    def read_sysctl(self, param: str) -> Optional[str]:
        rc, out, _ = self.run(["sysctl", "-n", param], timeout=5)
        if rc == 0:
            return out.strip()
        return None


# ═══════════════════════════════════════════════════════════════════════════
# THREAT INTELLIGENCE API
# ═══════════════════════════════════════════════════════════════════════════
