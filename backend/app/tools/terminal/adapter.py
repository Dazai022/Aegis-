from __future__ import annotations
import subprocess, time, uuid, re
from dataclasses import dataclass
from app.core.config import settings
from app.core import logging as aegis_logging

log = aegis_logging.logger

_HARD_BLOCKED = [
    re.compile(r'rm\s+-[a-z]*r[a-z]*f', re.I),
    re.compile(r'mkfs|dd\s+if=|shred\s', re.I),
    re.compile(r'\bshutdown\b|\breboot\b|\bhalt\b|\bpoweroff\b', re.I),
]


@dataclass
class TerminalResult:
    stdout: str
    stderr: str
    exit_code: int
    duration_ms: float
    blocked: bool = False
    error: str | None = None


class SecureTerminalAdapter:
    '''Prototype terminal adapter. NOT PRODUCTION READY without Docker isolation.'''

    def __init__(self) -> None:
        self.use_docker = False

    def _is_hard_blocked(self, command: str) -> bool:
        for pat in _HARD_BLOCKED:
            if pat.search(command):
                return True
        return False

    def execute(self, command: str, timeout: int | None = None, workdir: str | None = None) -> TerminalResult:
        t = timeout or settings.TERMINAL_TIMEOUT_SECONDS
        if self._is_hard_blocked(command):
            log.warning('terminal hard-block applied')
            return TerminalResult(stdout='', stderr='Command blocked by hard security policy',
                exit_code=-1, duration_ms=0.0, blocked=True, error='HARD_BLOCKED')
        if self.use_docker:
            return self._docker(command, t, workdir)
        return self._subprocess(command, t, workdir)

    def _subprocess(self, command: str, timeout: int, workdir: str | None) -> TerminalResult:
        env = {'PATH': '/usr/bin:/bin:/usr/local/bin', 'HOME': '/tmp', 'TERM': 'dumb'}
        start = time.perf_counter()
        try:
            proc = subprocess.run(['sh', '-c', command], capture_output=True, text=True,
                timeout=timeout, env=env, cwd=workdir or '/tmp')
            ms = (time.perf_counter() - start) * 1000
            return TerminalResult(stdout=proc.stdout[:settings.MAX_OUTPUT_BYTES],
                stderr=proc.stderr[:settings.MAX_OUTPUT_BYTES],
                exit_code=proc.returncode, duration_ms=round(ms, 2))
        except subprocess.TimeoutExpired:
            ms = (time.perf_counter() - start) * 1000
            return TerminalResult(stdout='', stderr='', exit_code=-1, duration_ms=round(ms,2), error='TIMEOUT')
        except Exception as exc:
            ms = (time.perf_counter() - start) * 1000
            return TerminalResult(stdout='', stderr='', exit_code=-1, duration_ms=round(ms,2), error=str(exc))

    def _docker(self, command: str, timeout: int, workdir: str | None) -> TerminalResult:
        start = time.perf_counter()
        cmd = ['docker', 'run', '--rm', '--network=none',
            f'--memory={settings.TERMINAL_MEMORY_MB}m', f'--cpus={settings.TERMINAL_CPU_SHARES}',
            '--cap-drop=ALL', '--security-opt=no-new-privileges:true',
            '--read-only', '--tmpfs=/workspace:rw,noexec,size=64m',
            settings.TERMINAL_IMAGE, 'sh', '-c', command]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            ms = (time.perf_counter() - start) * 1000
            return TerminalResult(stdout=proc.stdout[:settings.MAX_OUTPUT_BYTES],
                stderr=proc.stderr[:settings.MAX_OUTPUT_BYTES],
                exit_code=proc.returncode, duration_ms=round(ms, 2))
        except subprocess.TimeoutExpired:
            ms = (time.perf_counter() - start) * 1000
            return TerminalResult(stdout='', stderr='', exit_code=-1, duration_ms=round(ms,2), error='TIMEOUT')
        except Exception as exc:
            return TerminalResult(stdout='', stderr='', exit_code=-1, duration_ms=0.0, error=str(exc))


terminal_adapter = SecureTerminalAdapter()
