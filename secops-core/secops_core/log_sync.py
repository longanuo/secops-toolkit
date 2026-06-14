"""多模型执行日志同步 — 防上下文截断"""
import json
import time
import threading
import hashlib
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from datetime import datetime
from pathlib import Path
from secops_core.logger import get_logger
from secops_core.config import CACHE_DIR

log = get_logger("log_sync")

SYNC_DIR = CACHE_DIR / "log_sync"
SYNC_DIR.mkdir(parents=True, exist_ok=True)


@dataclass
class LogEntry:
    timestamp: float
    source: str
    event_type: str
    data: Any
    checksum: str = ""
    sequence: int = 0

    def __post_init__(self):
        if not self.checksum:
            raw = f"{self.timestamp}:{self.source}:{self.event_type}:{json.dumps(self.data, default=str)}"
            self.checksum = hashlib.md5(raw.encode()).hexdigest()[:12]


class LogSynchronizer:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self._entries: List[LogEntry] = []
        self._sequence = 0
        self._lock = threading.RLock()
        self._sessions: Dict[str, List[LogEntry]] = {}
        self._context_cache: Dict[str, str] = {}
        self._max_entries = 1000
        self._max_context_tokens = 8000

    def log(self, source: str, event_type: str, data: Any) -> LogEntry:
        with self._lock:
            self._sequence += 1
            entry = LogEntry(
                timestamp=time.time(),
                source=source,
                event_type=event_type,
                data=data,
                sequence=self._sequence,
            )
            self._entries.append(entry)
            if len(self._entries) > self._max_entries:
                self._entries = self._entries[-self._max_entries:]
            return entry

    def start_session(self, session_id: str):
        with self._lock:
            self._sessions[session_id] = []
            log.info(f"Log sync session started: {session_id}")

    def append_session(self, session_id: str, entry: LogEntry):
        with self._lock:
            if session_id in self._sessions:
                self._sessions[session_id].append(entry)

    def get_context_summary(self, session_id: str = None, max_tokens: int = None) -> str:
        max_tokens = max_tokens or self._max_context_tokens
        with self._lock:
            if session_id and session_id in self._sessions:
                entries = self._sessions[session_id]
            else:
                entries = self._entries[-100:]

        if not entries:
            return ""

        summary_parts = []
        current_tokens = 0

        for entry in reversed(entries):
            line = self._format_entry(entry)
            estimated_tokens = len(line) // 4
            if current_tokens + estimated_tokens > max_tokens:
                break
            summary_parts.append(line)
            current_tokens += estimated_tokens

        summary_parts.reverse()
        header = f"[LogSync] {len(summary_parts)} recent entries (est. {current_tokens} tokens)\n"
        return header + "\n".join(summary_parts)

    def get_compact_state(self, session_id: str = None) -> Dict:
        with self._lock:
            if session_id and session_id in self._sessions:
                entries = self._sessions[session_id]
            else:
                entries = self._entries[-50:]

        state = {
            "total_entries": len(entries),
            "event_counts": {},
            "last_activity": 0,
            "sources": set(),
        }

        for entry in entries:
            state["event_counts"][entry.event_type] = state["event_counts"].get(entry.event_type, 0) + 1
            state["sources"].add(entry.source)
            state["last_activity"] = max(state["last_activity"], entry.timestamp)

        state["sources"] = list(state["sources"])
        return state

    def sync_to_file(self, session_id: str = None) -> Path:
        with self._lock:
            if session_id and session_id in self._sessions:
                entries = self._sessions[session_id]
            else:
                entries = list(self._entries)

        filename = f"sync_{session_id or 'global'}_{int(time.time())}.json"
        filepath = SYNC_DIR / filename

        data = {
            "session_id": session_id,
            "timestamp": datetime.now().isoformat(),
            "entry_count": len(entries),
            "entries": [
                {
                    "sequence": e.sequence,
                    "timestamp": e.timestamp,
                    "source": e.source,
                    "event_type": e.event_type,
                    "data": e.data,
                    "checksum": e.checksum,
                }
                for e in entries
            ],
        }

        filepath.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str))
        log.info(f"Synced {len(entries)} entries to {filepath}")
        return filepath

    def load_from_file(self, filepath: Path) -> List[LogEntry]:
        data = json.loads(filepath.read_text())
        entries = []
        for item in data.get("entries", []):
            entry = LogEntry(
                timestamp=item["timestamp"],
                source=item["source"],
                event_type=item["event_type"],
                data=item["data"],
                checksum=item.get("checksum", ""),
                sequence=item.get("sequence", 0),
            )
            entries.append(entry)
            with self._lock:
                self._entries.append(entry)
        log.info(f"Loaded {len(entries)} entries from {filepath}")
        return entries

    def get_checksum_chain(self, count: int = 10) -> List[str]:
        with self._lock:
            return [e.checksum for e in self._entries[-count:]]

    def verify_integrity(self) -> bool:
        with self._lock:
            for entry in self._entries:
                raw = f"{entry.timestamp}:{entry.source}:{entry.event_type}:{json.dumps(entry.data, default=str)}"
                expected = hashlib.md5(raw.encode()).hexdigest()[:12]
                if entry.checksum != expected:
                    log.error(f"Integrity check failed for entry {entry.sequence}")
                    return False
        return True

    def _format_entry(self, entry: LogEntry) -> str:
        ts = datetime.fromtimestamp(entry.timestamp).strftime("%H:%M:%S")
        data_str = json.dumps(entry.data, default=str)
        if len(data_str) > 100:
            data_str = data_str[:97] + "..."
        return f"[{ts}] {entry.source}/{entry.event_type}: {data_str}"

    def clear(self, session_id: str = None):
        with self._lock:
            if session_id and session_id in self._sessions:
                del self._sessions[session_id]
            else:
                self._entries.clear()
                self._sessions.clear()


sync = LogSynchronizer()
