"""统一日志系统 — 结构化 + 关联 ID"""
import logging
import json
import sys
from datetime import datetime
from contextvars import ContextVar
from pathlib import Path
from secops_core.config import LOG_DIR

correlation_id: ContextVar[str] = ContextVar('correlation_id', default='')


class StructuredFormatter(logging.Formatter):
    def format(self, record):
        return json.dumps({
            "ts": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "module": record.name,
            "corr_id": correlation_id.get(),
            "msg": record.getMessage(),
        }, ensure_ascii=False)


class PlainFormatter(logging.Formatter):
    def __init__(self):
        super().__init__("[%(asctime)s] [%(name)s] %(levelname)s: %(message)s",
                         datefmt="%Y-%m-%d %H:%M:%S")


def get_logger(name: str, level=logging.INFO, structured=False) -> logging.Logger:
    logger = logging.getLogger(f"secops.{name}")
    if logger.handlers:
        return logger
    logger.setLevel(level)
    fmt = StructuredFormatter() if structured else PlainFormatter()
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(level)
    ch.setFormatter(fmt)
    logger.addHandler(ch)
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(LOG_DIR / f"{name}.log", encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(StructuredFormatter() if structured else PlainFormatter())
        logger.addHandler(fh)
    except Exception:
        pass
    return logger
