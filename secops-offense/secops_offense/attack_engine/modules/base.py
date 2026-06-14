"""检测器基类"""
from abc import ABC, abstractmethod
from typing import List
from secops_offense.attack_engine.finding import Finding


class BaseDetector(ABC):
    """漏洞检测器基类"""
    name: str = "base"
    category: str = "unknown"

    @abstractmethod
    def test(self, target_url: str, **kwargs) -> List[Finding]:
        raise NotImplementedError
