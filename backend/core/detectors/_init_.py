"""
检测器插件包

新增检测器只需在此导入即可被调度器自动发现
"""

from .base_detector import BaseDetector
from .cve_detector import CveDetector
from .config_detector import ConfigDetector
from .weak_password_detector import WeakPasswordDetector
from .service_detector import ServiceDetector

__all__ = [
    "BaseDetector",
    "CveDetector",
    "ConfigDetector",
    "WeakPasswordDetector",
    "ServiceDetector"
]