"""
检测器插件包

新增检测器只需在此导入即可被调度器自动发现
"""

from .base_detector import BaseDetector
from .cve_detector import CveDetector
from .config_detector import ConfigDetector
from .weak_password_detector import WeakPasswordDetector
from .service_detector import ServiceDetector
from .privilege_escalation_detector import PrivilegeEscalationDetector
from .file_integrity_detector import FileIntegrityDetector
from .threat_detector import ThreatDetector

__all__ = [
    "BaseDetector",
    "CveDetector",
    "ConfigDetector",
    "WeakPasswordDetector",
    "ServiceDetector",
    "PrivilegeEscalationDetector",
    "FileIntegrityDetector",
    "ThreatDetector"
]
