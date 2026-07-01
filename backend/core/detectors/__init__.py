"""
检测器插件包

新增检测器只需在此导入即可被调度器自动发现。
注意：本文件应在项目中命名为 __init__.py，而不是 _init_.py。
"""

from .base_detector import BaseDetector
from .cve_detector import CveDetector
from .config_detector import ConfigDetector
from .weak_password_detector import WeakPasswordDetector
from .service_detector import ServiceDetector
from .file_integrity_detector import FileIntegrityDetector
from .privilege_escalation_detector import PrivilegeEscalationDetector
from .threat_detector import ThreatDetector

__all__ = [
    "BaseDetector",
    "CveDetector",
    "ConfigDetector",
    "WeakPasswordDetector",
    "ServiceDetector",
    "FileIntegrityDetector",
    "PrivilegeEscalationDetector",
    "ThreatDetector",
]
