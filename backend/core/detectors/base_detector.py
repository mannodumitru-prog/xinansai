"""
BaseDetector 抽象基类

功能：
1. 提供统一的漏洞检测器接口
2. 自动加载规则文件
3. 提供统一漏洞结果格式
4. 规范所有检测器实现
5. 提供统一日志与安全执行辅助方法
"""

import os
import json
import logging
from datetime import datetime
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Callable, Optional


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)


class BaseDetector(ABC):
    """所有漏洞检测器的抽象基类。"""

    # 统一验证状态，供前端/报告模块直接使用
    STATUS_VERIFIED = "verified"
    STATUS_UNVERIFIED = "unverified"
    STATUS_NEEDS_MANUAL_CHECK = "needs_manual_check"
    STATUS_NOT_APPLICABLE = "not_applicable"
    STATUS_ERROR = "error"

    def __init__(self, rules_dir: str = "core/rules"):
        """
        初始化检测器。

        Args:
            rules_dir (str): 规则文件目录
        """
        self.rules_dir = rules_dir
        self.logger = logging.getLogger(self.get_detector_name())
        self.rules = self.load_rules()

    @abstractmethod
    def detect(self) -> List[Dict]:
        """执行漏洞检测。"""
        raise NotImplementedError

    @abstractmethod
    def get_detector_name(self) -> str:
        """获取检测器名称。"""
        raise NotImplementedError

    @abstractmethod
    def get_rule_file(self) -> str:
        """获取规则文件名。"""
        raise NotImplementedError

    def load_rules(self) -> Dict:
        """加载规则文件。"""
        rule_file = self.get_rule_file()
        rule_path = os.path.join(self.rules_dir, rule_file)

        if not os.path.exists(rule_path):
            self.logger.warning("Rule file not found: %s", rule_path)
            return {}

        try:
            with open(rule_path, "r", encoding="utf-8") as f:
                rules = json.load(f)
            self.logger.info("Rules loaded successfully: %s", rule_path)
            return rules
        except json.JSONDecodeError as e:
            self.logger.error("Invalid JSON rule file %s: %s", rule_path, e)
            return {}
        except Exception as e:
            self.logger.error("Failed to load rules %s: %s", rule_path, e)
            return {}

    def format_vulnerability(
        self,
        vuln_id: str,
        title: str,
        severity: str,
        category: str,
        description: str,
        affected_target: str,
        remediation: str,
        **kwargs
    ) -> Dict:
        """格式化漏洞结果，保证所有 Detector 返回字段统一。"""
        try:
            vulnerability = {
                "vuln_id": str(vuln_id or "UNKNOWN"),
                "title": str(title or "未命名风险"),
                "severity": str(severity or "medium").lower(),
                "category": str(category or "general"),
                "description": str(description or ""),
                "affected_target": str(affected_target or "unknown"),
                "remediation": str(remediation or "请结合业务环境进行人工核查并修复。"),
                "verification_status": self.STATUS_UNVERIFIED,
                "verification_method": None,
                "evidence": None,
                "detector_name": self.get_detector_name(),
                "detected_at": datetime.now().isoformat(timespec="seconds"),
            }
            vulnerability.update(kwargs)
            return vulnerability
        except Exception as e:
            self.logger.error("Failed to format vulnerability: %s", e)
            return {
                "vuln_id": str(vuln_id or "FORMAT-ERROR"),
                "title": "漏洞结果格式化失败",
                "severity": "medium",
                "category": "internal_error",
                "description": str(e),
                "affected_target": str(affected_target or "unknown"),
                "remediation": "请检查检测器返回字段。",
                "verification_status": self.STATUS_ERROR,
                "verification_method": None,
                "evidence": None,
                "detector_name": self.get_detector_name(),
                "detected_at": datetime.now().isoformat(timespec="seconds"),
            }

    def safe_execute(
        self,
        func: Callable,
        *args,
        default: Optional[Any] = None,
        context: str = "operation",
        **kwargs
    ) -> Any:
        """统一异常保护，避免单个检测点中断整个巡检流程。"""
        try:
            return func(*args, **kwargs)
        except Exception as e:
            self.logger.warning("%s failed: %s", context, e)
            return default

    def get_rules_list(self) -> List[Dict]:
        """兼容 rules: [] 和纯列表两种规则格式。"""
        if isinstance(self.rules, dict):
            rules = self.rules.get("rules", [])
            return rules if isinstance(rules, list) else []
        if isinstance(self.rules, list):
            return self.rules
        return []


if __name__ == "__main__":
    class TestDetector(BaseDetector):
        def detect(self):
            return []

        def get_detector_name(self):
            return "test_detector"

        def get_rule_file(self):
            return "test_rules.json"

    t = TestDetector()
    print("✅ base_detector 可用")
