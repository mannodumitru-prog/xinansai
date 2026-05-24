#!/usr/bin/env python3
"""
服务配置检测器
检查常见服务（SSH, Nginx, MySQL等）的安全配置项
"""

import os
import re
import subprocess
from typing import List, Dict, Any

try:
    from .base_detector import BaseDetector
except ImportError:
    import sys
    import os.path as osp
    sys.path.insert(0, osp.dirname(osp.abspath(__file__)))
    from base_detector import BaseDetector


class ServiceDetector(BaseDetector):
    """服务安全配置检测器"""

    def get_detector_name(self) -> str:
        return "service_detector"

    def get_rule_file(self) -> str:
        return "service_rules.json"

    def detect(self) -> List[Dict]:
        """执行服务配置检查"""
        vulnerabilities = []
        rules = self.rules.get("rules", [])
        if not rules:
            print("[WARN] 未加载到服务规则")
            return []

        print("[INFO] 开始服务配置检查...")

        for rule in rules:
            service = rule.get("service")
            config_file = rule.get("config_file")
            checks = rule.get("checks", [])
            if not config_file or not os.path.exists(config_file):
                print(f"[WARN] 服务 {service} 配置文件不存在: {config_file}")
                continue

            try:
                with open(config_file, "r") as f:
                    content = f.read()

                for check in checks:
                    check_name = check.get("name")
                    directive = check.get("directive")
                    expected = check.get("expected")
                    severity = check.get("severity", "medium")
                    description = check.get("description", "")
                    remediation = check.get("remediation", "")

                    actual = self._extract_directive(content, directive)
                    passed = self._compare_value(actual, expected)

                    if not passed:
                        vuln = self.format_vulnerability(
                            vuln_id=f"SERVICE-{service}-{check_name.replace(' ', '_')}",
                            title=f"服务 {service} 配置不合规: {check_name}",
                            severity=severity,
                            category="service_config",
                            description=description,
                            affected_target=f"{service} ({config_file})",
                            remediation=remediation,
                            service=service,
                            directive=directive,
                            expected=expected,
                            actual=actual
                        )
                        vulnerabilities.append(vuln)
                        print(f"  [FAIL] {service}/{check_name}: 期望 {expected}, 实际 {actual}")
            except Exception as e:
                print(f"[ERROR] 检查服务 {service} 失败: {e}")

        print(f"[INFO] 服务配置检查完成，发现 {len(vulnerabilities)} 个问题")
        return vulnerabilities

    def _extract_directive(self, content: str, directive: str) -> str:
        """从配置文件中提取指令的值（支持 nginx/apache/ssh 等格式）"""
        # 支持多种格式：directive value;  或 directive value  或 directive=value
        patterns = [
            rf"^\s*{re.escape(directive)}\s+([^;#\n]+)",
            rf"^\s*{re.escape(directive)}\s*=\s*([^;#\n]+)",
            rf"^\s*{re.escape(directive)}\s+([^;#\n]+);",
        ]
        for pattern in patterns:
            match = re.search(pattern, content, re.MULTILINE)
            if match:
                return match.group(1).strip()
        return "not_found"

    def _compare_value(self, actual: str, expected: Any) -> bool:
        """比较配置值"""
        if actual == "not_found":
            return False
        if isinstance(expected, bool):
            # 期望 True/False，实际值可能是 "yes"/"no" 或 "on"/"off"
            return (expected and actual.lower() in ["yes", "on", "true", "1"]) or \
                   (not expected and actual.lower() in ["no", "off", "false", "0"])
        if isinstance(expected, list):
            return actual in expected
        if isinstance(expected, dict):
            if "contains" in expected:
                return expected["contains"] in actual
            if "regex" in expected:
                return bool(re.search(expected["regex"], actual))
            return False
        return actual.strip().lower() == str(expected).strip().lower()


if __name__ == "__main__":
    detector = ServiceDetector(rules_dir=os.path.join("..", "rules"))
    results = detector.detect()
    for r in results:
        print(r)
