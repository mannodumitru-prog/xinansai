#!/usr/bin/env python3
"""
配置合规检测器
检查系统安全配置，如SSH、防火墙、密码策略等
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


class ConfigDetector(BaseDetector):
    """配置合规检测器"""

    def get_detector_name(self) -> str:
        return "config_detector"

    def get_rule_file(self) -> str:
        return "config_rules.json"

    def detect(self) -> List[Dict]:
        """执行配置合规检查"""
        vulnerabilities = []
        rules = self.rules.get("rules", [])
        if not rules:
            print("[WARN] 未加载到配置合规规则")
            return []

        print("[INFO] 开始配置合规检查...")

        for rule in rules:
            try:
                check_name = rule.get("check_name")
                check_type = rule.get("check_type")  # file, command, sysctl, service
                target = rule.get("target")
                expected = rule.get("expected")
                severity = rule.get("severity", "medium")
                category = rule.get("category", "config")
                description = rule.get("description", "")
                remediation = rule.get("remediation", "")

                actual = self._perform_check(check_type, target)
                passed = self._compare(actual, expected)

                if not passed:
                    vuln = self.format_vulnerability(
                        vuln_id=f"CONFIG-{check_name.replace(' ', '_')}",
                        title=f"配置不合规: {check_name}",
                        severity=severity,
                        category=category,
                        description=description,
                        affected_target=target,
                        remediation=remediation,
                        check_name=check_name,
                        expected=expected,
                        actual=actual
                    )
                    vulnerabilities.append(vuln)
                    print(f"  [FAIL] {check_name}: 期望 {expected}, 实际 {actual}")

            except Exception as e:
                print(f"  [ERROR] 检查失败: {rule.get('check_name')} - {e}")

        print(f"[INFO] 配置合规检查完成，发现 {len(vulnerabilities)} 个问题")
        return vulnerabilities

    def _perform_check(self, check_type: str, target: str) -> Any:
        """执行具体检查"""
        if check_type == "file":
            return self._check_file_content(target)
        elif check_type == "command":
            return self._run_command(target)
        elif check_type == "sysctl":
            return self._get_sysctl(target)
        elif check_type == "service":
            return self._check_service_status(target)
        else:
            return None

    def _check_file_content(self, file_path: str) -> str:
        """读取文件内容（或特定配置项）"""
        if not os.path.exists(file_path):
            return "missing"
        try:
            with open(file_path, "r") as f:
                return f.read().strip()
        except Exception:
            return "error"

    def _run_command(self, cmd: str) -> str:
        """执行命令并返回输出（去除换行）"""
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=10
            )
            return result.stdout.strip()
        except Exception:
            return "error"

    def _get_sysctl(self, param: str) -> str:
        """获取内核参数值"""
        try:
            result = subprocess.run(
                ["sysctl", "-n", param], capture_output=True, text=True, timeout=5
            )
            return result.stdout.strip()
        except Exception:
            return "error"

    def _check_service_status(self, service: str) -> str:
        """检查服务是否启用并运行"""
        # 使用 systemctl
        try:
            result = subprocess.run(
                ["systemctl", "is-enabled", service], capture_output=True, text=True, timeout=5
            )
            enabled = result.stdout.strip()
            result = subprocess.run(
                ["systemctl", "is-active", service], capture_output=True, text=True, timeout=5
            )
            active = result.stdout.strip()
            return f"enabled={enabled},active={active}"
        except Exception:
            return "unknown"

    def _compare(self, actual: Any, expected: Any) -> bool:
        """比较实际值与期望值（支持字符串、正则、列表等）"""
        if actual is None:
            return False
        if isinstance(expected, dict):
            # 支持复杂匹配，如 {"contains": "pattern"}
            if "contains" in expected:
                return expected["contains"] in actual
            if "regex" in expected:
                return bool(re.search(expected["regex"], actual))
            return False
        if isinstance(expected, list):
            return actual in expected
        # 字符串比较，忽略大小写和空行
        return str(actual).strip().lower() == str(expected).strip().lower()


if __name__ == "__main__":
    detector = ConfigDetector(rules_dir=os.path.join("..", "rules"))
    results = detector.detect()
    for r in results:
        print(r)
