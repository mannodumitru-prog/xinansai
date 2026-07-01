#!/usr/bin/env python3
"""
配置合规检测器 (全能融合版)
负责检查系统安全配置、内核参数、服务状态，以及提取静态配置文件中的指令（如 SSH, Nginx 配置）
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
        # 你可以将原来的 config_rules.json 和 service_rules.json 合并到这里
        return "config_rules.json"

    def detect(self) -> List[Dict]:
        """执行配置合规检查"""
        vulnerabilities = []
        rules = self.rules.get("rules", [])
        if not rules:
            print("[WARN] 未加载到配置合规规则")
            return []

        print("[INFO] 🛠️ 开始全局配置合规检查...")

        for rule in rules:
            try:
                check_name = rule.get("check_name")
                # 核心升级：支持 file, command, sysctl, service, 以及新增的 file_directive
                check_type = rule.get("check_type")
                target = rule.get("target")
                expected = rule.get("expected")
                directive = rule.get("directive")  # 针对 file_directive 模式

                severity = rule.get("severity", "medium")
                category = rule.get("category", "config")
                description = rule.get("description", "")
                remediation = rule.get("remediation", "")

                # 执行检测
                actual = self._perform_check(check_type, target, directive)
                passed = self._compare(actual, expected)

                if not passed:
                    vuln = self.format_vulnerability(
                        vuln_id=f"CONFIG-{check_name.replace(' ', '_').upper()}",
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

        print(f"[INFO] 🛠️ 配置合规检查完成，发现 {len(vulnerabilities)} 个问题")
        return vulnerabilities

    def _perform_check(self, check_type: str, target: str, directive: str = None) -> Any:
        """执行具体检查分发"""
        if check_type == "file":
            return self._check_file_content(target)
        elif check_type == "file_directive":
            # 接管原 service_detector 的静态文件指令提取功能
            return self._extract_directive_from_file(target, directive)
        elif check_type == "command":
            return self._run_command(target)
        elif check_type == "sysctl":
            return self._get_sysctl(target)
        elif check_type == "service":
            return self._check_service_status(target)
        else:
            return None

    def _check_file_content(self, file_path: str) -> str:
        """直接读取整个文件内容（用于简单比对）"""
        if not os.path.exists(file_path):
            return "missing"
        try:
            with open(file_path, "r") as f:
                return f.read().strip()
        except Exception:
            return "error"

    def _extract_directive_from_file(self, file_path: str, directive: str) -> str:
        """
        [新增核心能力] 从配置文件中提取特定指令的值
        例如从 /etc/ssh/sshd_config 提取 PermitRootLogin 的值
        """
        if not directive:
            return "missing_directive_param"
        if not os.path.exists(file_path):
            return "file_not_found"

        try:
            with open(file_path, "r") as f:
                content = f.read()

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
        except Exception:
            return "error"

    def _run_command(self, cmd: str) -> str:
        """执行命令并返回输出"""
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
        """检查系统服务是否启用并运行"""
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
        """安全比较实际值与期望值"""
        if actual is None or actual in ["not_found", "file_not_found", "missing_directive_param"]:
            return False

        # 布尔值特殊处理 (例如期望 True，实际读取到的是 "yes" 或 "on")
        if isinstance(expected, bool):
            return (expected and str(actual).lower() in ["yes", "on", "true", "1"]) or \
                (not expected and str(actual).lower() in ["no", "off", "false", "0"])

        if isinstance(expected, dict):
            if "contains" in expected:
                return expected["contains"] in str(actual)
            if "regex" in expected:
                return bool(re.search(expected["regex"], str(actual)))
            return False

        if isinstance(expected, list):
            return actual in expected

        return str(actual).strip().lower() == str(expected).strip().lower()


if __name__ == "__main__":
    detector = ConfigDetector(rules_dir=os.path.join("..", "rules"))
    results = detector.detect()
    for r in results:
        print(r)