#!/usr/bin/env python3
"""
配置合规检测器
负责检查系统安全配置、内核参数、服务状态，以及提取静态配置文件中的指令。
"""

import os
import re
import subprocess
import shlex
import glob
from typing import List, Dict, Any

try:
    from .base_detector import BaseDetector
except ImportError:
    import sys
    import os.path as osp
    sys.path.insert(0, osp.dirname(osp.abspath(__file__)))
    from base_detector import BaseDetector


class ConfigDetector(BaseDetector):
    """配置合规检测器。"""

    def get_detector_name(self) -> str:
        return "config_detector"

    def get_rule_file(self) -> str:
        return "config_rules.json"

    def detect(self) -> List[Dict]:
        vulnerabilities = []
        rules = self.get_rules_list()
        if not rules:
            self.logger.warning("未加载到配置合规规则")
            return []

        self.logger.info("开始全局配置合规检查")

        for rule in rules:
            check_name = rule.get("check_name", "unknown_check")
            try:
                check_type = rule.get("check_type")
                target = rule.get("target")
                expected = rule.get("expected")
                directive = rule.get("directive")
                compare_mode = rule.get("compare_mode") or rule.get("expected_type")

                actual = self._perform_check(check_type, target, directive)
                passed = self._compare(actual, expected, compare_mode)

                if not passed:
                    vuln = self.format_vulnerability(
                        vuln_id=f"CONFIG-{str(check_name).replace(' ', '_').upper()}",
                        title=f"配置不合规: {check_name}",
                        severity=rule.get("severity", "medium"),
                        category=rule.get("category", "config"),
                        description=rule.get("description", ""),
                        affected_target=target or check_name,
                        remediation=rule.get("remediation", "请根据安全基线调整该配置。"),
                        check_name=check_name,
                        expected=expected,
                        actual=actual,
                        comparison=compare_mode or "auto",
                        verification_status=self.STATUS_VERIFIED,
                        verification_method="config_check",
                        evidence={"target": target, "actual": actual, "expected": expected},
                    )
                    vulnerabilities.append(vuln)
                    self.logger.info("配置不合规: %s, expected=%s, actual=%s", check_name, expected, actual)
            except Exception as e:
                self.logger.warning("检查失败: %s - %s", check_name, e)

        self.logger.info("配置合规检查完成，发现 %d 个问题", len(vulnerabilities))
        return vulnerabilities

    def _perform_check(self, check_type: str, target: str, directive: str = None) -> Any:
        if check_type == "file":
            return self._check_file_content(target)
        if check_type == "file_directive":
            return self._extract_directive_from_file(target, directive)
        if check_type == "command":
            return self._run_command(target)
        if check_type == "sysctl":
            return self._get_sysctl(target)
        if check_type == "service":
            return self._check_service_status(target)
        if check_type == "service_any":
            return self._check_any_service_status(target)
        if check_type == "file_permission":
            return self._get_file_permission(target)
        if check_type == "file_search":
            return self._search_files(target, directive)
        self.logger.warning("未知配置检查类型: %s", check_type)
        return None

    def _check_file_content(self, file_path: str) -> str:
        if not file_path or not os.path.exists(file_path):
            return "missing"
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                return f.read().strip()
        except Exception as e:
            self.logger.warning("读取文件失败 %s: %s", file_path, e)
            return "error"

    def _extract_directive_from_file(self, file_path: str, directive: str) -> str:
        if not directive:
            return "missing_directive_param"
        if not file_path or not os.path.exists(file_path):
            return "file_not_found"

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            patterns = [
                rf"^\s*{re.escape(directive)}\s+([^;#\n]+)",
                rf"^\s*{re.escape(directive)}\s*=\s*([^;#\n]+)",
                rf"^\s*{re.escape(directive)}\s+([^;#\n]+);",
            ]
            for pattern in patterns:
                match = re.search(pattern, content, re.MULTILINE | re.IGNORECASE)
                if match:
                    return match.group(1).strip()
            return "not_found"
        except Exception as e:
            self.logger.warning("提取配置指令失败 %s:%s - %s", file_path, directive, e)
            return "error"


    def _check_any_service_status(self, services: Any) -> str:
        """检查多个服务中是否至少有一个处于 active 状态，避免规则中使用 shell 的 ||。"""
        try:
            if isinstance(services, str):
                services = [item.strip() for item in re.split(r"[,;\\s]+", services) if item.strip()]
            if not isinstance(services, list) or not services:
                return "error"

            states = []
            for service in services:
                active_result = subprocess.run(
                    ["systemctl", "is-active", str(service)],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                active = active_result.stdout.strip() or active_result.stderr.strip() or "unknown"
                states.append(f"{service}={active}")
                if active == "active":
                    return f"active ({';'.join(states)})"
            return f"inactive ({';'.join(states)})"
        except Exception as e:
            self.logger.warning("多服务状态检查失败 %s: %s", services, e)
            return "error"

    def _get_file_permission(self, file_path: str) -> str:
        """安全获取文件权限，替代规则中的 stat shell 命令。"""
        try:
            if not file_path or not os.path.exists(file_path):
                return "not_found"
            return f"{os.stat(file_path).st_mode & 0o777:03o}"
        except Exception as e:
            self.logger.warning("文件权限检查失败 %s: %s", file_path, e)
            return "error"

    def _search_files(self, pattern: str, keyword: str = None) -> str:
        """在受控 glob 路径中搜索关键词，替代 grep/glob shell 命令。"""
        try:
            if not pattern:
                return "error"
            if not os.path.isabs(pattern):
                self.logger.warning("拒绝非绝对路径文件搜索规则: %s", pattern)
                return "unsafe_path"

            files = [p for p in glob.glob(pattern) if os.path.isfile(p)]
            if not files:
                return "not_found"

            keyword = keyword or ""
            matched = []
            for path in files[:50]:
                try:
                    with open(path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                    if not keyword or re.search(str(keyword), content, re.IGNORECASE):
                        matched.append(path)
                except Exception as e:
                    self.logger.warning("文件搜索读取失败 %s: %s", path, e)

            return "matched:" + ",".join(matched[:10]) if matched else "not_found"
        except Exception as e:
            self.logger.warning("文件搜索失败 %s: %s", pattern, e)
            return "error"


    def _run_command(self, cmd: str) -> str:
        """安全执行规则命令：拒绝 shell 元字符，避免规则注入。"""
        try:
            if not cmd:
                return "error"
            if re.search(r"[|;&`$<>]", cmd):
                self.logger.warning("拒绝执行包含 shell 元字符的规则命令: %s", cmd)
                return "unsafe_command"
            result = subprocess.run(shlex.split(cmd), capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                return result.stderr.strip() or "error"
            return result.stdout.strip()
        except Exception as e:
            self.logger.warning("命令检查失败: %s - %s", cmd, e)
            return "error"

    def _get_sysctl(self, param: str) -> str:
        try:
            result = subprocess.run(["sysctl", "-n", param], capture_output=True, text=True, timeout=5)
            if result.returncode != 0:
                return result.stderr.strip() or "error"
            return result.stdout.strip()
        except Exception as e:
            self.logger.warning("sysctl读取失败 %s: %s", param, e)
            return "error"

    def _check_service_status(self, service: str) -> str:
        try:
            enabled_result = subprocess.run(["systemctl", "is-enabled", service], capture_output=True, text=True, timeout=5)
            active_result = subprocess.run(["systemctl", "is-active", service], capture_output=True, text=True, timeout=5)
            enabled = enabled_result.stdout.strip() or enabled_result.stderr.strip() or "unknown"
            active = active_result.stdout.strip() or active_result.stderr.strip() or "unknown"
            return f"enabled={enabled},active={active}"
        except Exception as e:
            self.logger.warning("服务状态检查失败 %s: %s", service, e)
            return "unknown"

    def _compare(self, actual: Any, expected: Any, compare_mode: str = None) -> bool:
        if actual is None or actual in ["not_found", "file_not_found", "missing_directive_param", "error", "unsafe_command"]:
            return False

        actual_s = str(actual).strip()
        actual_l = actual_s.lower()

        if isinstance(expected, bool):
            truthy = ["yes", "on", "true", "1", "enabled", "active"]
            falsy = ["no", "off", "false", "0", "disabled", "inactive"]
            return (expected and actual_l in truthy) or ((not expected) and actual_l in falsy)

        if isinstance(expected, dict):
            if "equals" in expected:
                return actual_l == str(expected["equals"]).strip().lower()
            if "contains" in expected:
                return str(expected["contains"]).lower() in actual_l
            if "not_contains" in expected:
                return str(expected["not_contains"]).lower() not in actual_l
            if "regex" in expected:
                return bool(re.search(str(expected["regex"]), actual_s, re.IGNORECASE))
            if "greater" in expected:
                return self._to_float(actual_s) > float(expected["greater"])
            if "greater_equal" in expected:
                return self._to_float(actual_s) >= float(expected["greater_equal"])
            if "less" in expected:
                return self._to_float(actual_s) < float(expected["less"])
            if "less_equal" in expected:
                return self._to_float(actual_s) <= float(expected["less_equal"])
            return False

        if isinstance(expected, list):
            return actual_l in [str(item).strip().lower() for item in expected]

        if compare_mode:
            mode = compare_mode.lower()
            expected_s = str(expected).strip()
            if mode in ["equals", "eq"]:
                return actual_l == expected_s.lower()
            if mode == "contains":
                return expected_s.lower() in actual_l
            if mode == "regex":
                return bool(re.search(expected_s, actual_s, re.IGNORECASE))
            if mode in ["greater", "gt"]:
                return self._to_float(actual_s) > float(expected)
            if mode in ["greater_equal", "gte"]:
                return self._to_float(actual_s) >= float(expected)
            if mode in ["less", "lt"]:
                return self._to_float(actual_s) < float(expected)
            if mode in ["less_equal", "lte"]:
                return self._to_float(actual_s) <= float(expected)

        return actual_l == str(expected).strip().lower()

    def _to_float(self, value: str) -> float:
        match = re.search(r"-?\d+(?:\.\d+)?", str(value))
        if not match:
            raise ValueError(f"无法从 {value} 提取数值")
        return float(match.group(0))


if __name__ == "__main__":
    detector = ConfigDetector(rules_dir=os.path.join("..", "rules"))
    for item in detector.detect():
        print(item)
