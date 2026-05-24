#!/usr/bin/env python3
"""
提权风险检测器
检测危险的SUID文件、sudoers配置问题
"""

import os
import re
import subprocess
from typing import List, Dict, Any

try:
    from .base_detector import BaseDetector
except ImportError:
    import sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from base_detector import BaseDetector


class PrivilegeEscalationDetector(BaseDetector):
    """提权风险检测器"""

    def get_detector_name(self) -> str:
        return "privilege_escalation_detector"

    def get_rule_file(self) -> str:
        return "privilege_escalation_rules.json"

    def detect(self) -> List[Dict]:
        """执行提权风险检测"""
        vulnerabilities = []
        rules = self.rules.get("rules", [])
        if not rules:
            print("[WARN] 未加载到提权检测规则")
            return []

        print("[INFO] 开始提权风险检测...")

        # 1. 检测危险SUID文件
        dangerous_suid_rules = next(
            (r for r in rules if r.get("check_name") == "dangerous_suid_files"),
            None
        )
        if dangerous_suid_rules:
            suid_vulns = self._check_suid_files(dangerous_suid_rules)
            vulnerabilities.extend(suid_vulns)

        # 2. 检测sudoers配置问题
        sudoers_rules = next(
            (r for r in rules if r.get("check_name") == "sudoers_dangerous_config"),
            None
        )
        if sudoers_rules:
            sudoers_vulns = self._check_sudoers(sudoers_rules)
            vulnerabilities.extend(sudoers_vulns)

        print(f"[INFO] 提权风险检测完成，发现 {len(vulnerabilities)} 个问题")
        return vulnerabilities

    def _check_suid_files(self, rule: Dict) -> List[Dict]:
        """检查危险的SUID/SGID文件"""
        vulnerabilities = []
        dangerous_list = rule.get("dangerous_binaries", [])
        if not dangerous_list:
            return []

        try:
            # 查找所有SUID和SGID文件，放宽超时到 120 秒
            result = subprocess.run(
                ["find", "/", "-perm", "-4000", "-o", "-perm", "-2000", "-type", "f"],
                capture_output=True, text=True, timeout=120
            )
            suid_files = set(result.stdout.strip().splitlines())

            for suid_file in suid_files:
                base_name = os.path.basename(suid_file)
                if base_name in dangerous_list:
                    vuln = self.format_vulnerability(
                        vuln_id=f"PRIV-ESC-{base_name.upper()}",
                        title=f"危险SUID文件: {suid_file}",
                        severity=rule.get("severity", "high"),
                        category="privilege_escalation",
                        description=f"文件 {suid_file} 设置了SUID/SGID位，且属于高危可提权程序（如{base_name}），普通用户可借此提升至root权限。",
                        affected_target=suid_file,
                        remediation=rule.get("remediation", f"执行 `chmod u-s {suid_file}` 移除SUID位。"),
                        binary=base_name
                    )
                    vulnerabilities.append(vuln)
        except subprocess.TimeoutExpired:
            print("[WARN] SUID扫描超时(>120s)")
        except Exception as e:
            print(f"[ERROR] SUID扫描失败: {e}")

        return vulnerabilities

    def _check_sudoers(self, rule: Dict) -> List[Dict]:
        """检查sudoers配置中的危险项"""
        vulnerabilities = []
        dangerous_patterns = rule.get("dangerous_patterns", [])
        sudoers_path = "/etc/sudoers"

        if not os.path.exists(sudoers_path):
            return []

        try:
            with open(sudoers_path, "r") as f:
                content = f.read()

            for pattern in dangerous_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    vuln = self.format_vulnerability(
                        vuln_id="PRIV-ESC-SUDOERS",
                        title="sudoers配置存在提权风险",
                        severity=rule.get("severity", "high"),
                        category="privilege_escalation",
                        description=f"检测到危险配置: {pattern}，可能导致普通用户无需密码或绕过限制执行特权命令。",
                        affected_target=sudoers_path,
                        remediation=rule.get("remediation", "编辑/etc/sudoers，移除NOPASSWD或!authenticate等危险选项。"),
                        matched_pattern=pattern
                    )
                    vulnerabilities.append(vuln)
                    break  # 同一文件只报告一次
        except Exception as e:
            print(f"[ERROR] sudoers检查失败: {e}")

        return vulnerabilities


if __name__ == "__main__":
    detector = PrivilegeEscalationDetector(rules_dir=os.path.join("..", "rules"))
    results = detector.detect()
    for r in results:
        print(r)
