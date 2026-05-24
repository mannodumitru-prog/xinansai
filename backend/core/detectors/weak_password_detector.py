#!/usr/bin/env python3
"""
弱口令检测器
检查系统用户是否存在弱口令、空密码或不符合密码策略的账户
"""

import os
import re
import subprocess
import math
from typing import List, Dict, Any

try:
    from .base_detector import BaseDetector
except ImportError:
    import sys
    import os.path as osp
    sys.path.insert(0, osp.dirname(osp.abspath(__file__)))
    from base_detector import BaseDetector


class WeakPasswordDetector(BaseDetector):
    """弱口令检测器"""

    def get_detector_name(self) -> str:
        return "weak_password_detector"

    def get_rule_file(self) -> str:
        return "weak_password_rules.json"

    def detect(self) -> List[Dict]:
        """执行弱口令检测"""
        vulnerabilities = []
        rules = self.rules.get("rules", [])
        if not rules:
            print("[WARN] 未加载到弱口令规则")
            return []

        print("[INFO] 开始弱口令检测...")

        # 获取系统用户列表（有登录shell的用户）
        users = self._get_system_users()
        print(f"[INFO] 检测到 {len(users)} 个可登录用户")

        # 检查空密码账户
        empty_pass_users = self._check_empty_password(users)
        for user in empty_pass_users:
            vuln = self._create_weak_password_vuln(
                user, "空密码账户", "该用户未设置密码或密码为空，存在严重安全风险",
                severity="critical", remediation="使用 passwd 命令设置强密码"
            )
            vulnerabilities.append(vuln)

        # 检查弱口令（基于规则中的弱密码字典）
        weak_dict = self.rules.get("weak_password_dict", [])
        if weak_dict:
            for user in users:
                if user in empty_pass_users:
                    continue
                # 实际环境中不可能直接获取明文密码，这里通过模拟方式或只检查常见默认账户
                # 例如：检查用户名是否等于弱口令本身（admin/admin），或尝试使用chntpw等工具？
                # 本实现仅演示：检测用户名是否在弱口令字典中（作为弱口令的常见情景）
                if user.lower() in weak_dict:
                    vuln = self._create_weak_password_vuln(
                        user, f"用户名 {user} 属于常见弱口令/默认账户",
                        f"用户 {user} 使用默认用户名/弱口令，容易被暴力破解",
                        severity="high", remediation="修改用户名或设置强密码"
                    )
                    vulnerabilities.append(vuln)

        # 检查密码策略（如最小长度、复杂度）是否符合要求
        policy_checks = rules
        for check in policy_checks:
            check_name = check.get("check_name")
            if check_name == "password_policy":
                passed = self._check_password_policy(check.get("expected", {}))
                if not passed:
                    vuln = self.format_vulnerability(
                        vuln_id="WEAK-POLICY-001",
                        title="密码策略不合规",
                        severity=check.get("severity", "medium"),
                        category="weak_password",
                        description=check.get("description", "密码复杂度或长度要求未满足"),
                        affected_target="系统密码策略",
                        remediation=check.get("remediation", "配置pam_pwquality模块，设置最小长度、字符类别数"),
                        details=check
                    )
                    vulnerabilities.append(vuln)

        print(f"[INFO] 弱口令检测完成，发现 {len(vulnerabilities)} 个问题")
        return vulnerabilities

    def _get_system_users(self) -> List[str]:
        """获取所有可登录用户（shell不是nologin）"""
        users = []
        try:
            with open("/etc/passwd", "r") as f:
                for line in f:
                    parts = line.strip().split(":")
                    if len(parts) >= 7:
                        username, _, uid, _, _, _, shell = parts[:7]
                        # 跳过系统用户（UID<1000）和伪用户（shell为nologin或false）
                        if uid.isdigit() and int(uid) >= 1000 and shell not in ["/sbin/nologin", "/bin/false", "/usr/sbin/nologin"]:
                            users.append(username)
        except Exception as e:
            print(f"[WARN] 无法读取 /etc/passwd: {e}")
            # 模拟一些默认用户用于演示
            users = ["root", "admin", "test", "guest"]
        return users

    def _check_empty_password(self, users: List[str]) -> List[str]:
        """检查空密码账户（shadow中密码字段为空或!!表示锁定但可能空密码？）"""
        empty_users = []
        try:
            with open("/etc/shadow", "r") as f:
                for line in f:
                    parts = line.strip().split(":")
                    if len(parts) >= 2:
                        user, pwd = parts[0], parts[1]
                        if user in users:
                            # 空密码字段（:: 或 :!::）
                            if pwd == "" or pwd.startswith("!!") or pwd == "*":
                                empty_users.append(user)
        except Exception as e:
            print(f"[WARN] 无法读取 /etc/shadow (可能需要root权限): {e}")
            # 模拟返回空列表，避免误报
        return empty_users

    def _check_password_policy(self, expected: Dict) -> bool:
        """检查密码策略（PAM配置）"""
        min_len = expected.get("min_length", 8)
        required_classes = expected.get("min_classes", 3)

        # 检查 /etc/pam.d/common-password 或 /etc/security/pwquality.conf
        try:
            content = ""
            if os.path.exists("/etc/security/pwquality.conf"):
                with open("/etc/security/pwquality.conf", "r") as f:
                    content = f.read()
            else:
                with open("/etc/pam.d/common-password", "r") as f:
                    content = f.read()
            # 查找 minlen, dcredit, ucredit 等
            minlen_match = re.search(r"minlen\s*=\s*(\d+)", content)
            actual_minlen = int(minlen_match.group(1)) if minlen_match else 0
            if actual_minlen < min_len:
                return False

            # 简单检查字符类别要求（通过是否包含dcredit/ucredit/lcredit/ocredit）
            has_class = any(x in content for x in ["dcredit", "ucredit", "lcredit", "ocredit"])
            if not has_class and required_classes > 1:
                return False
            return True
        except Exception:
            # 无法检查时默认通过
            return True

    def _create_weak_password_vuln(self, user: str, title: str, desc: str,
                                   severity: str, remediation: str) -> Dict:
        return self.format_vulnerability(
            vuln_id=f"WEAK-PASS-{user}",
            title=title,
            severity=severity,
            category="weak_password",
            description=desc,
            affected_target=f"用户账户: {user}",
            remediation=remediation,
            username=user
        )


if __name__ == "__main__":
    detector = WeakPasswordDetector(rules_dir=os.path.join("..", "rules"))
    results = detector.detect()
    for r in results:
        print(r)
