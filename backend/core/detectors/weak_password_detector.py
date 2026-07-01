#!/usr/bin/env python3
"""
弱口令检测器
检查系统用户是否存在空密码、默认高风险账户或不符合要求的密码策略。

说明：Linux 本地无法直接获取明文密码，因此本检测器不会伪造“已破解弱口令”结论；
只对可验证事实上报：空密码、默认/高风险可登录账户、密码策略不合规。
"""

import os
import re
from typing import List, Dict

try:
    from .base_detector import BaseDetector
except ImportError:
    import sys
    import os.path as osp
    sys.path.insert(0, osp.dirname(osp.abspath(__file__)))
    from base_detector import BaseDetector


DEFAULT_RISK_USERS = {
    "admin", "test", "guest", "oracle", "mysql", "postgres", "tomcat",
    "ftp", "www", "www-data", "deploy", "dev", "user"
}


class WeakPasswordDetector(BaseDetector):
    """弱口令/账户策略检测器。"""

    def get_detector_name(self) -> str:
        return "weak_password_detector"

    def get_rule_file(self) -> str:
        return "weak_password_rules.json"

    def detect(self) -> List[Dict]:
        vulnerabilities = []
        rules = self.get_rules_list()
        if not rules:
            self.logger.warning("未加载到弱口令规则")
            return []

        self.logger.info("开始弱口令与密码策略检测")
        users = self._get_system_users()
        self.logger.info("检测到 %d 个可登录用户", len(users))

        empty_pass_users = self._check_empty_password(users)
        for user in empty_pass_users:
            vulnerabilities.append(self._create_weak_password_vuln(
                user=user,
                title="空密码账户",
                desc="该用户在 /etc/shadow 中密码字段为空，存在严重安全风险。",
                severity="critical",
                remediation="使用 passwd 命令为该账户设置强密码，或锁定/删除不必要账户。",
                verification_status=self.STATUS_VERIFIED,
                verification_method="shadow_empty_password_check",
            ))

        risk_users = self._get_default_risk_users_from_rules()
        for user in users:
            if user in empty_pass_users:
                continue
            if user.lower() in risk_users:
                vulnerabilities.append(self._create_weak_password_vuln(
                    user=user,
                    title=f"默认/高风险可登录账户: {user}",
                    desc=(f"检测到默认或高风险账户 {user} 具有登录能力。"
                          "本项不代表已确认其密码为弱口令，但该类账户常被暴力破解，建议重点核查。"),
                    severity="medium",
                    remediation="确认该账户是否必要；如不必要应禁用，必要时应启用强密码和登录审计。",
                    verification_status=self.STATUS_NEEDS_MANUAL_CHECK,
                    verification_method="login_account_name_check",
                ))

        for check in rules:
            if check.get("check_name") == "password_policy":
                passed, evidence = self._check_password_policy(check.get("expected", {}))
                if not passed:
                    vulnerabilities.append(self.format_vulnerability(
                        vuln_id="WEAK-POLICY-001",
                        title="密码策略不合规",
                        severity=check.get("severity", "medium"),
                        category="weak_password",
                        description=check.get("description", "密码复杂度或长度要求未满足"),
                        affected_target="系统密码策略",
                        remediation=check.get("remediation", "配置 pam_pwquality 模块，设置最小长度和复杂度要求。"),
                        details=check,
                        evidence=evidence,
                        verification_status=self.STATUS_VERIFIED,
                        verification_method="pam_password_policy_check",
                    ))

        self.logger.info("弱口令检测完成，发现 %d 个问题", len(vulnerabilities))
        return vulnerabilities

    def _get_system_users(self) -> List[str]:
        """获取所有可登录用户。"""
        users = []
        nologin_shells = {"/sbin/nologin", "/bin/false", "/usr/sbin/nologin"}
        try:
            with open("/etc/passwd", "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    parts = line.strip().split(":")
                    if len(parts) >= 7:
                        username, _, uid, _, _, _, shell = parts[:7]
                        if uid.isdigit() and (int(uid) >= 1000 or username == "root") and shell not in nologin_shells:
                            users.append(username)
        except Exception as e:
            self.logger.warning("无法读取 /etc/passwd: %s", e)
        return users

    def _check_empty_password(self, users: List[str]) -> List[str]:
        """检查真正空密码账户。'!', '!!', '*' 是锁定标记，不作为空密码。"""
        empty_users = []
        try:
            with open("/etc/shadow", "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    parts = line.strip().split(":")
                    if len(parts) >= 2:
                        user, pwd = parts[0], parts[1]
                        if user in users and pwd == "":
                            empty_users.append(user)
        except PermissionError:
            self.logger.warning("无权限读取 /etc/shadow，空密码检查跳过；建议以 root 权限运行巡检。")
        except Exception as e:
            self.logger.warning("读取 /etc/shadow 失败: %s", e)
        return empty_users

    def _get_default_risk_users_from_rules(self) -> set:
        configured = self.rules.get("default_risk_users") if isinstance(self.rules, dict) else None
        weak_dict = self.rules.get("weak_password_dict") if isinstance(self.rules, dict) else None
        result = set(DEFAULT_RISK_USERS)
        if isinstance(configured, list):
            result.update(str(x).lower() for x in configured)
        # 兼容旧规则：只取明显像“账户名”的条目，不再把任意弱密码字典等同为账户风险。
        if isinstance(weak_dict, list):
            result.update(str(x).lower() for x in weak_dict if str(x).lower() in DEFAULT_RISK_USERS)
        return result

    def _check_password_policy(self, expected: Dict) -> tuple:
        min_len = int(expected.get("min_length", 8))
        required_classes = int(expected.get("min_classes", 3))
        evidence = {"expected_min_length": min_len, "expected_min_classes": required_classes}

        try:
            content = ""
            source = None
            for path in ["/etc/security/pwquality.conf", "/etc/pam.d/common-password", "/etc/pam.d/system-auth"]:
                if os.path.exists(path):
                    with open(path, "r", encoding="utf-8", errors="ignore") as f:
                        content += "\n" + f.read()
                    source = path if source is None else source + "," + path

            if not content:
                evidence["reason"] = "未找到可检查的 PAM 密码策略配置文件"
                return False, evidence

            evidence["source"] = source
            minlen_match = re.search(r"^\s*minlen\s*=\s*(\d+)", content, re.MULTILINE)
            actual_minlen = int(minlen_match.group(1)) if minlen_match else 0
            evidence["actual_min_length"] = actual_minlen
            if actual_minlen < min_len:
                evidence["reason"] = "密码最小长度不足"
                return False, evidence

            class_keys = ["dcredit", "ucredit", "lcredit", "ocredit"]
            configured_classes = sum(1 for key in class_keys if re.search(rf"^\s*{key}\s*=\s*-?\d+", content, re.MULTILINE))
            evidence["configured_class_items"] = configured_classes
            if required_classes > 1 and configured_classes == 0:
                evidence["reason"] = "未发现字符类别复杂度配置"
                return False, evidence

            return True, evidence
        except Exception as e:
            self.logger.warning("密码策略检查失败: %s", e)
            evidence["error"] = str(e)
            return False, evidence

    def _create_weak_password_vuln(
        self,
        user: str,
        title: str,
        desc: str,
        severity: str,
        remediation: str,
        verification_status: str,
        verification_method: str,
    ) -> Dict:
        return self.format_vulnerability(
            vuln_id=f"WEAK-PASS-{user}",
            title=title,
            severity=severity,
            category="weak_password",
            description=desc,
            affected_target=f"用户账户: {user}",
            remediation=remediation,
            username=user,
            verification_status=verification_status,
            verification_method=verification_method,
            evidence={"username": user},
        )


if __name__ == "__main__":
    detector = WeakPasswordDetector(rules_dir=os.path.join("..", "rules"))
    for item in detector.detect():
        print(item)
