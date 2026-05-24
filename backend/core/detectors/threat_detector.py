#!/usr/bin/env python3
"""
恶意行为/后门排查检测器
检查定时任务后门、SSH后门公钥、可疑文件
"""

import os
import re
import subprocess
import pwd
from datetime import datetime, timedelta
from typing import List, Dict, Any

try:
    from .base_detector import BaseDetector
except ImportError:
    import sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from base_detector import BaseDetector


class ThreatDetector(BaseDetector):
    """恶意行为/后门排查检测器"""

    def get_detector_name(self) -> str:
        return "threat_detector"

    def get_rule_file(self) -> str:
        return "threat_rules.json"

    def detect(self) -> List[Dict]:
        """执行后门排查"""
        vulnerabilities = []
        rules = self.rules.get("rules", [])
        if not rules:
            print("[WARN] 未加载到威胁检测规则")
            return []

        print("[INFO] 开始后门排查检测...")

        cron_rules = next((r for r in rules if r.get("check_name") == "suspicious_cron"), None)
        if cron_rules:
            vulnerabilities.extend(self._check_cron_jobs(cron_rules))

        ssh_rules = next((r for r in rules if r.get("check_name") == "unauthorized_ssh_keys"), None)
        if ssh_rules:
            vulnerabilities.extend(self._check_ssh_keys(ssh_rules))

        recent_suid_rules = next((r for r in rules if r.get("check_name") == "recent_suid_files"), None)
        if recent_suid_rules:
            vulnerabilities.extend(self._check_recent_suid(recent_suid_rules))

        tmp_rules = next((r for r in rules if r.get("check_name") == "suspicious_tmp_executables"), None)
        if tmp_rules:
            vulnerabilities.extend(self._check_tmp_executables(tmp_rules))

        print(f"[INFO] 后门排查检测完成，发现 {len(vulnerabilities)} 个问题")
        return vulnerabilities

    def _check_cron_jobs(self, rule: Dict) -> List[Dict]:
        """检查定时任务中的可疑命令（精确到文件级别）"""
        vulnerabilities = []
        suspicious_keywords = rule.get("suspicious_keywords", [])
        cron_locations = [
            "/etc/crontab",
            "/etc/cron.d/",
            "/etc/cron.daily/",
            "/etc/cron.hourly/",
            "/etc/cron.weekly/",
            "/etc/cron.monthly/"
        ]
        
        try:
            for user in pwd.getpwall():
                # 必须包含 root 和 uid >= 1000 的用户
                if user.pw_uid >= 1000 or user.pw_name == "root":
                    result = subprocess.run(
                        ["crontab", "-l", "-u", user.pw_name],
                        capture_output=True, text=True, timeout=10
                    )
                    if result.returncode == 0:
                        cron_locations.append(f"crontab:{user.pw_name}")
        except Exception:
            pass

        for location in cron_locations:
            try:
                targets_to_check = {}  # 字典 {文件/位置标识: 文件内容}
                
                if location.startswith("crontab:"):
                    user = location.split(":")[1]
                    result = subprocess.run(["crontab", "-l", "-u", user], capture_output=True, text=True)
                    if result.returncode == 0:
                        targets_to_check[location] = result.stdout
                elif os.path.isdir(location):
                    for file in os.listdir(location):
                        file_path = os.path.join(location, file)
                        if os.path.isfile(file_path):
                            with open(file_path, "r") as f:
                                targets_to_check[file_path] = f.read()
                elif os.path.isfile(location):
                    with open(location, "r") as f:
                        targets_to_check[location] = f.read()

                # 精确检测具体文件
                for target_path, content in targets_to_check.items():
                    for keyword in suspicious_keywords:
                        if re.search(keyword, content, re.IGNORECASE):
                            vuln = self.format_vulnerability(
                                vuln_id="THREAT-SUSPICIOUS-CRON",
                                title="发现可疑定时任务",
                                severity=rule.get("severity", "high"),
                                category="backdoor",
                                description=f"在 [{target_path}] 中发现包含危险关键词 '{keyword}' 的命令，可能是后门或持久化机制。",
                                affected_target=target_path,
                                remediation=rule.get("remediation", "检查并删除可疑的cron条目。"),
                                keyword=keyword
                            )
                            vulnerabilities.append(vuln)
                            break  # 该文件已命中，不再验证其他关键词
            except Exception as e:
                pass # 忽略读取失败的文件

        return vulnerabilities

    def _check_ssh_keys(self, rule: Dict) -> List[Dict]:
        """检查SSH authorized_keys中是否存在异常公钥"""
        vulnerabilities = []
        home_dirs = []
        try:
            for user in pwd.getpwall():
                if user.pw_uid >= 1000 or user.pw_name == "root":
                    home_dirs.append((user.pw_name, user.pw_dir))
        except Exception:
            home_dirs = [("root", "/root")]

        for username, home in home_dirs:
            key_file = os.path.join(home, ".ssh", "authorized_keys")
            if os.path.exists(key_file):
                try:
                    with open(key_file, "r") as f:
                        keys = f.read().strip()
                    if keys and not self._is_expected_keys(username, keys):
                        vuln = self.format_vulnerability(
                            vuln_id="THREAT-SSH-BACKDOOR",
                            title=f"用户 {username} 的SSH公钥可能存在后门",
                            severity=rule.get("severity", "high"),
                            category="backdoor",
                            description=f"检测到 {key_file} 中存在异常的大量公钥，可能被植入后门免密登录。",
                            affected_target=key_file,
                            remediation=rule.get("remediation", "删除可疑公钥，并重新生成SSH密钥对。"),
                            user=username
                        )
                        vulnerabilities.append(vuln)
                except Exception:
                    pass

        return vulnerabilities

    def _is_expected_keys(self, username: str, keys: str) -> bool:
        # 简单策略：行数过多即示警
        if len(keys.splitlines()) > 3:
            return False
        return True

    def _check_recent_suid(self, rule: Dict) -> List[Dict]:
        """检查最近24小时内新增的SUID文件"""
        vulnerabilities = []
        threshold = datetime.now() - timedelta(hours=24)
        try:
            # 同样放宽搜索超时时间
            result = subprocess.run(
                ["find", "/", "-perm", "-4000", "-type", "f", "-printf", "%T@ %p\\n"],
                capture_output=True, text=True, timeout=120
            )
            for line in result.stdout.strip().splitlines():
                if not line: continue
                parts = line.split(" ", 1)
                if len(parts) != 2: continue
                
                timestamp = float(parts[0])
                file_path = parts[1]
                ctime = datetime.fromtimestamp(timestamp)
                
                if ctime > threshold:
                    vuln = self.format_vulnerability(
                        vuln_id="THREAT-RECENT-SUID",
                        title="最近新增的SUID文件",
                        severity=rule.get("severity", "medium"),
                        category="backdoor",
                        description=f"文件 {file_path} 在最近24小时内被设置了SUID位，可能是攻击者放置的后门程序。",
                        affected_target=file_path,
                        remediation=rule.get("remediation", "检查文件来源，如非必须使用 `chmod u-s` 移除。"),
                        creation_time=ctime.isoformat()
                    )
                    vulnerabilities.append(vuln)
        except Exception:
            pass

        return vulnerabilities

    def _check_tmp_executables(self, rule: Dict) -> List[Dict]:
        """检查/tmp目录中的可执行文件"""
        vulnerabilities = []
        try:
            result = subprocess.run(
                ["find", "/tmp", "-type", "f", "-executable"],
                capture_output=True, text=True, timeout=30
            )
            for file_path in result.stdout.strip().splitlines():
                if file_path:
                    vuln = self.format_vulnerability(
                        vuln_id="THREAT-TMP-EXEC",
                        title="/tmp目录中存在可执行文件",
                        severity=rule.get("severity", "medium"),
                        category="backdoor",
                        description=f"临时目录 {file_path} 中存在可执行文件，可能是恶意软件或临时后门。",
                        affected_target=file_path,
                        remediation=rule.get("remediation", "审查文件内容，如非必要请立即删除。")
                    )
                    vulnerabilities.append(vuln)
        except Exception:
            pass

        return vulnerabilities


if __name__ == "__main__":
    detector = ThreatDetector(rules_dir=os.path.join("..", "rules"))
    results = detector.detect()
    for r in results:
        print(r)
