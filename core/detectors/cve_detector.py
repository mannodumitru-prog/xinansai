#!/usr/bin/env python3
"""
CVE漏洞检测器模块

功能：
1. 加载本地CVE规则库
2. 扫描系统已安装软件
3. 检测受影响的软件版本
4. 输出标准化漏洞结果
"""

import sys
import os
import subprocess
import re
from typing import List, Dict, Tuple

# 兼容两种运行方式
try:
    from .base_detector import BaseDetector
except ImportError:
    current_dir = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, current_dir)
    from base_detector import BaseDetector

# 安全导入 PoC 验证引擎
try:
    from ..poc_verifier import PocVerifier
except ImportError:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
    from poc_verifier import PocVerifier


class CveDetector(BaseDetector):
    """CVE漏洞检测器"""

    def __init__(self, rules_dir: str = "core/rules"):
        """初始化检测器并实例化PoC验证引擎"""
        super().__init__(rules_dir)
        self.verifier = PocVerifier()

    def get_detector_name(self) -> str:
        """返回检测器名称"""
        try:
            return "cve_detector"
        except Exception as e:
            print(f"❌ 获取检测器名称失败: {e}")
            return "unknown_detector"

    def get_rule_file(self) -> str:
        """返回规则文件名"""
        try:
            return "cve_rules.json"
        except Exception as e:
            print(f"❌ 获取规则文件失败: {e}")
            return ""

    def detect(self, software_list: List[Dict] = None) -> List[Dict]:
        """执行漏洞检测"""
        vulnerabilities = []

        try:
            rules = self.rules.get("rules", [])

            if not rules:
                print("⚠️ 未加载到任何CVE规则")
                return []

            if software_list is None:
                software_list = self._get_installed_software()

            print(f"📦 检测到 {len(software_list)} 个关键软件")

            for software in software_list:
                for rule in rules:
                    try:
                        if self._is_software_affected(software, rule):

                            # 调用 PoC 验证引擎进行"实锤"验证
                            verify_result = self.verifier.verify(rule["cve_id"], software)

                            if verify_result is False:
                                # 验证明确失败，可能打了补丁，消除误报
                                print(f"⚠️ 版本匹配但 PoC 验证失败，排除误报: {rule['cve_id']} → {software['name']}")
                                continue

                            if verify_result is True:
                                status_prefix = "🔴[实锤漏洞]"
                                ver_status = "verified"
                            else:
                                status_prefix = "🟡[疑似漏洞]"
                                ver_status = "unverified"

                            vulnerability = self.format_vulnerability(
                                vuln_id=rule["cve_id"],
                                title=f"{status_prefix} {rule['cve_id']}: {rule['description'][:100]}",
                                severity=rule["severity"],
                                category="cve",
                                description=rule["description"],
                                affected_target=f"{software['name']} {software['version']}",
                                remediation=rule["remediation"],
                                cvss_score=rule.get("cvss_score", 0.0),
                                references=rule.get("references", []),
                                published_date=rule.get("published_date", ""),
                                tags=rule.get("tags", []),
                                verification_status=ver_status
                            )

                            vulnerabilities.append(vulnerability)

                    except Exception as e:
                        print(f"⚠️ 规则匹配失败: {e}")

            print(f"✅ 漏洞检测完成，发现 {len(vulnerabilities)} 个漏洞")

            return vulnerabilities

        except Exception as e:
            print(f"❌ 漏洞检测失败: {e}")
            return []

    def _get_installed_software(self) -> List[Dict]:
        """获取系统已安装软件"""
        software_list = []

        try:
            # Debian / Ubuntu
            try:
                result = subprocess.run(
                    ['dpkg-query', '-W', '-f=${Package} ${Version}\n'],
                    capture_output=True,
                    text=True,
                    timeout=30
                )

                if result.returncode == 0:

                    for line in result.stdout.split('\n'):
                        line = line.strip()

                        if not line:
                            continue

                        try:
                            parts = line.split()

                            if len(parts) >= 2:
                                package_name = parts[0]
                                package_version = parts[1]

                                if self._is_critical_software(package_name):
                                    software_list.append({
                                        "name": package_name,
                                        "version": package_version
                                    })

                        except Exception as e:
                            print(f"⚠️ 软件解析失败: {e}")

            except Exception as e:
                print(f"⚠️ dpkg-query执行失败: {e}")

            # RPM 系统
            if not software_list:
                try:
                    result = subprocess.run(
                        ['rpm', '-qa', '--queryformat', '%{NAME} %{VERSION}\n'],
                        capture_output=True,
                        text=True,
                        timeout=30
                    )

                    if result.returncode == 0:

                        for line in result.stdout.split('\n'):
                            line = line.strip()

                            if not line:
                                continue

                            try:
                                parts = line.split()

                                if len(parts) >= 2:
                                    package_name = parts[0]
                                    package_version = parts[1]

                                    if self._is_critical_software(package_name):
                                        software_list.append({
                                            "name": package_name,
                                            "version": package_version
                                        })

                            except Exception as e:
                                print(f"⚠️ RPM软件解析失败: {e}")

                except Exception as e:
                    print(f"⚠️ rpm执行失败: {e}")

            # 兜底软件
            if not software_list:
                print("⚠️ 未检测到系统软件，使用兜底软件列表")

                software_list = [
                    {
                        "name": "openssl",
                        "version": "1.1.1f"
                    },
                    {
                        "name": "openssh-server",
                        "version": "8.9p1"
                    },
                    {
                        "name": "sudo",
                        "version": "1.9.5"
                    },
                    {
                        "name": "glibc",
                        "version": "2.35"
                    }
                ]

            return software_list

        except Exception as e:
            print(f"❌ 获取系统软件失败: {e}")

            return [
                {
                    "name": "openssl",
                    "version": "1.1.1f"
                },
                {
                    "name": "openssh-server",
                    "version": "8.9p1"
                }
            ]

    def _is_critical_software(self, package_name: str) -> bool:
        """判断是否为关键软件"""
        try:
            critical_keywords = [
                "openssl",
                "libssl",
                "kernel",
                "linux",
                "glibc",
                "libc",
                "python",
                "nginx",
                "apache2",
                "mysql",
                "postgresql",
                "php",
                "nodejs",
                "docker",
                "openssh",
                "log4j",
                "sudo",
                "polkit",
                "runc",
                "containerd"
            ]

            package_name = package_name.lower()

            for keyword in critical_keywords:
                if keyword in package_name:
                    return True

            return False

        except Exception as e:
            print(f"❌ 关键软件判断失败: {e}")
            return False

    def _is_software_affected(self, software: Dict, rule: Dict) -> bool:
        """判断软件是否受漏洞影响"""
        try:
            affected_list = rule.get("affected_software", [])

            for affected in affected_list:

                try:
                    affected_name = affected.get("name", "").lower()
                    software_name = software.get("name", "").lower()

                    if affected_name in software_name:

                        version_start = affected.get("version_start", "")
                        version_end = affected.get("version_end", "")

                        if self._check_version_range(
                            software["version"],
                            version_start,
                            version_end
                        ):
                            return True

                except Exception as e:
                    print(f"⚠️ 受影响软件匹配失败: {e}")

            return False

        except Exception as e:
            print(f"❌ 软件影响判断失败: {e}")
            return False

    def _check_version_range(
        self,
        installed: str,
        start: str,
        end: str
    ) -> bool:
        """检查版本范围"""
        try:
            installed_parsed = self._parse_version(installed)
            start_parsed = self._parse_version(start)
            end_parsed = self._parse_version(end)

            return start_parsed <= installed_parsed <= end_parsed

        except Exception as e:
            print(f"❌ 版本范围检查失败: {e}")
            return False

    def _parse_version(self, version_str: str) -> Tuple:
        """解析版本号"""
        try:
            numbers = re.findall(r'\d+', version_str)

            parsed = [int(num) for num in numbers]

            while len(parsed) < 4:
                parsed.append(0)

            return tuple(parsed[:4])

        except Exception as e:
            print(f"❌ 版本解析失败: {e}")
            return (0, 0, 0, 0)


if __name__ == "__main__":
    # 规则目录相对于项目根目录
    detector = CveDetector(rules_dir=os.path.join(os.path.dirname(__file__), "..", "rules"))
    print(f"检测器: {detector.get_detector_name()}")
    print(f"加载规则数: {len(detector.rules.get('rules', []))}")

    results = detector.detect()
    print(f"\n发现 {len(results)} 个漏洞:\n")
    for r in results:
        # 【修改这里】把 r['vuln_id'] 换成 r['title']，把状态也打印出来
        print(f"  [{r['severity'].upper()}] {r['title']}")
        print(f"      ↳ 目标: {r['affected_target']} | 状态: {r.get('verification_status', '未知')}\n")