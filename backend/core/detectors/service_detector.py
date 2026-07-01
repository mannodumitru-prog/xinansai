#!/usr/bin/env python3
"""
动态服务与中间件检测器 (Nuclei 网络雷达)
专职负责提取主机存活端口，进行 HTTP 指纹识别，并调度 Nuclei 引擎进行 YAML 网络实锤漏洞验证
"""

import os
import re
import sys
import subprocess
import urllib.request
import urllib.error
import ssl
from typing import List, Dict, Any, Optional

try:
    from .base_detector import BaseDetector
except ImportError:
    import os.path as osp
    sys.path.insert(0, osp.dirname(osp.abspath(__file__)))
    from base_detector import BaseDetector

# 动态获取当前文件 (detector) 所在目录的父目录 (即 core 目录)
current_dir = os.path.dirname(os.path.abspath(__file__))
core_dir = os.path.dirname(current_dir)

# 将 core 目录安全地加入系统的环境变量中
if core_dir not in sys.path:
    sys.path.insert(0, core_dir)

# 现在可以直接导入了，IDE 既不会画红线，运行也不会报错！
try:
    from poc_verifier import PocVerifier
except ImportError as e:
    print(f"⚠️ 无法导入 PocVerifier: {e}")


# ============================================================
# HTTP 指纹特征库
# 用于在进程名相同（如均为 java）的情况下区分具体组件
# 格式：{ fingerprint_key : [出现在 title/body/header 中即视为命中的关键词] }
# ============================================================
FINGERPRINT_SIGNATURES: Dict[str, List[str]] = {
    "tongweb":  ["tongweb", "东方通"],
    "dameng":   ["dmserver", "达梦", "dameng"],
    "kingbase": ["kingbase", "人大金仓"],
    "tomcat":   ["apache tomcat", "tomcat"],
    "nginx":    ["nginx"],
    "spring":   ["whitelabel error page", "springframework", "spring boot"],
}


class ServiceDetector(BaseDetector):
    """动态服务网络雷达检测器"""

    def __init__(self, rules_dir: str = "core/rules"):
        super().__init__(rules_dir)
        try:
            self.verifier = PocVerifier()
        except Exception as e:
            print(f"⚠️ PocVerifier 初始化失败，将跳过网络服务实锤: {e}")
            self.verifier = None

    def get_detector_name(self) -> str:
        return "service_detector"

    def get_rule_file(self) -> str:
        return "service_rules.json"

    def detect(self) -> List[Dict]:
        """执行网络服务存活探测、指纹识别与 Nuclei 验证"""
        vulnerabilities = []
        rules = self.rules.get("rules", [])

        print("[INFO] 📡 启动网络雷达，探测存活服务与端口...")
        live_services = self._get_live_services()

        if not live_services:
            print("[WARN] 未探测到任何对外开放的网络服务")
            return []

        # 对每个存活服务做一次 HTTP 指纹识别，覆盖进程名不可靠的情况
        for service in live_services:
            service["fingerprint"] = self._fingerprint_service(service["url"])

        print(f"[INFO] 🎯 锁定 {len(live_services)} 个存活网络目标，准备接入 Nuclei 武器库")

        for service in live_services:
            match_key = service["fingerprint"] or service["name"]

            for rule in rules:
                target_app = rule.get("target_app", "").lower()
                # 优先用指纹匹配，指纹未命中时回退到进程名匹配
                if target_app and target_app != match_key and target_app != service["name"]:
                    continue

                cve_id = rule.get("cve_id")
                if not cve_id:
                    continue

                try:
                    verify_result = None
                    if self.verifier:
                        verify_result = self.verifier.verify(
                            cve_id=cve_id,
                            target_info=service,
                            target_type="yaml_pocs"
                        )

                    if verify_result is True:
                        vuln = self.format_vulnerability(
                            vuln_id=cve_id,
                            title=f"🔴[实锤漏洞] {cve_id}: 发现高危网络服务漏洞",
                            severity=rule.get("severity", "critical"),
                            category="network_service",
                            description=f"{rule.get('description', '')}\n\n[实战战果]: Nuclei 已成功通过 {service['url']} 验证此漏洞。",
                            affected_target=f"{service['name']} ({service['port']} 端口, 指纹: {match_key})",
                            remediation=rule.get("remediation", "请立即打补丁或限制端口访问"),
                            verification_status="verified",
                            live_url=service['url']
                        )
                        vulnerabilities.append(vuln)

                    elif verify_result is None:
                        vuln = self.format_vulnerability(
                            vuln_id=cve_id,
                            title=f"🟡[疑似漏洞] {cve_id}: 存在潜在网络风险",
                            severity=rule.get("severity", "medium"),
                            category="network_service",
                            description=rule.get('description',
                                                 '端口处于开放状态，但本地武器库暂无该组件的 YAML 验证脚本。'),
                            affected_target=f"{service['name']} ({service['port']} 端口, 指纹: {match_key})",
                            remediation=rule.get("remediation", "建议进行人工排查"),
                            verification_status="unverified",
                            live_url=service['url']
                        )
                        vulnerabilities.append(vuln)

                except Exception as e:
                    print(f"  [ERROR] Nuclei 验证服务 {service['name']} 时出错: {e}")

        print(f"[INFO] 📡 网络实战探测完成，捕获 {len(vulnerabilities)} 个威胁")
        return vulnerabilities

    def _get_live_services(self) -> List[Dict]:
        """动态扫描当前系统对外开放的端口及服务进程"""
        live_services = []
        try:
            result = subprocess.run(
                ['ss', '-tulnp'],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode != 0:
                return []

            for line in result.stdout.split('\n')[1:]:
                if not line.strip():
                    continue
                parts = line.split()
                if len(parts) < 6:
                    continue

                port_str = parts[4].split(':')[-1]
                process_info = parts[6] if len(parts) > 6 else ""

                match = re.search(r'\"(.*?)\"', process_info)
                service_name = match.group(1).lower() if match else "unknown"

                if service_name in ["unknown", "sshd", "systemd"]:
                    continue

                protocol = "https" if port_str == "443" else "http"
                live_services.append({
                    "name": service_name,
                    "port": port_str,
                    "url": f"{protocol}://127.0.0.1:{port_str}"
                })
        except Exception:
            pass

        unique_services = {f"{s['name']}:{s['port']}": s for s in live_services}
        return list(unique_services.values())

    def _fingerprint_service(self, url: str) -> Optional[str]:
        """
        对存活端口发起一次轻量 HTTP 请求，提取 title/server header/响应体特征，
        用于在进程名相同（如均为 java）的情况下区分具体组件。
        识别失败返回 None，由调用方回退到进程名匹配。
        """
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            req = urllib.request.Request(url, headers={"User-Agent": "SecKeeper-Scanner/1.0"})
            with urllib.request.urlopen(req, timeout=3, context=ctx) as resp:
                server_header = resp.headers.get("Server", "")
                body = resp.read(4096).decode("utf-8", errors="ignore")

            haystack = f"{server_header} {body}".lower()

            for fp_key, keywords in FINGERPRINT_SIGNATURES.items():
                if any(kw.lower() in haystack for kw in keywords):
                    return fp_key

        except (urllib.error.URLError, urllib.error.HTTPError, ConnectionError, TimeoutError):
            pass
        except Exception:
            pass

        return None


if __name__ == "__main__":
    detector = ServiceDetector(rules_dir=os.path.join("..", "rules"))
    results = detector.detect()
    for r in results:
        print(r)