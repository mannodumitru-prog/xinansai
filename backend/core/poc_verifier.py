"""
PoC 验证引擎 - 负责调度和调用本地 PoC 脚本进行漏洞深度验证。
"""
import os
import subprocess
import sys


class PocVerifier:
    """PoC 调度与验证引擎，根据 CVE 编号调用对应的本地验证脚本。"""

    def __init__(self):
        # pocs 目录位于 core/rules/pocs
        self.pocs_dir = os.path.join(os.path.dirname(__file__), "rules", "pocs")
        # Nuclei YAML 模板目录位于 core/rules/yaml_pocs
        self.yaml_pocs_dir = os.path.join(os.path.dirname(__file__), "rules", "yaml_pocs")

    def verify(self, cve_id: str, target_info: dict):
        """
        验证指定 CVE 是否影响目标软件。

        Args:
            cve_id: CVE 编号，格式如 'CVE-2021-3156'
            target_info: 目标信息字典，如 {'name': 'sudo', 'version': '1.8.31'}

        Returns:
            True  - 验证确认存在漏洞
            False - 验证确认不存在漏洞
            None  - 无本地脚本，保持疑似状态
        """
        # 路线 1（高优先级）：查找 Python 脚本
        poc_path = os.path.join(self.pocs_dir, f"{cve_id}.py")

        if os.path.exists(poc_path):
            print(f"[!] 走 Python 引擎调用: {cve_id}")

            try:
                target_version = target_info.get("version", "")
                result = subprocess.run(
                    [sys.executable, poc_path, "--target_version", target_version],
                    capture_output=True,
                    text=True,
                    timeout=15,
                )

                if result.returncode == 0 and "[VULN_STATUS]: VERIFIED_TRUE" in result.stdout:
                    return True
                return False

            except subprocess.TimeoutExpired:
                print(f"[!] {cve_id} Python 脚本执行超时（>15s），视为无法确认")
                return False
            except Exception as e:
                print(f"[!] {cve_id} Python 脚本执行异常: {e}")
                return False

        # 路线 2（量产武器库）：查找 Nuclei YAML 模板
        yaml_name = f"{cve_id.lower()}.yaml"
        yaml_path = os.path.join(self.yaml_pocs_dir, yaml_name)

        if os.path.exists(yaml_path):
            print(f"[!] 走 Nuclei 引擎调用: {cve_id}")

            try:
                target_url = target_info.get("url", "http://127.0.0.1")
                result = subprocess.run(
                    ["nuclei", "-t", yaml_path, "-u", target_url, "-silent"],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )

                if result.returncode == 0 and cve_id.lower() in result.stdout.lower():
                    return True
                return False

            except subprocess.TimeoutExpired:
                print(f"[!] {cve_id} Nuclei 模板执行超时（>30s），视为无法确认")
                return False
            except Exception as e:
                print(f"[!] {cve_id} Nuclei 模板执行异常: {e}")
                return False

        # 路线 3（兜底）：无验证脚本
        print(f"[?] 既没有 py 也没有 yaml，跳过 {cve_id} 深度验证")
        return None


if __name__ == "__main__":
    verifier = PocVerifier()

    # 测试用例 1：预期 True（低版本 sudo 存在漏洞）
    print("--- 测试用例 1 ---")
    res1 = verifier.verify("CVE-2021-3156", {"name": "sudo", "version": "1.8.31"})
    print(f"结果: {res1}\n")

    # 测试用例 2：预期 False（高版本已修复）
    print("--- 测试用例 2 ---")
    res2 = verifier.verify("CVE-2021-3156", {"name": "sudo", "version": "1.9.9"})
    print(f"结果: {res2}\n")

    # 测试用例 3：预期 None（无对应 PoC 脚本）
    print("--- 测试用例 3 ---")
    res3 = verifier.verify("CVE-9999-9999", {"name": "test", "version": "1.0"})
    print(f"结果: {res3}\n")
