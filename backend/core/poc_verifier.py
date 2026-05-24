"""
PoC 验证引擎 - 负责调度和调用本地 PoC 脚本进行漏洞深度验证。
"""
import os
import subprocess
import sys


class PocVerifier:
    """PoC 调度与验证引擎，根据 CVE 编号调用对应的本地验证脚本。"""

    def __init__(self):
        # pocs 目录位于当前文件所在目录下的 pocs 文件夹
        self.pocs_dir = os.path.join(os.path.dirname(__file__), "pocs")

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
        poc_path = os.path.join(self.pocs_dir, f"{cve_id}.py")

        if not os.path.exists(poc_path):
            print(f"[?] 未找到 {cve_id} 的本地验证脚本，跳过深度验证")
            return None

        print(f"[!] 找到 {cve_id} 验证脚本，开始调用...")

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
            print(f"[!] {cve_id} 验证脚本执行超时（>15s），视为无法确认")
            return False
        except Exception as e:
            print(f"[!] {cve_id} 验证脚本执行异常: {e}")
            return False


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
