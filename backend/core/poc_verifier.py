"""
PoC 验证引擎 - 负责调度和调用本地 PoC 脚本进行漏洞深度验证。
"""
import os
import subprocess
import sys
import platform


class PocVerifier:
    """PoC 调度与验证引擎，根据 CVE 编号调用对应的本地验证脚本。"""

    def __init__(self):
        base_dir = os.path.dirname(os.path.abspath(__file__))

        self.pocs_dir = os.path.join(base_dir, "rules", "pocs")
        self.yaml_pocs_dir = os.path.join(base_dir, "rules", "yaml_pocs")

        current_os = platform.system()
        tool_name = "nuclei.exe" if current_os == "Windows" else "nuclei"
        self.nuclei_bin = os.path.join(base_dir, "tools", tool_name)

        print(f"[DEBUG] SecKeeper 验证引擎已初始化")
        print(f"[DEBUG] 部署环境: {current_os}")
        print(f"[DEBUG] 挂载 Nuclei 路径: {self.nuclei_bin}")
        print(f"[DEBUG] 工具状态检测: {'正常就绪' if os.path.exists(self.nuclei_bin) else '未找到文件，请检查 tools 目录！'}")

    def verify(self, cve_id: str, target_info: dict, target_type: str = "pocs"):
        """
        target_type:
          "pocs"   -> 只走本地 Python PoC（cve_detector / privilege_escalation_detector 使用）
          "yaml_pocs" -> 只走 Nuclei YAML（service_detector 使用）
        """
        if target_type == "pocs":
            return self._verify_local(cve_id, target_info)
        elif target_type == "yaml_pocs":
            return self._verify_network(cve_id, target_info)

        # 兜底：未指定类型时，先本地后网络
        result = self._verify_local(cve_id, target_info)
        if result is not None:
            return result
        return self._verify_network(cve_id, target_info)

    # ----------------------------------------------------------------
    # 路线 1：本地 Python PoC（真正执行，不再是文件存在即 True）
    # ----------------------------------------------------------------
    def _verify_local(self, cve_id: str, target_info: dict):
        poc_path = os.path.join(self.pocs_dir, f"{cve_id}.py")

        if not os.path.exists(poc_path):
            print(f"[?] 无本地 PoC 脚本，跳过实锤验证: {cve_id}")
            return None  # 无脚本 → 保持疑似

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

    # ----------------------------------------------------------------
    # 路线 2：Nuclei YAML（真正执行，且必须有 url 才打）
    # ----------------------------------------------------------------
    def _verify_network(self, cve_id: str, target_info: dict):
        target_url = target_info.get("url")
        if not target_url:
            print(f"[?] 缺少 url 参数，无法执行 Nuclei 网络扫描: {cve_id}")
            return None

        yaml_name = f"{cve_id.lower()}.yaml"
        yaml_path = os.path.join(self.yaml_pocs_dir, yaml_name)

        if not os.path.exists(yaml_path):
            print(f"[?] 无对应 Nuclei YAML 模板，跳过网络实锤: {cve_id}")
            return None

        print(f"[!] 走 Nuclei 引擎调用: {cve_id}")
        try:
            result = subprocess.run(
                [self.nuclei_bin, "-t", yaml_path, "-u", target_url, "-silent", "-duc", "-ni"],
                capture_output=True,
                text=True,
                timeout=30,
                stdin=subprocess.DEVNULL
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


if __name__ == "__main__":
    verifier = PocVerifier()

    print("--- 测试用例 1：本地 PoC，预期 True/False（取决于本机环境）---")
    res1 = verifier.verify("CVE-2021-3156", {"version": "1.8.31"}, target_type="pocs")
    print(f"结果: {res1}\n")

    print("--- 测试用例 2：无对应 PoC，预期 None ---")
    res2 = verifier.verify("CVE-9999-9999", {"version": "1.0"}, target_type="pocs")
    print(f"结果: {res2}\n")

    print("--- 测试用例 3：网络验证缺 url，预期 None ---")
    res3 = verifier.verify("CVE-2021-23017", {}, target_type="yaml_pocs")
    print(f"结果: {res3}\n")