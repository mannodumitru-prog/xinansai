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
        # 使用绝对路径锁定当前 core 目录，确保在任何地方启动都能找对位置
        base_dir = os.path.dirname(os.path.abspath(__file__))

        # 1. 目录配置
        self.pocs_dir = os.path.join(base_dir, "rules", "pocs")
        self.yaml_pocs_dir = os.path.join(base_dir, "rules", "yaml_pocs")

        # 2. 跨平台 Nuclei 路径自动识别引擎
        current_os = platform.system()
        tool_name = "nuclei.exe" if current_os == "Windows" else "nuclei"
        self.nuclei_bin = os.path.join(base_dir, "tools", tool_name)

        # 3. 调试心跳包 (用于本地开发排错)
        print(f"[DEBUG] SecKeeper 验证引擎已初始化")
        print(f"[DEBUG] 部署环境: {current_os}")
        print(f"[DEBUG] 挂载 Nuclei 路径: {self.nuclei_bin}")
        print(f"[DEBUG] 工具状态检测: {'正常就绪' if os.path.exists(self.nuclei_bin) else '未找到文件，请检查 tools 目录！'}")

    def verify(self, cve_id: str, target_info: dict):
        """
        验证指定 CVE 是否影响目标软件。
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
                # [核心修改]: 使用自动识别的 self.nuclei_bin 变量，而不是写死的 "nuclei"
                result = subprocess.run(
                    [self.nuclei_bin, "-t", yaml_path, "-u", target_url, "-silent", "-duc",  "-ni"],
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

    # 测试用例 4：预期 True（测试 Nuclei 引擎是否能成功发包并被 Python 捕获）
    print("--- 测试用例 4 (Nuclei 重机枪测试) ---")
    # 我们随便打一个绝对能返回 200 OK 的大厂网址做测试（比如百度或必应）
    res4 = verifier.verify("CVE-TEST-1234", {"name": "test-web", "url": "http://www.baidu.com"})
    print(f"结果: {res4}\n")
