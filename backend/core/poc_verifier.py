"""
PoC 验证引擎

职责：
1. 调度本地 Python PoC，完成 Local Verify。
2. 调度 Nuclei YAML，完成 Network Verify。
3. 对外保持原有 True / False / None 返回语义，避免影响现有 Detector。
4. 内部补充结构化状态，供后续报告、前端和日志扩展使用。
"""

import logging
import os
import platform
import subprocess
import sys
from datetime import datetime
from typing import Any, Dict, Optional


class PocVerifier:
    """PoC 调度与验证引擎。"""

    # 对外兼容层仍返回 True / False / None：
    # True  = 确认漏洞
    # False = 有 PoC / YAML，但验证未命中或执行失败
    # None  = 没有对应 PoC / YAML，无法验证
    VERIFY_SUCCESS = "verified"
    VERIFY_FAILED = "failed"
    NO_POC = "no_poc"
    NO_TARGET = "no_target"
    TOOL_MISSING = "tool_missing"
    TIMEOUT = "timeout"
    EXEC_ERROR = "exec_error"

    # 目录名保持和工程真实结构一致：
    # core/rules/pocs       -> Local Verify / Python PoC
    # core/rules/yaml_pocs  -> Network Verify / Nuclei YAML
    LOCAL_TYPE = "pocs"
    NETWORK_TYPE = "yaml_pocs"
    LOCAL_DISPLAY = "local"
    NETWORK_DISPLAY = "network"

    def __init__(
        self,
        base_dir: Optional[str] = None,
        pocs_dir: Optional[str] = None,
        yaml_pocs_dir: Optional[str] = None,
        nuclei_bin: Optional[str] = None,
        local_timeout: int = 15,
        network_timeout: int = 30,
    ):
        self.base_dir = base_dir or os.path.dirname(os.path.abspath(__file__))
        self.pocs_dir = pocs_dir or os.path.join(self.base_dir, "rules", "pocs")
        self.yaml_pocs_dir = yaml_pocs_dir or os.path.join(self.base_dir, "rules", "yaml_pocs")
        self.local_timeout = local_timeout
        self.network_timeout = network_timeout

        current_os = platform.system()
        tool_name = "nuclei.exe" if current_os == "Windows" else "nuclei"
        self.nuclei_bin = nuclei_bin or os.getenv(
            "SECKEEPER_NUCLEI_BIN",
            os.path.join(self.base_dir, "tools", tool_name),
        )

        self.logger = logging.getLogger(self.__class__.__name__)
        self.last_result: Dict[str, Any] = {}

        self.logger.info("SecKeeper 验证引擎初始化完成")
        self.logger.info("部署环境: %s", current_os)
        self.logger.info("本地 PoC 路径: %s", self.pocs_dir)
        self.logger.info("YAML PoC 路径: %s", self.yaml_pocs_dir)
        if os.path.exists(self.nuclei_bin):
            self.logger.info("Nuclei 工具就绪: %s", self.nuclei_bin)
        else:
            self.logger.warning("Nuclei 工具未找到: %s", self.nuclei_bin)

    def verify(self, cve_id: str, target_info: Optional[Dict[str, Any]], target_type: str = LOCAL_TYPE):
        """
        执行验证，并保持与现有 Detector 兼容的返回值。

        Args:
            cve_id: CVE 编号。
            target_info: 目标信息，本地 PoC 通常需要 version，网络 PoC 通常需要 url。
            target_type:
                "pocs"      -> 本地 Python PoC
                "yaml_pocs" -> Nuclei YAML
                其他值       -> 先本地后网络兜底

        Returns:
            True:  确认漏洞存在
            False: PoC/YAML 存在但验证失败、超时或执行异常
            None:  没有对应 PoC/YAML 或缺少必要目标信息
        """
        detail = self.verify_detail(cve_id, target_info or {}, target_type)
        return self._to_legacy_result(detail)

    def verify_detail(
        self,
        cve_id: str,
        target_info: Optional[Dict[str, Any]],
        target_type: str = LOCAL_TYPE,
    ) -> Dict[str, Any]:
        """执行验证并返回结构化结果，供后续前端、报告和日志使用。"""
        target_info = target_info or {}
        cve_id = str(cve_id or "").strip().upper()

        if not cve_id:
            return self._record_result(
                status=self.EXEC_ERROR,
                cve_id="UNKNOWN",
                target_type=target_type,
                message="CVE ID 为空，无法执行验证。",
            )

        if target_type == self.LOCAL_TYPE:
            return self._verify_local_detail(cve_id, target_info)

        if target_type == self.NETWORK_TYPE:
            return self._verify_network_detail(cve_id, target_info)

        # 兜底：先尝试本地 PoC，再尝试网络 YAML。
        local_result = self._verify_local_detail(cve_id, target_info)
        if local_result.get("status") != self.NO_POC:
            return local_result
        return self._verify_network_detail(cve_id, target_info)

    def _verify_local_detail(self, cve_id: str, target_info: Dict[str, Any]) -> Dict[str, Any]:
        """路线一：本地 Python PoC。"""
        poc_path = self._find_local_poc(cve_id)

        if not poc_path:
            expected_path = os.path.join(self.pocs_dir, f"{cve_id}.py")
            return self._record_result(
                status=self.NO_POC,
                cve_id=cve_id,
                target_type=self.LOCAL_TYPE,
                message=f"无本地 Python PoC，跳过实锤验证: {cve_id}",
                poc_path=expected_path,
            )

        target_version = str(target_info.get("version", ""))
        command = [sys.executable, poc_path, "--target_version", target_version]

        self.logger.info("调用本地 Python PoC: %s", cve_id)
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.local_timeout,
            )
            stdout = result.stdout or ""
            stderr = result.stderr or ""

            if result.returncode == 0 and "[VULN_STATUS]: VERIFIED_TRUE" in stdout:
                return self._record_result(
                    status=self.VERIFY_SUCCESS,
                    cve_id=cve_id,
                    target_type=self.LOCAL_TYPE,
                    message="Python PoC 验证成功，漏洞确认存在。",
                    poc_path=poc_path,
                    returncode=result.returncode,
                    stdout=self._trim_output(stdout),
                    stderr=self._trim_output(stderr),
                )

            return self._record_result(
                status=self.VERIFY_FAILED,
                cve_id=cve_id,
                target_type=self.LOCAL_TYPE,
                message="Python PoC 已执行，但未命中漏洞特征。",
                poc_path=poc_path,
                returncode=result.returncode,
                stdout=self._trim_output(stdout),
                stderr=self._trim_output(stderr),
            )

        except subprocess.TimeoutExpired as e:
            return self._record_result(
                status=self.TIMEOUT,
                cve_id=cve_id,
                target_type=self.LOCAL_TYPE,
                message=f"Python PoC 执行超时（>{self.local_timeout}s）。",
                poc_path=poc_path,
                stdout=self._trim_output(e.stdout),
                stderr=self._trim_output(e.stderr),
            )
        except Exception as e:
            return self._record_result(
                status=self.EXEC_ERROR,
                cve_id=cve_id,
                target_type=self.LOCAL_TYPE,
                message=f"Python PoC 执行异常: {e}",
                poc_path=poc_path,
            )

    def _verify_network_detail(self, cve_id: str, target_info: Dict[str, Any]) -> Dict[str, Any]:
        """路线二：Nuclei YAML。"""
        target_url = target_info.get("url")
        if not target_url:
            return self._record_result(
                status=self.NO_TARGET,
                cve_id=cve_id,
                target_type=self.NETWORK_TYPE,
                message=f"缺少 url 参数，无法执行 Nuclei 网络验证: {cve_id}",
            )

        yaml_path = self._find_network_poc(cve_id)

        if not yaml_path:
            expected_path = os.path.join(self.yaml_pocs_dir, f"{cve_id.lower()}.yaml")
            return self._record_result(
                status=self.NO_POC,
                cve_id=cve_id,
                target_type=self.NETWORK_TYPE,
                message=f"无对应 Nuclei YAML 模板，跳过网络实锤: {cve_id}",
                poc_path=expected_path,
                target_url=target_url,
            )

        if not os.path.exists(self.nuclei_bin):
            return self._record_result(
                status=self.TOOL_MISSING,
                cve_id=cve_id,
                target_type=self.NETWORK_TYPE,
                message=f"Nuclei 工具不存在，无法执行网络验证: {self.nuclei_bin}",
                poc_path=yaml_path,
                target_url=target_url,
            )

        command = [
            self.nuclei_bin,
            "-t", yaml_path,
            "-u", str(target_url),
            "-silent",
            "-duc",
            "-ni",
        ]

        self.logger.info("调用 Nuclei YAML: %s -> %s", cve_id, target_url)
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.network_timeout,
                stdin=subprocess.DEVNULL,
            )
            stdout = result.stdout or ""
            stderr = result.stderr or ""

            # Nuclei -silent 输出可能只包含模板结果，也可能不包含 CVE ID。
            # 因此只要 returncode 为 0 且 stdout 非空，即可视为命中。
            if result.returncode == 0 and stdout.strip():
                return self._record_result(
                    status=self.VERIFY_SUCCESS,
                    cve_id=cve_id,
                    target_type=self.NETWORK_TYPE,
                    message="Nuclei YAML 验证成功，漏洞确认存在。",
                    poc_path=yaml_path,
                    target_url=target_url,
                    returncode=result.returncode,
                    stdout=self._trim_output(stdout),
                    stderr=self._trim_output(stderr),
                )

            return self._record_result(
                status=self.VERIFY_FAILED,
                cve_id=cve_id,
                target_type=self.NETWORK_TYPE,
                message="Nuclei YAML 已执行，但未命中漏洞特征。",
                poc_path=yaml_path,
                target_url=target_url,
                returncode=result.returncode,
                stdout=self._trim_output(stdout),
                stderr=self._trim_output(stderr),
            )

        except subprocess.TimeoutExpired as e:
            return self._record_result(
                status=self.TIMEOUT,
                cve_id=cve_id,
                target_type=self.NETWORK_TYPE,
                message=f"Nuclei YAML 执行超时（>{self.network_timeout}s）。",
                poc_path=yaml_path,
                target_url=target_url,
                stdout=self._trim_output(e.stdout),
                stderr=self._trim_output(e.stderr),
            )
        except Exception as e:
            return self._record_result(
                status=self.EXEC_ERROR,
                cve_id=cve_id,
                target_type=self.NETWORK_TYPE,
                message=f"Nuclei YAML 执行异常: {e}",
                poc_path=yaml_path,
                target_url=target_url,
            )

    def _record_result(self, status: str, cve_id: str, target_type: str, message: str, **kwargs) -> Dict[str, Any]:
        """记录最近一次验证结果。"""
        result = {
            "status": status,
            "cve_id": cve_id,
            "target_type": target_type,
            "verification_method": self._display_method(target_type),
            "message": message,
            "verified": status == self.VERIFY_SUCCESS,
            "timestamp": datetime.now().isoformat(timespec="seconds"),
        }
        result.update(kwargs)
        self.last_result = result

        if status == self.VERIFY_SUCCESS:
            self.logger.info("%s", message)
        elif status in (self.NO_POC, self.NO_TARGET):
            self.logger.info("%s", message)
        else:
            self.logger.warning("%s", message)

        return result


    def _find_local_poc(self, cve_id: str) -> Optional[str]:
        """查找本地 Python PoC，兼容 CVE 文件名大小写。"""
        candidates = [
            os.path.join(self.pocs_dir, f"{cve_id}.py"),
            os.path.join(self.pocs_dir, f"{cve_id.lower()}.py"),
            os.path.join(self.pocs_dir, f"{cve_id.upper()}.py"),
        ]
        for path in candidates:
            if os.path.exists(path):
                return path
        return None

    def _find_network_poc(self, cve_id: str) -> Optional[str]:
        """查找 Nuclei YAML PoC，兼容 .yaml/.yml 与大小写文件名。"""
        candidates = []
        for name in (cve_id.lower(), cve_id.upper(), cve_id):
            for ext in (".yaml", ".yml"):
                candidates.append(os.path.join(self.yaml_pocs_dir, f"{name}{ext}"))
        for path in candidates:
            if os.path.exists(path):
                return path
        return None

    def _display_method(self, target_type: str) -> str:
        """将内部目录名转换为前端/报告展示用的验证类型。"""
        if target_type == self.LOCAL_TYPE:
            return self.LOCAL_DISPLAY
        if target_type == self.NETWORK_TYPE:
            return self.NETWORK_DISPLAY
        return str(target_type or "unknown")

    def _to_legacy_result(self, detail: Dict[str, Any]):
        """将结构化结果转换为旧版 Detector 兼容返回值。"""
        status = detail.get("status")
        if status == self.VERIFY_SUCCESS:
            return True
        if status in (self.NO_POC, self.NO_TARGET):
            return None
        return False

    @staticmethod
    def _trim_output(value: Any, max_len: int = 2000) -> str:
        """裁剪外部命令输出，避免日志和报告过大。"""
        if value is None:
            return ""
        if isinstance(value, bytes):
            value = value.decode(errors="ignore")
        text = str(value).strip()
        if len(text) <= max_len:
            return text
        return text[:max_len] + "... [truncated]"


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")

    verifier = PocVerifier()

    print("--- 测试用例 1：本地 PoC，预期 True/False/None（取决于本机环境）---")
    res1 = verifier.verify("CVE-2021-3156", {"version": "1.8.31"}, target_type="pocs")
    print(f"兼容结果: {res1}")
    print(f"结构化结果: {verifier.last_result}\n")

    print("--- 测试用例 2：无对应 PoC，预期 None ---")
    res2 = verifier.verify("CVE-9999-9999", {"version": "1.0"}, target_type="pocs")
    print(f"兼容结果: {res2}")
    print(f"结构化结果: {verifier.last_result}\n")

    print("--- 测试用例 3：网络验证缺 url，预期 None ---")
    res3 = verifier.verify("CVE-2021-23017", {}, target_type="yaml_pocs")
    print(f"兼容结果: {res3}")
    print(f"结构化结果: {verifier.last_result}\n")
