#!/usr/bin/env python3
"""
提权风险检测器 - 升级版

检测维度：
1. 危险SUID/SGID文件
2. sudoers危险配置
3. 内核CVE行为验证（绕过版本号比对局限，直接检测漏洞特征）
   - CVE-2021-4034 PwnKit (polkit pkexec)
   - CVE-2022-0847 Dirty Pipe (内核管道)
   - CVE-2021-3156 Baron Samedit (sudo堆溢出)
   - CVE-2023-0386 OverlayFS提权

设计说明：
  内核CVE无法通过版本号精确比对（发行版会向后移植补丁），
  因此本模块采用"行为特征检测"：
    - 检查漏洞的直接触发条件是否存在（文件权限、版本范围、补丁标记）
    - 有专用PoC脚本时调用PoC进行实锤验证
    - 结果分为：🔴实锤确认 / 🟡疑似（需人工核查） / ✅已修复
"""

import os
import re
import subprocess
import sys
import platform
from typing import List, Dict, Any, Optional, Tuple

try:
    from .base_detector import BaseDetector
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
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
    PocVerifier = None
    print(f"⚠️ 无法导入 PocVerifier: {e}")

class PrivilegeEscalationDetector(BaseDetector):
    """提权风险检测器"""

    def __init__(self, rules_dir: str = "core/rules"):
        super().__init__(rules_dir)
        # 复用 PocVerifier，让提权检测器也能调用 PoC 实锤
        if PocVerifier is None:
            self.verifier = None
            print("⚠️ PocVerifier 不可用，将跳过 PoC 验证")
        else:
            try:
                self.verifier = PocVerifier()
            except Exception as e:
                print(f"⚠️ PocVerifier 初始化失败，将跳过 PoC 验证: {e}")
                self.verifier = None

    def get_detector_name(self) -> str:
        return "privilege_escalation_detector"

    def get_rule_file(self) -> str:
        return "privilege_escalation_rules.json"

    def detect(self) -> List[Dict]:
        """执行提权风险检测"""
        vulnerabilities = []
        rules = self.rules.get("rules", [])
        if not rules:
            print("[WARN] 未加载到提权检测规则")
            return []

        print("[INFO] 开始提权风险检测...")

        for rule in rules:
            check_name = rule.get("check_name", "")

            if check_name == "dangerous_suid_files":
                vulnerabilities.extend(self._check_suid_files(rule))

            elif check_name == "sudoers_dangerous_config":
                vulnerabilities.extend(self._check_sudoers(rule))

            elif check_name == "kernel_cve_behavior":
                # 内核CVE：走行为验证，不走版本初筛
                vulnerabilities.extend(self._check_kernel_cves(rule))

        print(f"[INFO] 提权风险检测完成，发现 {len(vulnerabilities)} 个问题")
        return vulnerabilities

    # ----------------------------------------------------------------
    # 1. 危险 SUID 文件检测（原有逻辑不变）
    # ----------------------------------------------------------------
    def _check_suid_files(self, rule: Dict) -> List[Dict]:
        """检查危险的SUID/SGID文件"""
        vulnerabilities = []
        dangerous_list = rule.get("dangerous_binaries", [])
        if not dangerous_list:
            return []

        try:
            result = subprocess.run(
                ["find", "/", "-perm", "-4000", "-o", "-perm", "-2000", "-type", "f"],
                capture_output=True, text=True, timeout=120
            )
            suid_files = set(result.stdout.strip().splitlines())

            for suid_file in suid_files:
                base_name = os.path.basename(suid_file)
                if base_name in dangerous_list:
                    vuln = self.format_vulnerability(
                        vuln_id=f"PRIV-ESC-SUID-{base_name.upper()}",
                        title=f"🔴 危险SUID文件: {suid_file}",
                        severity=rule.get("severity", "high"),
                        category="privilege_escalation",
                        description=(f"文件 {suid_file} 设置了SUID/SGID位，"
                                     f"属于高危可提权程序（{base_name}），"
                                     f"普通用户可借此提升至root权限。"),
                        affected_target=suid_file,
                        remediation=rule.get("remediation",
                                             f"执行 `chmod u-s {suid_file}` 移除SUID位。"),
                        binary=base_name,
                        verification_status="verified",
                        verification_method=rule.get("verification_method", "local"),
                        verification_engine=rule.get("verification_engine", "state_check"),
                        verification_safety=rule.get("verification_safety", "safe_probe"),
                        offline_supported=rule.get("offline_supported", True)
                    )
                    vulnerabilities.append(vuln)

        except subprocess.TimeoutExpired:
            print("[WARN] SUID扫描超时(>120s)")
        except Exception as e:
            print(f"[ERROR] SUID扫描失败: {e}")

        return vulnerabilities

    # ----------------------------------------------------------------
    # 2. sudoers 危险配置检测（原有逻辑不变）
    # ----------------------------------------------------------------
    def _check_sudoers(self, rule: Dict) -> List[Dict]:
        """检查sudoers配置中的危险项"""
        vulnerabilities = []
        dangerous_patterns = rule.get("dangerous_patterns", [])
        sudoers_path = "/etc/sudoers"

        if not os.path.exists(sudoers_path):
            return []

        try:
            with open(sudoers_path, "r") as f:
                content = f.read()

            for pattern in dangerous_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    vuln = self.format_vulnerability(
                        vuln_id="PRIV-ESC-SUDOERS",
                        title="🟡 sudoers配置存在提权风险",
                        severity=rule.get("severity", "high"),
                        category="privilege_escalation",
                        description=(f"检测到危险配置: {pattern}，"
                                     f"可能导致普通用户无需密码或绕过限制执行特权命令。"),
                        affected_target=sudoers_path,
                        remediation=rule.get("remediation",
                                             "编辑/etc/sudoers，移除NOPASSWD或!authenticate等危险选项。"),
                        matched_pattern=pattern,
                        verification_status="verified",
                        verification_method=rule.get("verification_method", "local"),
                        verification_engine=rule.get("verification_engine", "state_check"),
                        verification_safety=rule.get("verification_safety", "safe_probe"),
                        offline_supported=rule.get("offline_supported", True)
                    )
                    vulnerabilities.append(vuln)
                    break
        except PermissionError:
            print("[WARN] 无权限读取 /etc/sudoers，跳过检测")
        except Exception as e:
            print(f"[ERROR] sudoers检查失败: {e}")

        return vulnerabilities

    # ----------------------------------------------------------------
    # 3. 内核CVE行为验证（新增核心模块）
    # ----------------------------------------------------------------
    def _check_kernel_cves(self, rule: Dict) -> List[Dict]:
        """
        对内核CVE进行行为特征验证。
        不依赖版本号比对，而是：
          a) 检查漏洞的触发前提条件（文件权限/配置/内核版本范围）
          b) 若有 PoC 脚本则调用实锤验证
          c) 两者结合给出最终判定
        """
        vulnerabilities = []
        cve_list = rule.get("cves", [])
        kernel_ver = self._get_kernel_version()

        for cve_rule in cve_list:
            cve_id = cve_rule.get("cve_id", "")
            check_method = cve_rule.get("check_method", "")
            print(f"[INFO] 检测内核CVE: {cve_id} ({check_method})")

            try:
                result = self._dispatch_kernel_check(cve_rule, kernel_ver)
                if result is None:
                    # 明确判定已修复或不受影响，跳过
                    print(f"  ✅ {cve_id}: 未受影响或已修复")
                    continue

                # result 是 (status, detail_msg) 元组
                status, detail = result
                vuln = self._build_kernel_cve_vuln(cve_rule, status, detail)
                vulnerabilities.append(vuln)

            except Exception as e:
                print(f"  ⚠️ {cve_id} 检测异常: {e}")

        return vulnerabilities

    def _dispatch_kernel_check(
        self, cve_rule: Dict, kernel_ver: str
    ) -> Optional[Tuple[str, str]]:
        """
        根据 check_method 分发到具体检测函数。
        返回 None 表示未受影响；返回 (status, detail) 表示存在风险。
        status: "verified" | "unverified" | "needs_manual_check"
        """
        method = cve_rule.get("check_method", "")
        cve_id = cve_rule.get("cve_id", "")

        # ---- 方法A：polkit 版本+文件权限检测 -------------------------
        if method == "polkit_version_and_patch":
            return self._check_cve_2021_4034(cve_rule)

        # ---- 方法B：内核版本范围检测（发行版内核降级为疑似）-----------
        elif method == "kernel_version_range":
            return self._check_kernel_version_range(cve_rule, kernel_ver)

        # ---- 方法C：sudo 版本检测 ------------------------------------
        elif method == "sudo_version":
            return self._check_sudo_version(cve_rule)

        # ---- 兜底：调用 PoC 验证引擎 ---------------------------------
        else:
            return self._try_poc_verify(cve_id)

    # ----------------------------------------------------------------
    # CVE-2021-4034 PwnKit：检查 pkexec 的 SUID 位 + polkit 版本
    # ----------------------------------------------------------------
    def _check_cve_2021_4034(self, cve_rule: Dict) -> Optional[Tuple[str, str]]:
        """
        PwnKit 的触发条件：pkexec 文件存在且有 SUID 位。
        修复方案之一是 chmod 0755 pkexec（去掉SUID），可直接检测。
        若有 PoC 脚本则进一步实锤。
        """
        cve_id = cve_rule.get("cve_id", "CVE-2021-4034")
        pkexec_paths = ["/usr/bin/pkexec", "/usr/pocs/bin/pkexec"]
        pkexec_found = None

        for path in pkexec_paths:
            if os.path.exists(path):
                pkexec_found = path
                break

        if not pkexec_found:
            # 没有 pkexec，不受影响
            return None

        # 检查是否有 SUID 位
        try:
            st = os.stat(pkexec_found)
            has_suid = bool(st.st_mode & 0o4000)
        except Exception:
            has_suid = False

        if not has_suid:
            # SUID 已被移除，说明打了临时缓解补丁
            print(f"  ✅ {cve_id}: pkexec 存在但 SUID 位已移除，已缓解")
            return None

        # pkexec 存在且有 SUID，进一步检查 polkit 版本
        polkit_ver = self._get_polkit_version()
        detail = f"pkexec ({pkexec_found}) 存在SUID位，polkit版本: {polkit_ver or '未知'}"

        # 尝试 PoC 实锤
        poc_result = self._try_poc_verify(cve_id)
        if poc_result and poc_result[0] == "verified":
            return ("verified", detail + " | PoC验证: 确认可利用")

        # polkit < 0.121 才受影响（修复版本）
        # 如果版本解析失败，保守标记为疑似
        if polkit_ver:
            try:
                from packaging.version import Version
                if Version(polkit_ver) >= Version("0.121"):
                    print(f"  ✅ {cve_id}: polkit {polkit_ver} >= 0.121，已修复")
                    return None
            except Exception:
                pass

        return ("unverified", detail)

    # ----------------------------------------------------------------
    # 内核版本范围检测（CVE-2022-0847 / CVE-2023-0386 等）
    # ----------------------------------------------------------------
    def _check_kernel_version_range(
        self, cve_rule: Dict, kernel_ver: str
    ) -> Optional[Tuple[str, str]]:
        """
        用内核版本范围做初步判断，但要注意发行版 backport 的问题，
        所以命中后只标"疑似"，不标"实锤"（除非有PoC）。
        """
        cve_id = cve_rule.get("cve_id", "")
        k_min = cve_rule.get("affected_kernel_min", "0")
        k_max = cve_rule.get("affected_kernel_max", "99999")

        if not kernel_ver or kernel_ver == "unknown":
            return ("needs_manual_check",
                    f"内核版本获取失败，无法判断 {cve_id} 是否受影响")

        try:
            from packaging.version import Version
            kv = Version(kernel_ver)
            min_v = Version(k_min)
            max_v = Version(k_max)

            if not (min_v <= kv < max_v):
                # 版本号不在范围内，但因为 backport 可能已修复，给出提示
                print(f"  ℹ️ {cve_id}: 内核 {kernel_ver} 不在上游受影响范围 "
                      f"[{k_min}, {k_max})，但发行版可能已 backport 修复")
                return None

        except Exception:
            # 版本解析失败，保守处理
            pass

        # 版本落在受影响范围，尝试 PoC 实锤
        detail = (f"内核版本 {kernel_ver} 落在上游受影响范围 [{k_min}, {k_max})\n"
                  f"⚠️ 注意：发行版内核可能已向后移植修复补丁，建议查阅发行版安全公告确认")

        poc_result = self._try_poc_verify(cve_id)
        if poc_result and poc_result[0] == "verified":
            return ("verified", detail + " | PoC验证: 确认可利用")

        # 无 PoC，标记为疑似+需人工确认
        return ("needs_manual_check", detail)

    # ----------------------------------------------------------------
    # sudo 版本检测（CVE-2021-3156 Baron Samedit）
    # ----------------------------------------------------------------
    def _check_sudo_version(self, cve_rule: Dict) -> Optional[Tuple[str, str]]:
        """
        Baron Samedit: sudo < 1.9.5p2 受影响。
        sudo 的版本号比发行版包名直接，可以精确比对。
        """
        cve_id = cve_rule.get("cve_id", "CVE-2021-3156")
        sudo_ver = self._get_sudo_version()

        if not sudo_ver:
            return ("needs_manual_check", "sudo版本获取失败，无法判断是否受影响")

        try:
            from packaging.version import Version
            # sudo 版本规范化：1.9.5p2 → 1.9.5.2
            normalized = re.sub(r'p(\d+)', r'.\1', sudo_ver)
            sv = Version(normalized)
            fixed = Version("1.9.5.2")  # 1.9.5p2

            if sv >= fixed:
                print(f"  ✅ {cve_id}: sudo {sudo_ver} >= 1.9.5p2，已修复")
                return None

        except Exception as e:
            print(f"  ⚠️ sudo版本解析失败: {e}")
            return ("needs_manual_check", f"sudo版本 {sudo_ver} 解析失败，请人工确认")

        detail = f"sudo版本 {sudo_ver} < 1.9.5p2，存在堆溢出提权漏洞"

        # 尝试 PoC 实锤
        poc_result = self._try_poc_verify(cve_id)
        if poc_result and poc_result[0] == "verified":
            return ("verified", detail + " | PoC验证: 确认可利用")

        return ("unverified", detail)

    # ----------------------------------------------------------------
    # PoC 验证通用调用
    # ----------------------------------------------------------------
    def _try_poc_verify(self, cve_id: str) -> Optional[Tuple[str, str]]:
        """
        尝试调用 PocVerifier 对指定 CVE 进行实锤验证。
        返回 ("verified", "") 或 None（无PoC/验证失败）。
        """
        if not self.verifier:
            return None
        try:
            result = self.verifier.verify(cve_id, {}, target_type="pocs")
            if result is True:
                return ("verified", "PoC实锤验证成功")
            elif result is False:
                return None  # PoC 明确失败，说明已修复
        except Exception as e:
            print(f"  ⚠️ PoC验证异常 ({cve_id}): {e}")
        return None

    # ----------------------------------------------------------------
    # 构建漏洞结果字典
    # ----------------------------------------------------------------
    def _build_kernel_cve_vuln(
        self, cve_rule: Dict, status: str, detail: str
    ) -> Dict:
        """根据检测状态构建标准化漏洞字典"""
        cve_id = cve_rule.get("cve_id", "")
        name = cve_rule.get("name", cve_id)

        if status == "verified":
            prefix = "🔴[实锤漏洞]"
            sev = cve_rule.get("severity", "high")
        elif status == "unverified":
            prefix = "🟡[疑似漏洞]"
            sev = cve_rule.get("severity", "high")
        else:  # needs_manual_check
            prefix = "⚪[待确认]"
            sev = "low"  # 降级，避免误导

        return self.format_vulnerability(
            vuln_id=cve_id,
            title=f"{prefix} {cve_id}: {name}",
            severity=sev,
            category="privilege_escalation",
            description=f"{cve_rule.get('description', '')}\n\n检测详情: {detail}",
            affected_target=f"Linux内核 / 系统组件",
            remediation=cve_rule.get("remediation", "请升级至修复版本"),
            cvss_score=cve_rule.get("cvss_score", 0.0),
            references=cve_rule.get("references", []),
            tags=["kernel", "privilege_escalation", cve_id.lower().replace("-", "_")],
            verification_status=status,
            verification_method=cve_rule.get("verification_method", "local"),
            verification_engine=cve_rule.get("verification_engine", "python_probe"),
            verification_safety=cve_rule.get("verification_safety", "environment_probe"),
            poc_file=cve_rule.get("poc_file"),
            offline_supported=cve_rule.get("offline_supported", True)
        )

    # ----------------------------------------------------------------
    # 工具函数：获取系统版本信息
    # ----------------------------------------------------------------
    def _get_kernel_version(self) -> str:
        """获取内核版本（纯数字部分，如 5.15.0）"""
        try:
            raw = platform.release()
            match = re.match(r'^(\d+\.\d+(?:\.\d+)?)', raw)
            return match.group(1) if match else raw
        except Exception:
            return "unknown"

    def _get_polkit_version(self) -> Optional[str]:
        """获取 polkit 版本号"""
        for cmd in [
            ["pkexec", "--version"],
            ["dpkg-query", "-W", "-f=${Version}", "policykit-1"],
            ["dpkg-query", "-W", "-f=${Version}", "polkit"],
        ]:
            try:
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                if r.returncode == 0 and r.stdout.strip():
                    # 提取版本号
                    match = re.search(r'(\d+\.\d+(?:\.\d+)?)', r.stdout)
                    if match:
                        return match.group(1)
            except Exception:
                continue
        return None

    def _get_sudo_version(self) -> Optional[str]:
        """获取 sudo 版本号"""
        try:
            r = subprocess.run(["sudo", "--version"],
                               capture_output=True, text=True, timeout=5)
            match = re.search(r'Sudo version\s+(\S+)', r.stdout, re.IGNORECASE)
            if match:
                return match.group(1)
        except Exception:
            pass
        # 备用：dpkg
        try:
            r = subprocess.run(
                ["dpkg-query", "-W", "-f=${Version}", "sudo"],
                capture_output=True, text=True, timeout=5
            )
            if r.returncode == 0 and r.stdout.strip():
                match = re.search(r'(\d+\.\d+[^\s]*)', r.stdout)
                if match:
                    return match.group(1)
        except Exception:
            pass
        return None


# ----------------------------------------------------------------
# 测试入口
# ----------------------------------------------------------------
if __name__ == "__main__":
    detector = PrivilegeEscalationDetector(
        rules_dir=os.path.join(os.path.dirname(__file__), "..", "rules")
    )
    print(f"检测器: {detector.get_detector_name()}")
    print(f"内核版本: {detector._get_kernel_version()}")
    print(f"polkit版本: {detector._get_polkit_version()}")
    print(f"sudo版本: {detector._get_sudo_version()}")
    print()

    results = detector.detect()
    print(f"\n🎯 共发现 {len(results)} 个提权风险:\n")
    for r in results:
        print(f"  [{r.get('severity','?').upper():8s}] {r.get('title','')}")
        print(f"           状态: {r.get('verification_status','?')} | "
              f"目标: {r.get('affected_target','')}\n")