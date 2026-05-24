#!/usr/bin/env python3
"""
敏感文件权限检测器
检查关键系统文件的权限是否正确
"""

import os
import stat
from typing import List, Dict, Any

try:
    from .base_detector import BaseDetector
except ImportError:
    import sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from base_detector import BaseDetector


class FileIntegrityDetector(BaseDetector):
    """敏感文件权限检测器"""

    def get_detector_name(self) -> str:
        return "file_integrity_detector"

    def get_rule_file(self) -> str:
        return "file_integrity_rules.json"

    def detect(self) -> List[Dict]:
        """执行敏感文件权限检查"""
        vulnerabilities = []
        rules = self.rules.get("rules", [])
        if not rules:
            print("[WARN] 未加载到文件权限规则")
            return []

        print("[INFO] 开始敏感文件权限检测...")

        for rule in rules:
            file_path = rule.get("file_path")
            expected_mode = rule.get("expected_permission")
            check_type = rule.get("check_type", "exact")  # exact or more_strict

            if not os.path.exists(file_path):
                continue

            actual_mode = self._get_permission_octal(file_path)
            if actual_mode is None:
                continue

            passed = self._compare_permission(actual_mode, expected_mode, check_type)
            if not passed:
                vuln = self.format_vulnerability(
                    vuln_id=f"FILE-{os.path.basename(file_path).upper()}",
                    title=f"敏感文件权限不安全: {file_path}",
                    severity=rule.get("severity", "high"),
                    category="file_integrity",
                    description=f"文件 {file_path} 权限为 {actual_mode}，预期要求应为 {expected_mode} 或更严格。过松的权限可能导致信息泄露或权限提升。",
                    affected_target=file_path,
                    remediation=rule.get("remediation", f"执行 `chmod {expected_mode} {file_path}` 修复权限。"),
                    expected=expected_mode,
                    actual=actual_mode
                )
                vulnerabilities.append(vuln)

        print(f"[INFO] 敏感文件权限检测完成，发现 {len(vulnerabilities)} 个问题")
        return vulnerabilities

    def _get_permission_octal(self, path: str) -> str:
        """获取文件权限的八进制表示（如 '644'）"""
        try:
            mode = os.stat(path).st_mode
            perm = stat.S_IMODE(mode)
            return f"{perm:03o}"
        except Exception as e:
            print(f"[ERROR] 读取权限失败 {path}: {e}")
            return None

    def _compare_permission(self, actual: str, expected: str, check_type: str) -> bool:
        """安全比较权限是否符合要求"""
        if check_type == "exact":
            return actual == expected
        elif check_type == "more_strict":
            # 使用按位或(OR)来判断权限子集。
            # 只有当实际权限没有任何超出预期权限的开启位时，按位或的结果才会等于预期权限。
            actual_int = int(actual, 8)
            expected_int = int(expected, 8)
            return (actual_int | expected_int) == expected_int
        return False


if __name__ == "__main__":
    detector = FileIntegrityDetector(rules_dir=os.path.join("..", "rules"))
    results = detector.detect()
    for r in results:
        print(r)
