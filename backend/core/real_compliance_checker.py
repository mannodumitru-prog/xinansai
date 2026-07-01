#!/usr/bin/env python3
"""
真实合规检查模块 - 工程化版本

定位：
1. 作为“合规检查”三大板块的统一入口
2. 默认调用 ConfigDetector，共享 core/rules/config_rules.json
3. 保留少量内置检查作为补充，避免旧前端/报告断裂
4. 识别信创等保基线项，用于前端突出展示信创特色
"""

import re
import subprocess
import math
import hashlib
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple

class RealComplianceChecker:
    """真实合规检查器 - 生产环境实现"""
    
    @staticmethod
    def run_compliance_checks(
        include_config_detector: bool = True,
        include_legacy_checks: bool = True,
    ) -> Dict[str, Any]:
        """
        执行真实合规检查。

        设计原则：
        - ConfigDetector 是合规规则主引擎，负责消费 config_rules.json。
        - 内置 legacy 检查只作为补充与兼容层，可通过 include_legacy_checks=False 关闭。

        兼容旧接口：
        - 仍然返回 summary / checks / scan_timestamp / scan_id
        新增工程化字段：
        - success / status / results / errors / warnings / categories / xinchuang_summary
        """
        scan_id = f"compliance_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        scan_timestamp = datetime.now().isoformat()
        started_at = datetime.now()
        errors: List[Dict[str, Any]] = []
        warnings: List[Dict[str, Any]] = []
        checks: List[Dict[str, Any]] = []

        print("🛡️ 开始系统合规检查...")

        # 1. 优先执行 ConfigDetector，让 config_rules.json 成为合规基线主规则源。
        if include_config_detector:
            try:
                detector_checks, detector_warnings = RealComplianceChecker._run_config_detector_checks()
                checks.extend(detector_checks)
                warnings.extend(detector_warnings)
            except Exception as e:
                warnings.append({
                    "section": "config_detector_bridge",
                    "warning": f"ConfigDetector 合规桥接跳过: {e}",
                    "timestamp": datetime.now().isoformat()
                })

        sections = [
            ("password_policy", RealComplianceChecker._check_password_policy),
            ("ssh_config", RealComplianceChecker._check_ssh_config),
            ("firewall", RealComplianceChecker._check_firewall),
            ("system_security", RealComplianceChecker._check_system_security),
            ("network_security", RealComplianceChecker._check_network_security),
        ]

        # 2. 内置检查作为补充层；默认保留，避免旧功能消失。
        if include_legacy_checks:
            for section_name, section_func in sections:
                try:
                    section_checks = section_func() or []
                    for item in section_checks:
                        checks.append(RealComplianceChecker._normalize_check(item, source=section_name))
                except Exception as e:
                    error = {
                        "section": section_name,
                        "error": str(e),
                        "timestamp": datetime.now().isoformat()
                    }
                    errors.append(error)
                    checks.append(RealComplianceChecker._normalize_check({
                        "name": f"{section_name} 检查异常",
                        "category": "系统",
                        "passed": False,
                        "description": f"检查过程出错: {e}",
                        "risk_level": "高",
                    }, source=section_name))

        checks = RealComplianceChecker._deduplicate_checks(checks)
        summary = RealComplianceChecker._generate_summary(checks)
        duration = round((datetime.now() - started_at).total_seconds(), 3)
        status = "success" if not errors else ("partial_success" if checks else "failed")

        result = {
            "success": status != "failed",
            "status": status,
            "scan_id": scan_id,
            "scan_timestamp": scan_timestamp,
            "duration_seconds": duration,
            "summary": summary,
            "checks": checks,        # 兼容旧前端/报告
            "results": checks,       # 统一新结构
            "errors": errors,
            "warnings": warnings,
            "categories": summary.get("categories", {}),
            "xinchuang_summary": RealComplianceChecker._detect_xinchuang_summary(checks),
            "config_detector_enabled": include_config_detector,
            "legacy_checks_enabled": include_legacy_checks,
            "primary_rule_source": "config_rules.json" if include_config_detector else "legacy_builtin_checks",
        }

        print(
            f"✅ 合规检查完成: 通过 {summary['passed']}/{summary['total']} 项检查，"
            f"合规率 {summary['compliance_rate']}%"
        )
        return result

    

    @staticmethod
    def _normalize_check(check: Dict[str, Any], source: str = "builtin") -> Dict[str, Any]:
        """统一合规检查项结构，同时保留旧字段。"""
        if not isinstance(check, dict):
            check = {
                "name": "未知检查项",
                "category": "未知",
                "passed": False,
                "description": str(check),
                "risk_level": "中",
            }

        name = check.get("name") or check.get("check") or check.get("check_name") or "未命名检查项"
        category = check.get("category") or check.get("type") or "通用合规"
        passed = bool(check.get("passed", False))
        risk_level = check.get("risk_level") or check.get("severity") or ("低" if passed else "中")
        description = check.get("description") or check.get("details") or ""
        remediation = check.get("remediation")

        status = "passed" if passed else "failed"
        normalized = dict(check)
        normalized.update({
            "id": check.get("id") or RealComplianceChecker._make_check_id(name, category),
            "name": name,
            "check": name,          # 兼容旧报告字段
            "category": category,
            "passed": passed,
            "status": status,
            "description": description,
            "risk_level": RealComplianceChecker._normalize_risk_level(risk_level),
            "severity": RealComplianceChecker._risk_to_severity(risk_level),
            "source": source,
            "remediation": remediation,
            "is_xinchuang": bool(check.get("is_xinchuang")) or RealComplianceChecker._is_xinchuang_related(
                name, category, description, check.get("target"), check.get("affected_target"), check.get("remediation")
            ),
            "checked_at": datetime.now().isoformat(),
        })
        return normalized

    @staticmethod
    def _deduplicate_checks(checks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        对合规检查项去重。

        同一检查项同时来自 ConfigDetector 与 legacy 内置检查时，优先保留
        ConfigDetector 结果，确保 config_rules.json 作为主规则源，避免两套密码/基线逻辑漂移。
        """
        if not checks:
            return []

        source_priority = {
            "config_detector": 0,
            "password_policy": 1,
            "ssh_config": 1,
            "firewall": 1,
            "system_security": 1,
            "network_security": 1,
        }

        def key_of(item: Dict[str, Any]) -> str:
            name = str(item.get("name") or item.get("check") or "").strip().lower()
            category = str(item.get("category") or "").strip().lower()
            target = str(item.get("target") or item.get("affected_target") or "").strip().lower()
            return f"{category}|{name}|{target}"

        selected: Dict[str, Dict[str, Any]] = {}
        for item in checks:
            key = key_of(item)
            if not key.strip("|"):
                key = str(id(item))

            old = selected.get(key)
            if old is None:
                selected[key] = item
                continue

            old_pri = source_priority.get(str(old.get("source")), 9)
            new_pri = source_priority.get(str(item.get("source")), 9)
            if new_pri < old_pri:
                selected[key] = item

        return list(selected.values())

    @staticmethod
    def _make_check_id(name: str, category: str) -> str:
        raw = f"{category}-{name}".lower()
        raw = re.sub(r"[^a-z0-9\u4e00-\u9fff]+", "-", raw).strip("-")
        return f"COMPLIANCE-{raw[:80]}"

    @staticmethod
    def _normalize_risk_level(level: Any) -> str:
        mapping = {
            "critical": "严重", "high": "高", "medium": "中", "low": "低", "info": "低",
            "严重": "严重", "高": "高", "中": "中", "低": "低",
        }
        return mapping.get(str(level).strip().lower(), str(level or "中"))

    @staticmethod
    def _risk_to_severity(level: Any) -> str:
        normalized = RealComplianceChecker._normalize_risk_level(level)
        mapping = {"严重": "critical", "高": "high", "中": "medium", "低": "low"}
        return mapping.get(normalized, "medium")

    @staticmethod
    def _generate_summary(checks: List[Dict[str, Any]]) -> Dict[str, Any]:
        total = len(checks)
        passed = sum(1 for item in checks if item.get("passed") is True)
        failed = total - passed
        compliance_rate = round((passed / total) * 100, 1) if total else 0

        risk_count = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        categories: Dict[str, Dict[str, int]] = {}
        xinchuang_total = 0
        xinchuang_failed = 0

        for item in checks:
            sev = item.get("severity", "medium")
            if sev in risk_count and not item.get("passed", False):
                risk_count[sev] += 1

            category = item.get("category", "其他")
            categories.setdefault(category, {"total": 0, "passed": 0, "failed": 0})
            categories[category]["total"] += 1
            if item.get("passed"):
                categories[category]["passed"] += 1
            else:
                categories[category]["failed"] += 1

            if item.get("is_xinchuang"):
                xinchuang_total += 1
                if not item.get("passed"):
                    xinchuang_failed += 1

        return {
            "total": total,
            "passed": passed,
            "failed": failed,
            "compliance_rate": compliance_rate,
            "risk_count": risk_count,
            "critical": risk_count["critical"],
            "high": risk_count["high"],
            "medium": risk_count["medium"],
            "low": risk_count["low"],
            "categories": categories,
            "xinchuang_total": xinchuang_total,
            "xinchuang_failed": xinchuang_failed,
        }

    @staticmethod
    def _run_config_detector_checks() -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """桥接 ConfigDetector：把规则库命中的配置问题转成合规检查失败项。"""
        warnings: List[Dict[str, Any]] = []
        checks: List[Dict[str, Any]] = []

        try:
            core_dir = Path(__file__).resolve().parent
            rules_dir = core_dir / "rules"
            if not rules_dir.exists():
                # 上传文件单独测试时可能没有 core/rules，安静跳过。
                return checks, warnings

            import sys
            project_root = str(core_dir.parent)
            if project_root not in sys.path:
                sys.path.insert(0, project_root)

            try:
                from core.detectors.config_detector import ConfigDetector
            except Exception:
                from detectors.config_detector import ConfigDetector

            detector = ConfigDetector(rules_dir=str(rules_dir))
            vulnerabilities = detector.detect() or []

            for vuln in vulnerabilities:
                checks.append(RealComplianceChecker._normalize_check({
                    "name": vuln.get("check_name") or vuln.get("title") or vuln.get("vuln_id"),
                    "category": vuln.get("category", "配置合规"),
                    "passed": False,
                    "description": vuln.get("description", "配置基线检查未通过"),
                    "risk_level": vuln.get("severity", "medium"),
                    "remediation": vuln.get("remediation"),
                    "target": vuln.get("affected_target"),
                    "affected_target": vuln.get("affected_target"),
                    "actual": vuln.get("actual"),
                    "expected": vuln.get("expected"),
                    "source_vuln_id": vuln.get("vuln_id"),
                    "verification_source": "config_rules.json",
                    "is_xinchuang": RealComplianceChecker._is_xinchuang_related(
                        vuln.get("title"), vuln.get("category"), vuln.get("description"),
                        vuln.get("affected_target"), vuln.get("remediation")
                    ),
                }, source="config_detector"))

        except Exception as e:
            warnings.append({
                "section": "config_detector_bridge",
                "warning": str(e),
                "timestamp": datetime.now().isoformat()
            })

        return checks, warnings

    @staticmethod
    def _is_xinchuang_related(*values: Any) -> bool:
        text = " ".join(str(v) for v in values if v is not None).lower()
        keywords = [
            "信创", "麒麟", "kylin", "银河麒麟", "统信", "uos", "deepin",
            "达梦", "dameng", "dmserver", "人大金仓", "kingbase", "tongweb", "东方通",
        ]
        return any(keyword.lower() in text for keyword in keywords)

    @staticmethod
    def _detect_xinchuang_summary(checks: List[Dict[str, Any]]) -> Dict[str, Any]:
        related = [item for item in checks if item.get("is_xinchuang")]
        failed = [item for item in related if not item.get("passed")]

        components: Dict[str, int] = {}
        keywords = {
            "kylin": ["麒麟", "kylin", "银河麒麟"],
            "uos": ["统信", "uos", "deepin"],
            "dameng": ["达梦", "dameng", "dmserver"],
            "kingbase": ["金仓", "kingbase", "人大金仓"],
            "tongweb": ["tongweb", "东方通"],
        }
        for item in related:
            text = " ".join(str(item.get(k, "")) for k in [
                "name", "category", "description", "target", "affected_target", "remediation"
            ]).lower()
            for component, words in keywords.items():
                if any(w.lower() in text for w in words):
                    components[component] = components.get(component, 0) + 1

        return {
            "total": len(related),
            "passed": len(related) - len(failed),
            "failed": len(failed),
            "enabled": len(related) > 0,
            "components": components,
            "samples": [
                {
                    "name": item.get("name"),
                    "category": item.get("category"),
                    "passed": item.get("passed"),
                    "source": item.get("source"),
                }
                for item in related[:10]
            ],
        }

    @staticmethod
    def _check_password_policy() -> List[Dict[str, Any]]:
        """检查密码策略 - 基于熵检查"""
        checks = []
        
        try:
            # 1. 检查系统密码策略配置
            if RealComplianceChecker._is_linux():
                checks.extend(RealComplianceChecker._check_linux_password_policy())
            
            # 2. 执行密码强度熵检查
            checks.extend(RealComplianceChecker._perform_entropy_checks())
            
            # 3. 检查密码历史与重用策略
            checks.extend(RealComplianceChecker._check_password_history_policy())
            
            # 4. 检查账户锁定策略
            checks.extend(RealComplianceChecker._check_account_lockout_policy())
            
            return checks
            
        except Exception as e:
            print(f"❌ 密码策略检查错误: {e}")
            return [{
                "name": "密码策略检查",
                "category": "密码策略",
                "passed": False,
                "description": f"检查过程出错: {str(e)}",
                "risk_level": "中"
            }]
    
    @staticmethod
    def _is_linux() -> bool:
        """检查是否为Linux系统"""
        import platform
        return platform.system().lower() == "linux"
    
    @staticmethod
    def _check_linux_password_policy() -> List[Dict[str, Any]]:
        """检查Linux系统密码策略"""
        checks = []
        
        try:
            # 检查PAM密码策略配置
            pam_files = [
                "/etc/pam.d/common-password",
                "/etc/pam.d/system-auth",
                "/etc/security/pwquality.conf"
            ]
            
            for pam_file in pam_files:
                if Path(pam_file).exists():
                    with open(pam_file, 'r') as f:
                        content = f.read()
                    
                    # 检查密码复杂度模块
                    if any(keyword in content for keyword in ['pam_pwquality.so', 'pam_cracklib.so']):
                        config_details = RealComplianceChecker._parse_pam_config(content)
                        checks.append({
                            "name": f"密码复杂度配置 - {Path(pam_file).name}",
                            "category": "密码策略",
                            "passed": True,
                            "description": f"系统配置了密码复杂度要求",
                            "risk_level": "低",
                            "details": config_details
                        })
                    else:
                        checks.append({
                            "name": f"密码复杂度配置 - {Path(pam_file).name}",
                            "category": "密码策略",
                            "passed": False,
                            "description": f"未配置密码复杂度要求",
                            "risk_level": "高",
                            "remediation": "安装并配置libpam-pwquality或libpam-cracklib"
                        })
            
            # 检查/etc/login.defs中的密码策略
            if Path("/etc/login.defs").exists():
                with open("/etc/login.defs", 'r') as f:
                    login_defs = f.read()
                
                # 检查最小密码长度
                min_len = RealComplianceChecker._extract_config_value(login_defs, "PASS_MIN_LEN")
                if min_len and int(min_len) >= 8:
                    checks.append({
                        "name": "最小密码长度",
                        "category": "密码策略",
                        "passed": True,
                        "description": f"密码最小长度要求: {min_len}位",
                        "risk_level": "低"
                    })
                else:
                    checks.append({
                        "name": "最小密码长度",
                        "category": "密码策略",
                        "passed": False,
                        "description": f"密码最小长度不足8位 (当前: {min_len or '未设置'})",
                        "risk_level": "高",
                        "remediation": "在/etc/login.defs中设置PASS_MIN_LEN 8"
                    })
                
                # 检查密码最大有效期
                max_days = RealComplianceChecker._extract_config_value(login_defs, "PASS_MAX_DAYS")
                if max_days and int(max_days) <= 90:
                    checks.append({
                        "name": "密码最大有效期",
                        "category": "密码策略", 
                        "passed": True,
                        "description": f"密码最大有效期: {max_days}天",
                        "risk_level": "低"
                    })
                else:
                    checks.append({
                        "name": "密码最大有效期",
                        "category": "密码策略",
                        "passed": False,
                        "description": f"密码有效期过长 (当前: {max_days or '未设置'}天)",
                        "risk_level": "中",
                        "remediation": "在/etc/login.defs中设置PASS_MAX_DAYS 90"
                    })
                        
        except Exception as e:
            print(f"❌ Linux密码策略检查错误: {e}")
            
        return checks
    
    @staticmethod
    def _parse_pam_config(content: str) -> Dict[str, Any]:
        """解析PAM配置详情"""
        details = {}
        
        # 提取常见PAM参数
        parameters = {
            'minlen': '最小长度',
            'minclass': '最小字符类别',
            'dcredit': '数字要求', 
            'ucredit': '大写字母要求',
            'lcredit': '小写字母要求',
            'ocredit': '特殊字符要求',
            'difok': '最少不同字符数',
            'maxrepeat': '最大重复字符数',
            'maxsequence': '最大序列长度'
        }
        
        for param, desc in parameters.items():
            match = re.search(rf'{param}\s*=\s*([^\s]+)', content)
            if match:
                details[desc] = match.group(1)
        
        return details
    
    @staticmethod
    def _extract_config_value(content: str, key: str) -> Optional[str]:
        """从配置文件中提取键值"""
        match = re.search(rf'^\s*{key}\s+(\d+)', content, re.MULTILINE)
        return match.group(1) if match else None
    
    @staticmethod
    def _perform_entropy_checks() -> List[Dict[str, Any]]:
        """执行密码熵检查"""
        checks = []
        
        # 测试密码样本
        test_passwords = [
            "Password123!",           # 中等强度
            "weakpassword",           # 弱密码
            "StrongPass2024!@#",      # 强密码  
            "12345678",               # 极弱密码
            "Admin@2024",             # 中等密码
            "Mu-icac-of-jaz-doad",    # 密码短语
            "P@ssw0rd!Secure2024",    # 强密码
            "qwerty123",              # 弱密码
            "CorrectHorseBatteryStaple", # 密码短语
        ]
        
        entropy_results = []
        for password in test_passwords:
            entropy_score = RealComplianceChecker._calculate_entropy(password)
            strength_analysis = RealComplianceChecker._analyze_password_strength(password)
            
            entropy_results.append({
                "password_sample": password[:2] + "*****" + password[-2:] if len(password) > 4 else "***",
                "entropy_score": round(entropy_score, 2),
                "strength_level": strength_analysis['level'],
                "crack_time_estimate": strength_analysis['crack_time'],
                "issues": strength_analysis['issues']
            })
        
        # 分析结果
        strong_count = sum(1 for r in entropy_results if r['strength_level'] in ['strong', 'very_strong'])
        avg_entropy = sum(r['entropy_score'] for r in entropy_results) / len(entropy_results)
        
        checks.append({
            "name": "密码熵强度测试",
            "category": "密码策略",
            "passed": avg_entropy >= 60,  # 平均熵值阈值
            "description": f"测试了 {len(test_passwords)} 个密码样本，平均熵值: {avg_entropy:.2f} bits",
            "risk_level": "低" if avg_entropy >= 60 else "高",
            "details": {
                "strong_passwords": strong_count,
                "total_tested": len(test_passwords),
                "entropy_threshold": 60,
                "results": entropy_results
            }
        })
        
        return checks
    
    @staticmethod
    def _calculate_entropy(password: str) -> float:
        """计算密码熵值"""
        if not password:
            return 0.0
        
        # 字符集分析
        char_sets = 0
        if re.search(r'[a-z]', password):
            char_sets += 26  # 小写字母
        if re.search(r'[A-Z]', password):
            char_sets += 26  # 大写字母  
        if re.search(r'[0-9]', password):
            char_sets += 10  # 数字
        if re.search(r'[^a-zA-Z0-9]', password):
            char_sets += 32  # 特殊字符
        
        if char_sets == 0:
            return 0.0
        
        # 熵计算: log2(字符集大小 ^ 密码长度)
        entropy = len(password) * math.log2(char_sets)
        
        # 常见模式惩罚
        penalties = 0
        
        # 重复字符惩罚
        repeats = len(password) - len(set(password))
        penalties += repeats * 0.5
        
        # 序列惩罚 (如123, abc)
        sequences = RealComplianceChecker._count_sequences(password)
        penalties += sequences * 1.0
        
        # 常见模式惩罚
        common_patterns = RealComplianceChecker._check_common_patterns(password)
        penalties += common_patterns * 2.0
        
        return max(0, entropy - penalties)
    
    @staticmethod
    def _count_sequences(password: str) -> int:
        """计算序列数量"""
        sequences = 0
        for i in range(len(password) - 2):
            # 数字序列
            if (password[i:i+3].isdigit() and 
                abs(ord(password[i]) - ord(password[i+1])) == 1 and
                abs(ord(password[i+1]) - ord(password[i+2])) == 1):
                sequences += 1
            # 字母序列  
            elif (password[i:i+3].isalpha() and
                  abs(ord(password[i].lower()) - ord(password[i+1].lower())) == 1 and
                  abs(ord(password[i+1].lower()) - ord(password[i+2].lower())) == 1):
                sequences += 1
        return sequences
    
    @staticmethod
    def _check_common_patterns(password: str) -> int:
        """检查常见弱密码模式"""
        common_patterns = [
            r'123456',
            r'password', 
            r'qwerty',
            r'admin',
            r'welcome',
            r'[0-9]{6,}',  # 长数字序列
            r'([a-zA-Z])\1{2,}',  # 重复字符
            r'(.)\1{2,}',  # 任何字符重复3次以上
        ]
        
        patterns_found = 0
        lower_password = password.lower()
        
        for pattern in common_patterns:
            if re.search(pattern, lower_password):
                patterns_found += 1
        
        return patterns_found
    
    @staticmethod
    def _analyze_password_strength(password: str) -> Dict[str, Any]:
        """分析密码强度"""
        entropy = RealComplianceChecker._calculate_entropy(password)
        
        # 基于熵值的强度分级
        if entropy >= 80:
            level = "very_strong"
            crack_time = "数百年"
        elif entropy >= 60:
            level = "strong" 
            crack_time = "数年"
        elif entropy >= 40:
            level = "medium"
            crack_time = "数天到数周"
        elif entropy >= 20:
            level = "weak"
            crack_time = "数分钟到数小时"
        else:
            level = "very_weak"
            crack_time = "瞬间"
        
        # 识别具体问题
        issues = []
        if len(password) < 8:
            issues.append("密码过短")
        if not re.search(r'[A-Z]', password):
            issues.append("缺少大写字母")
        if not re.search(r'[a-z]', password):
            issues.append("缺少小写字母") 
        if not re.search(r'[0-9]', password):
            issues.append("缺少数字")
        if not re.search(r'[^a-zA-Z0-9]', password):
            issues.append("缺少特殊字符")
        if RealComplianceChecker._check_common_patterns(password) > 0:
            issues.append("包含常见模式")
        
        return {
            "level": level,
            "crack_time": crack_time,
            "issues": issues
        }
    
    @staticmethod
    def _check_password_history_policy() -> List[Dict[str, Any]]:
        """检查密码历史与重用策略"""
        checks = []
        
        try:
            if RealComplianceChecker._is_linux():
                # 检查PAM的密码历史配置
                for pam_file in ["/etc/pam.d/common-password", "/etc/pam.d/system-auth"]:
                    if Path(pam_file).exists():
                        with open(pam_file, 'r') as f:
                            content = f.read()
                        
                        remember_match = re.search(r'remember=(\d+)', content)
                        if remember_match:
                            remember_count = remember_match.group(1)
                            checks.append({
                                "name": "密码历史策略",
                                "category": "密码策略",
                                "passed": int(remember_count) >= 5,
                                "description": f"系统配置了记住 {remember_count} 个历史密码",
                                "risk_level": "低" if int(remember_count) >= 5 else "中",
                                "remediation": "建议设置remember=12或更高"
                            })
                            break
                else:
                    checks.append({
                        "name": "密码历史策略", 
                        "category": "密码策略",
                        "passed": False,
                        "description": "未配置密码历史策略",
                        "risk_level": "高",
                        "remediation": "在PAM配置中添加password required pam_unix.so remember=12"
                    })
                        
        except Exception as e:
            print(f"❌ 密码历史检查错误: {e}")
            
        return checks
    
    @staticmethod
    def _check_account_lockout_policy() -> List[Dict[str, Any]]:
        """检查账户锁定策略"""
        checks = []
        
        try:
            if RealComplianceChecker._is_linux():
                # 检查PAM的账户锁定配置
                for pam_file in ["/etc/pam.d/common-auth", "/etc/pam.d/system-auth"]:
                    if Path(pam_file).exists():
                        with open(pam_file, 'r') as f:
                            content = f.read()
                        
                        if 'pam_tally2.so' in content or 'pam_faillock.so' in content:
                            checks.append({
                                "name": "账户锁定策略",
                                "category": "密码策略",
                                "passed": True,
                                "description": f"系统配置了账户锁定策略",
                                "risk_level": "低"
                            })
                            break
                else:
                    checks.append({
                        "name": "账户锁定策略",
                        "category": "密码策略",
                        "passed": False,
                        "description": "未配置账户锁定策略",
                        "risk_level": "中",
                        "remediation": "在PAM配置中添加账户锁定模块(pam_tally2或pam_faillock)"
                    })
                        
        except Exception as e:
            print(f"❌ 账户锁定策略检查错误: {e}")
            
        return checks
    
    @staticmethod
    def _check_ssh_config() -> List[Dict[str, Any]]:
        """检查SSH安全配置"""
        checks = []
        
        try:
            ssh_config_file = "/etc/ssh/sshd_config"
            
            if Path(ssh_config_file).exists():
                with open(ssh_config_file, 'r') as f:
                    content = f.read()
                
                # 检查关键安全配置
                security_checks = [
                    {
                        "name": "SSH Root登录禁用",
                        "config": "PermitRootLogin",
                        "expected": ["no", "prohibit-password"],
                        "risk": "高"
                    },
                    {
                        "name": "SSH密码认证",
                        "config": "PasswordAuthentication", 
                        "expected": ["no"],
                        "risk": "中"
                    },
                    {
                        "name": "空密码禁止",
                        "config": "PermitEmptyPasswords",
                        "expected": ["no"],
                        "risk": "高"
                    },
                    {
                        "name": "最大认证尝试次数",
                        "config": "MaxAuthTries",
                        "expected": lambda x: int(x) <= 3,
                        "risk": "中"
                    },
                    {
                        "name": "SSH协议版本",
                        "config": "Protocol",
                        "expected": lambda x: int(x) >= 2,
                        "risk": "高"
                    }
                ]
                
                for check in security_checks:
                    config_match = re.search(rf'^\s*{check["config"]}\s+(\S+)', content, re.MULTILINE | re.IGNORECASE)
                    if config_match:
                        value = config_match.group(1).lower()
                        
                        if callable(check["expected"]):
                            passed = check["expected"](value)
                        else:
                            passed = value in check["expected"]
                        
                        checks.append({
                            "name": check["name"],
                            "category": "SSH配置",
                            "passed": passed,
                            "description": f"{check['config']} = {value}",
                            "risk_level": check["risk"],
                            "remediation": f"建议设置 {check['config']} {check['expected']}" if not passed else None
                        })
                    else:
                        checks.append({
                            "name": check["name"],
                            "category": "SSH配置",
                            "passed": False,
                            "description": f"未配置 {check['config']}",
                            "risk_level": check["risk"],
                            "remediation": f"在sshd_config中明确设置 {check['config']}"
                        })
                
                return checks

        except Exception as e:
            print(f"❌ SSH配置检查错误: {e}")
            checks.append({
                "name": "SSH配置检查",
                "category": "SSH配置",
                "passed": False,
                "description": f"检查失败: {str(e)}",
                "risk_level": "中"
            })

            # 🟢 修复重点：确保无论如何最后都返回 checks 列表
        return checks
    
    @staticmethod
    def _check_firewall() -> List[Dict[str, Any]]:
        """检查防火墙状态"""
        checks = []
        
        try:
            if RealComplianceChecker._is_linux():
                # 检查UFW状态
                try:
                    result = subprocess.run(['ufw', 'status'], capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        if "Status: active" in result.stdout:
                            checks.append({
                                "name": "UFW防火墙状态",
                                "category": "防火墙",
                                "passed": True,
                                "description": "UFW防火墙正在运行",
                                "risk_level": "低"
                            })
                        else:
                            checks.append({
                                "name": "UFW防火墙状态",
                                "category": "防火墙", 
                                "passed": False,
                                "description": "UFW防火墙未运行",
                                "risk_level": "高",
                                "remediation": "运行 'ufw enable' 启用防火墙"
                            })
                except Exception:
                    pass
                
                # 检查iptables
                try:
                    result = subprocess.run(['iptables', '-L', '-n'], capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        if "Chain INPUT" in result.stdout and "Chain FORWARD" in result.stdout:
                            # 检查是否有实际规则
                            lines = result.stdout.split('\n')
                            rule_count = sum(1 for line in lines if line and not line.startswith('Chain') 
                                           and not line.startswith('target') and not line.startswith('num'))
                            if rule_count > 0:
                                checks.append({
                                    "name": "iptables配置",
                                    "category": "防火墙",
                                    "passed": True, 
                                    "description": f"iptables规则已配置 ({rule_count} 条规则)",
                                    "risk_level": "低"
                                })
                            else:
                                checks.append({
                                    "name": "iptables配置",
                                    "category": "防火墙",
                                    "passed": False,
                                    "description": "iptables未配置有效规则",
                                    "risk_level": "高"
                                })
                except Exception:
                    pass
                
                # 检查firewalld (CentOS/RHEL)
                try:
                    result = subprocess.run(['firewall-cmd', '--state'], capture_output=True, text=True, timeout=10)
                    if result.returncode == 0 and "running" in result.stdout:
                        checks.append({
                            "name": "firewalld状态",
                            "category": "防火墙",
                            "passed": True,
                            "description": "firewalld正在运行",
                            "risk_level": "低"
                        })
                except Exception:
                    pass
                
                # 如果没有发现防火墙
                if not any(check['name'] in ['UFW防火墙状态', 'iptables配置', 'firewalld状态'] for check in checks):
                    checks.append({
                        "name": "防火墙状态",
                        "category": "防火墙",
                        "passed": False,
                        "description": "未检测到运行的防火墙",
                        "risk_level": "高",
                        "remediation": "安装并配置UFW、iptables或firewalld防火墙"
                    })
                
                return checks

        except Exception as e:
            print(f"❌ 防火墙检查错误: {e}")
            checks.append({
                "name": "防火墙检查",
                "category": "防火墙",
                "passed": False,
                "description": f"检查失败: {str(e)}",
                "risk_level": "高"
            })

            # 🟢 修复重点：确保最后返回 checks
        return checks
    
    @staticmethod
    def _check_system_security() -> List[Dict[str, Any]]:
        """检查系统安全配置"""
        checks = []
        
        try:
            # 检查SELinux/AppArmor
            if RealComplianceChecker._is_linux():
                # SELinux检查
                try:
                    result = subprocess.run(['getenforce'], capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        selinux_status = result.stdout.strip()
                        checks.append({
                            "name": "SELinux状态",
                            "category": "系统安全",
                            "passed": selinux_status == "Enforcing",
                            "description": f"SELinux状态: {selinux_status}",
                            "risk_level": "低" if selinux_status == "Enforcing" else "高"
                        })
                except Exception:
                    pass
                
                # 检查AppArmor
                try:
                    result = subprocess.run(['aa-status', '--enforced'], capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        checks.append({
                            "name": "AppArmor状态",
                            "category": "系统安全",
                            "passed": True,
                            "description": "AppArmor已启用并执行策略",
                            "risk_level": "低"
                        })
                    else:
                        # 检查aa-status是否存在
                        result = subprocess.run(['which', 'aa-status'], capture_output=True, text=True, timeout=5)
                        if result.returncode == 0:
                            checks.append({
                                "name": "AppArmor状态",
                                "category": "系统安全",
                                "passed": False,
                                "description": "AppArmor未完全启用",
                                "risk_level": "中"
                            })
                except Exception:
                    pass
                
                # 检查自动安全更新
                try:
                    if Path("/etc/apt/apt.conf.d/20auto-upgrades").exists():
                        with open("/etc/apt/apt.conf.d/20auto-upgrades", 'r') as f:
                            content = f.read()
                            if 'APT::Periodic::Update-Package-Lists "1";' in content and 'APT::Periodic::Unattended-Upgrade "1";' in content:
                                checks.append({
                                    "name": "自动安全更新",
                                    "category": "系统安全",
                                    "passed": True,
                                    "description": "已配置自动安全更新",
                                    "risk_level": "低"
                                })
                            else:
                                checks.append({
                                    "name": "自动安全更新",
                                    "category": "系统安全",
                                    "passed": False,
                                    "description": "自动安全更新配置不完整",
                                    "risk_level": "中"
                                })
                    else:
                        checks.append({
                            "name": "自动安全更新",
                            "category": "系统安全",
                            "passed": False,
                            "description": "未配置自动安全更新",
                            "risk_level": "中",
                            "remediation": "配置unattended-upgrades包"
                        })
                except Exception:
                    pass
                
                # 检查核心转储设置
                try:
                    result = subprocess.run(['sysctl', 'kernel.core_pattern'], capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        core_pattern = result.stdout.strip()
                        if 'core' in core_pattern:
                            checks.append({
                                "name": "核心转储配置",
                                "category": "系统安全",
                                "passed": False,
                                "description": f"核心转储已启用: {core_pattern}",
                                "risk_level": "中",
                                "remediation": "考虑禁用核心转储以防止敏感信息泄露"
                            })
                except Exception:
                    pass
            
            return checks
            
        except Exception as e:
            print(f"❌ 系统安全检查错误: {e}")
            return []
    
    @staticmethod
    def _check_network_security() -> List[Dict[str, Any]]:
        """检查网络安全配置"""
        checks = []
        
        try:
            if RealComplianceChecker._is_linux():
                # 检查ICMP重定向
                try:
                    result = subprocess.run(['sysctl', 'net.ipv4.conf.all.accept_redirects'], capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        value = result.stdout.split('=')[1].strip()
                        if value == '0':
                            checks.append({
                                "name": "ICMP重定向保护",
                                "category": "网络安全",
                                "passed": True,
                                "description": "已禁用ICMP重定向",
                                "risk_level": "低"
                            })
                        else:
                            checks.append({
                                "name": "ICMP重定向保护",
                                "category": "网络安全",
                                "passed": False,
                                "description": "ICMP重定向未禁用",
                                "risk_level": "中"
                            })
                except Exception:
                    pass
                
                # 检查源路由
                try:
                    result = subprocess.run(['sysctl', 'net.ipv4.conf.all.accept_source_route'], capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        value = result.stdout.split('=')[1].strip()
                        if value == '0':
                            checks.append({
                                "name": "源路由保护",
                                "category": "网络安全",
                                "passed": True,
                                "description": "已禁用源路由",
                                "risk_level": "低"
                            })
                        else:
                            checks.append({
                                "name": "源路由保护",
                                "category": "网络安全",
                                "passed": False,
                                "description": "源路由未禁用",
                                "risk_level": "中"
                            })
                except Exception:
                    pass
                
                # 检查SYN Cookie保护
                try:
                    result = subprocess.run(['sysctl', 'net.ipv4.tcp_syncookies'], capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        value = result.stdout.split('=')[1].strip()
                        if value == '1':
                            checks.append({
                                "name": "SYN Flood保护",
                                "category": "网络安全",
                                "passed": True,
                                "description": "已启用SYN Cookie保护",
                                "risk_level": "低"
                            })
                        else:
                            checks.append({
                                "name": "SYN Flood保护",
                                "category": "网络安全",
                                "passed": False,
                                "description": "SYN Cookie保护未启用",
                                "risk_level": "中"
                            })
                except Exception:
                    pass
            
            return checks
            
        except Exception as e:
            print(f"❌ 网络安全检查错误: {e}")
            return []
