# core/report_generator_fixed_safe.py
"""
SecKeeper PDF 报告生成器 - 双核验证增强版

设计目标：
1. 兼容旧版 scan_data 结构，避免影响现有 Flask / 前端调用。
2. 兼容新版 real_vulnerability_scanner.py 输出：scan_summary、summary、detector_metrics、errors、warnings。
3. 在报告中突出 SecKeeper 的核心能力：Local Verify / Network Verify / Verified / Need Confirmation。
4. 保持 ReportLab 生成方式，避免引入新的运行时依赖。
"""

from datetime import datetime
import os
import re
import traceback
from typing import Any, Dict, List, Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import inch
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle


class ReportGeneratorFixedSafe:
    """SecKeeper 安全巡检 PDF 报告生成器。"""

    CHINESE_FONT = "Helvetica"
    ENGLISH_FONT = "Helvetica"
    FONTS_CONFIGURED = False

    SEVERITY_LABELS = {
        "critical": "严重",
        "high": "高危",
        "medium": "中危",
        "low": "低危",
        "info": "信息",
        "unknown": "未知",
    }

    VERIFY_LABELS = {
        "verified": "已验证",
        "unverified": "疑似/未验证",
        "needs_manual_check": "待人工确认",
        "no_poc": "暂无PoC",
        "failed": "验证失败",
        "tool_missing": "工具缺失",
        "timeout": "验证超时",
        "exec_error": "执行异常",
        "unknown": "未知",
    }

    METHOD_LABELS = {
        "local": "Local Verify / Python PoC",
        "network": "Network Verify / Nuclei YAML",
        "version_match": "规则版本初筛",
        "rule_match": "规则命中",
        "manual": "人工确认",
        None: "未标注",
        "": "未标注",
    }

    SAFETY_LABELS = {
        "safe_probe": "无害探测",
        "environment_probe": "环境探针",
        "version_probe": "版本探针",
        "auth_probe": "口令/授权探测",
        "sensitive_read": "敏感读取验证",
        "active_probe": "深度无害验证",
        "oob_probe": "OOB验证",
        None: "未标注",
        "": "未标注",
    }

    XINCHUANG_KEYWORDS = [
        "kylin", "麒麟", "银河麒麟",
        "uos", "统信", "deepin", "深度",
        "dameng", "达梦", "dmserver",
        "kingbase", "金仓", "人大金仓",
        "tongweb", "东方通",
        "国产", "信创",
    ]

    # ------------------------------------------------------------------
    # 字体与样式
    # ------------------------------------------------------------------
    @staticmethod
    def _setup_fonts() -> None:
        if ReportGeneratorFixedSafe.FONTS_CONFIGURED:
            return

        try:
            english_font_paths = [
                "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
                "/usr/share/fonts/truetype/dejavu/DejaVuSansCondensed.ttf",
                "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
                "/usr/share/fonts/truetype/freefont/FreeSans.ttf",
            ]
            chinese_font_paths = [
                "/usr/share/fonts/truetype/noto/NotoSansCJK-Regular.ttc",
                "/usr/share/fonts/truetype/noto/NotoSansSC-Regular.otf",
                "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
                "/usr/share/fonts/truetype/wqy/wqy-microhei.ttc",
                "/usr/share/fonts/truetype/wqy/wqy-zenhei.ttc",
                "/usr/share/fonts/truetype/arphic/uming.ttc",
                "/usr/share/fonts/truetype/arphic/ukai.ttc",
                "/usr/share/fonts/truetype/droid/DroidSansFallbackFull.ttf",
            ]

            for font_path in english_font_paths:
                if os.path.exists(font_path):
                    try:
                        font_name = f"English_{os.path.basename(font_path).split('.')[0]}"
                        pdfmetrics.registerFont(TTFont(font_name, font_path))
                        ReportGeneratorFixedSafe.ENGLISH_FONT = font_name
                        break
                    except Exception:
                        continue

            for font_path in chinese_font_paths:
                if os.path.exists(font_path):
                    try:
                        font_name = f"Chinese_{os.path.basename(font_path).split('.')[0]}"
                        pdfmetrics.registerFont(TTFont(font_name, font_path))
                        ReportGeneratorFixedSafe.CHINESE_FONT = font_name
                        break
                    except Exception:
                        continue

            # 如果找不到中文字体，至少使用可用英文字体，避免直接失败。
            if ReportGeneratorFixedSafe.CHINESE_FONT == "Helvetica":
                ReportGeneratorFixedSafe.CHINESE_FONT = ReportGeneratorFixedSafe.ENGLISH_FONT

            ReportGeneratorFixedSafe.FONTS_CONFIGURED = True
        except Exception as e:
            print(f"⚠️ PDF字体初始化失败，使用默认字体: {e}")
            ReportGeneratorFixedSafe.CHINESE_FONT = "Helvetica"
            ReportGeneratorFixedSafe.ENGLISH_FONT = "Helvetica"
            ReportGeneratorFixedSafe.FONTS_CONFIGURED = True

    @staticmethod
    def _create_styles() -> Dict[str, ParagraphStyle]:
        ReportGeneratorFixedSafe._setup_fonts()
        styles = getSampleStyleSheet()
        font = ReportGeneratorFixedSafe.CHINESE_FONT

        return {
            "title": ParagraphStyle(
                "SecKeeperTitle",
                parent=styles["Heading1"],
                fontName=font,
                fontSize=18,
                leading=24,
                alignment=1,
                textColor=colors.HexColor("#1f2937"),
                spaceAfter=18,
            ),
            "subtitle": ParagraphStyle(
                "SecKeeperSubtitle",
                parent=styles["Normal"],
                fontName=font,
                fontSize=10,
                leading=14,
                alignment=1,
                textColor=colors.HexColor("#4b5563"),
                spaceAfter=16,
            ),
            "heading2": ParagraphStyle(
                "SecKeeperHeading2",
                parent=styles["Heading2"],
                fontName=font,
                fontSize=14,
                leading=18,
                textColor=colors.HexColor("#111827"),
                spaceBefore=8,
                spaceAfter=10,
            ),
            "heading3": ParagraphStyle(
                "SecKeeperHeading3",
                parent=styles["Heading3"],
                fontName=font,
                fontSize=11,
                leading=15,
                textColor=colors.HexColor("#374151"),
                spaceBefore=6,
                spaceAfter=6,
            ),
            "normal": ParagraphStyle(
                "SecKeeperNormal",
                parent=styles["Normal"],
                fontName=font,
                fontSize=9,
                leading=13,
                textColor=colors.HexColor("#111827"),
                spaceAfter=6,
            ),
            "small": ParagraphStyle(
                "SecKeeperSmall",
                parent=styles["Normal"],
                fontName=font,
                fontSize=7.5,
                leading=10,
                textColor=colors.HexColor("#374151"),
            ),
        }

    # ------------------------------------------------------------------
    # 通用数据适配
    # ------------------------------------------------------------------
    @staticmethod
    def _safe_get_data(data: Any, keys: List[str], default: Any = "未知") -> Any:
        try:
            current = data
            for key in keys:
                if isinstance(current, dict) and key in current:
                    current = current[key]
                else:
                    return default
            return current if current is not None else default
        except Exception:
            return default

    @staticmethod
    def _clean_text(value: Any, max_len: Optional[int] = None) -> str:
        if value is None:
            text = ""
        elif isinstance(value, (list, tuple)):
            text = ", ".join(str(v) for v in value)
        elif isinstance(value, dict):
            text = "; ".join(f"{k}: {v}" for k, v in value.items())
        else:
            text = str(value)

        # ReportLab Paragraph 对 &, <, > 敏感，做最小转义。
        text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        text = re.sub(r"\s+", " ", text).strip()
        if max_len and len(text) > max_len:
            text = text[: max_len - 3] + "..."
        return text or "-"

    @staticmethod
    def _paragraph(value: Any, styles: Dict[str, ParagraphStyle], style_name: str = "small", max_len: Optional[int] = None) -> Paragraph:
        return Paragraph(ReportGeneratorFixedSafe._clean_text(value, max_len), styles[style_name])

    @staticmethod
    def _as_list(value: Any) -> List[Any]:
        return value if isinstance(value, list) else []

    @staticmethod
    def _get_vulnerability_payload(scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """兼容旧结构和新版漏洞扫描结构。"""
        vuln_payload = scan_data.get("vulnerabilities", {}) if isinstance(scan_data, dict) else {}
        if isinstance(vuln_payload, list):
            return {"vulnerabilities": vuln_payload}
        if not isinstance(vuln_payload, dict):
            return {"vulnerabilities": []}
        return vuln_payload

    @staticmethod
    def _get_vulnerability_list(scan_data_or_payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        payload = scan_data_or_payload
        if "vulnerabilities" in payload and isinstance(payload.get("vulnerabilities"), dict):
            payload = payload.get("vulnerabilities", {})
        vulns = payload.get("vulnerabilities", []) if isinstance(payload, dict) else []
        return [v for v in vulns if isinstance(v, dict)]

    @staticmethod
    def _get_compliance_checks(compliance_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        # 新版 RealComplianceChecker 使用 checks；旧报告函数曾使用 details。
        checks = compliance_data.get("checks") if isinstance(compliance_data, dict) else []
        if not isinstance(checks, list):
            checks = compliance_data.get("details", []) if isinstance(compliance_data, dict) else []
        return [c for c in checks if isinstance(c, dict)]

    @staticmethod
    def _normalize_verify_status(vuln: Dict[str, Any]) -> str:
        status = (
            vuln.get("verification_status")
            or vuln.get("verify_status")
            or vuln.get("status")
            or "unverified"
        )
        status = str(status).strip().lower()
        if status in {"need_confirmation", "manual_check", "needs_check", "need_manual_check"}:
            return "needs_manual_check"
        if status in {"true", "confirmed", "success"}:
            return "verified"
        if status in {"false", "not_verified"}:
            return "unverified"
        return status or "unverified"

    @staticmethod
    def _normalize_method(vuln: Dict[str, Any]) -> str:
        method = (
            vuln.get("verification_method")
            or vuln.get("verify_method")
            or vuln.get("engine")
            or ""
        )
        method = str(method).strip().lower()
        detector_name = str(vuln.get("detector_name", "")).lower()
        category = str(vuln.get("category", "")).lower()

        if method in {"local", "python", "python_poc", "poc", "pocs"}:
            return "local"
        if method in {"network", "nuclei", "yaml", "yaml_pocs"}:
            return "network"
        if "service" in detector_name or "network" in category:
            return "network"
        if "cve" in detector_name or "privilege" in detector_name:
            return "local"
        return method or "version_match"

    @staticmethod
    def _compute_vuln_summary(vulns: List[Dict[str, Any]], existing_summary: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        summary = {
            "total_vulnerabilities": len(vulns),
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "verified": 0,
            "unverified": 0,
            "needs_manual_check": 0,
            "local": 0,
            "network": 0,
        }

        for vuln in vulns:
            sev = str(vuln.get("severity", "low")).lower()
            if sev not in {"critical", "high", "medium", "low", "info"}:
                sev = "low"
            summary[sev] += 1

            status = ReportGeneratorFixedSafe._normalize_verify_status(vuln)
            if status == "verified":
                summary["verified"] += 1
            elif status == "needs_manual_check":
                summary["needs_manual_check"] += 1
            else:
                summary["unverified"] += 1

            method = ReportGeneratorFixedSafe._normalize_method(vuln)
            if method == "local":
                summary["local"] += 1
            elif method == "network":
                summary["network"] += 1

        # 新版 scanner 已经计算过的值优先不覆盖，但缺失时用本地统计补齐。
        if isinstance(existing_summary, dict):
            for key, value in existing_summary.items():
                if key in summary and value not in (None, "未知"):
                    summary[key] = value
                elif key == "total" and value not in (None, "未知"):
                    summary["total_vulnerabilities"] = value

        return summary

    @staticmethod
    def _is_xinchuang_related(item: Dict[str, Any]) -> bool:
        blob = " ".join(str(v) for v in item.values()).lower()
        return any(keyword.lower() in blob for keyword in ReportGeneratorFixedSafe.XINCHUANG_KEYWORDS)

    # ------------------------------------------------------------------
    # 表格构建
    # ------------------------------------------------------------------
    @staticmethod
    def _make_table(data: List[List[Any]], col_widths: List[float], header_color: str = "#2563eb", font_size: float = 8) -> Table:
        table = Table(data, colWidths=col_widths, repeatRows=1)
        table.setStyle(TableStyle([
            ("FONT", (0, 0), (-1, -1), ReportGeneratorFixedSafe.CHINESE_FONT),
            ("FONTSIZE", (0, 0), (-1, -1), font_size),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(header_color)),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("ALIGN", (0, 0), (-1, 0), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#d1d5db")),
            ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#f9fafb")),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        return table

    @staticmethod
    def _create_overview_table(scan_data: Dict[str, Any]) -> Table:
        payload = ReportGeneratorFixedSafe._get_vulnerability_payload(scan_data)
        vulns = ReportGeneratorFixedSafe._get_vulnerability_list({"vulnerabilities": payload})
        existing_summary = payload.get("scan_summary") or payload.get("summary") or scan_data.get("scan_summary") or {}
        vuln_summary = ReportGeneratorFixedSafe._compute_vuln_summary(vulns, existing_summary)

        assets = scan_data.get("assets", {}) if isinstance(scan_data.get("assets", {}), dict) else {}
        compliance = scan_data.get("compliance", {}) if isinstance(scan_data.get("compliance", {}), dict) else {}
        compliance_summary = compliance.get("summary", {}) if isinstance(compliance.get("summary", {}), dict) else {}

        scan_time = (
            scan_data.get("timestamp")
            or scan_data.get("scan_timestamp")
            or payload.get("scan_timestamp")
            or datetime.now().isoformat()
        )
        scan_id = scan_data.get("scan_id") or payload.get("scan_id") or "未提供"

        software_count = len(ReportGeneratorFixedSafe._as_list(assets.get("software")))
        services_count = len(ReportGeneratorFixedSafe._as_list(assets.get("services")))
        compliance_total = compliance_summary.get("total", 0)
        compliance_passed = compliance_summary.get("passed", 0)
        compliance_rate = compliance_summary.get("compliance_rate", 0)

        data = [
            ["扫描时间", ReportGeneratorFixedSafe._clean_text(scan_time)],
            ["扫描ID", ReportGeneratorFixedSafe._clean_text(scan_id)],
            ["报告生成时间", datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
            ["软件资产数量", str(software_count)],
            ["服务资产数量", str(services_count)],
            ["合规检查", f"{compliance_passed}/{compliance_total} 通过，合规率 {compliance_rate}%"],
            ["漏洞总数", str(vuln_summary.get("total_vulnerabilities", 0))],
            ["验证状态", f"已验证 {vuln_summary.get('verified', 0)} / 待确认 {vuln_summary.get('needs_manual_check', 0)} / 疑似 {vuln_summary.get('unverified', 0)}"],
            ["双核验证", f"Local {vuln_summary.get('local', 0)} / Network {vuln_summary.get('network', 0)}"],
        ]
        return ReportGeneratorFixedSafe._make_table(data, [1.6 * inch, 4.6 * inch], "#1f2937", 9)

    @staticmethod
    def _create_risk_summary_table(vuln_summary: Dict[str, Any]) -> Table:
        data = [
            ["统计项", "数量"],
            ["严重(Critical)", str(vuln_summary.get("critical", 0))],
            ["高危(High)", str(vuln_summary.get("high", 0))],
            ["中危(Medium)", str(vuln_summary.get("medium", 0))],
            ["低危(Low)", str(vuln_summary.get("low", 0))],
            ["已验证漏洞", str(vuln_summary.get("verified", 0))],
            ["待人工确认", str(vuln_summary.get("needs_manual_check", 0))],
            ["疑似/未验证", str(vuln_summary.get("unverified", 0))],
            ["Local Verify", str(vuln_summary.get("local", 0))],
            ["Network Verify", str(vuln_summary.get("network", 0))],
        ]
        return ReportGeneratorFixedSafe._make_table(data, [2.4 * inch, 1.2 * inch], "#7c3aed", 8.5)

    @staticmethod
    def _create_software_table(software_list: List[Dict[str, Any]], styles: Dict[str, ParagraphStyle]) -> Optional[Table]:
        if not software_list:
            return None
        data = [["软件名称", "版本", "类型/包管理器"]]
        for software in software_list[:20]:
            data.append([
                ReportGeneratorFixedSafe._paragraph(software.get("name", "未知"), styles, max_len=35),
                ReportGeneratorFixedSafe._paragraph(software.get("version", "未知"), styles, max_len=22),
                ReportGeneratorFixedSafe._paragraph(software.get("type") or software.get("package_manager") or "未知", styles, max_len=28),
            ])
        return ReportGeneratorFixedSafe._make_table(data, [2.4 * inch, 1.5 * inch, 1.7 * inch], "#2563eb", 7.5)

    @staticmethod
    def _create_services_table(services_list: List[Dict[str, Any]], styles: Dict[str, ParagraphStyle]) -> Optional[Table]:
        if not services_list:
            return None
        data = [["服务名称", "端口", "状态/地址"]]
        for service in services_list[:15]:
            data.append([
                ReportGeneratorFixedSafe._paragraph(service.get("name", "未知"), styles, max_len=35),
                ReportGeneratorFixedSafe._paragraph(service.get("port", "未知"), styles, max_len=12),
                ReportGeneratorFixedSafe._paragraph(service.get("status") or service.get("url") or service.get("address") or "未知", styles, max_len=45),
            ])
        return ReportGeneratorFixedSafe._make_table(data, [2.2 * inch, 0.8 * inch, 2.6 * inch], "#059669", 7.5)

    @staticmethod
    def _create_compliance_table(compliance_data: Dict[str, Any], styles: Dict[str, ParagraphStyle]) -> Optional[Table]:
        checks = ReportGeneratorFixedSafe._get_compliance_checks(compliance_data)
        if not checks:
            return None

        data = [["检查项", "状态", "风险", "说明"]]
        for check in checks[:15]:
            passed = check.get("passed")
            status = check.get("status")
            if status is None:
                status = "通过" if passed is True else "未通过" if passed is False else "未知"
            data.append([
                ReportGeneratorFixedSafe._paragraph(check.get("name") or check.get("check") or "未知", styles, max_len=34),
                ReportGeneratorFixedSafe._paragraph(status, styles, max_len=10),
                ReportGeneratorFixedSafe._paragraph(check.get("risk_level") or check.get("severity") or "-", styles, max_len=12),
                ReportGeneratorFixedSafe._paragraph(check.get("description") or check.get("remediation") or "-", styles, max_len=70),
            ])
        return ReportGeneratorFixedSafe._make_table(data, [1.55 * inch, 0.65 * inch, 0.65 * inch, 2.75 * inch], "#d97706", 7)

    @staticmethod
    def _create_vulnerabilities_table(vulns: List[Dict[str, Any]], styles: Dict[str, ParagraphStyle]) -> Optional[Table]:
        if not vulns:
            return None

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_vulns = sorted(
            vulns,
            key=lambda v: (
                severity_order.get(str(v.get("severity", "low")).lower(), 9),
                0 if ReportGeneratorFixedSafe._normalize_verify_status(v) == "verified" else 1,
            ),
        )

        data = [["漏洞ID", "等级", "验证", "方式", "标题/目标", "修复建议"]]
        for vuln in sorted_vulns[:25]:
            vuln_id = vuln.get("vuln_id") or vuln.get("cve_id") or vuln.get("id") or "未知"
            severity = str(vuln.get("severity", "unknown")).lower()
            status = ReportGeneratorFixedSafe._normalize_verify_status(vuln)
            method = ReportGeneratorFixedSafe._normalize_method(vuln)
            safety = str(vuln.get("verification_safety") or "").strip().lower()
            method_label = ReportGeneratorFixedSafe.METHOD_LABELS.get(method, method)
            safety_label = ReportGeneratorFixedSafe.SAFETY_LABELS.get(safety, safety or "未标注")
            method_text = f"{method_label} / {safety_label}"
            title_target = f"{vuln.get('title', '')} | {vuln.get('affected_target', '')}"

            data.append([
                ReportGeneratorFixedSafe._paragraph(vuln_id, styles, max_len=18),
                ReportGeneratorFixedSafe._paragraph(ReportGeneratorFixedSafe.SEVERITY_LABELS.get(severity, severity), styles, max_len=8),
                ReportGeneratorFixedSafe._paragraph(ReportGeneratorFixedSafe.VERIFY_LABELS.get(status, status), styles, max_len=18),
                ReportGeneratorFixedSafe._paragraph(method_text, styles, max_len=34),
                ReportGeneratorFixedSafe._paragraph(title_target, styles, max_len=80),
                ReportGeneratorFixedSafe._paragraph(vuln.get("remediation", "请结合业务影响进行修复"), styles, max_len=80),
            ])

        return ReportGeneratorFixedSafe._make_table(
            data,
            [0.85 * inch, 0.45 * inch, 0.75 * inch, 1.0 * inch, 1.45 * inch, 1.35 * inch],
            "#dc2626",
            6.5,
        )

    @staticmethod
    def _create_xinchuang_table(scan_data: Dict[str, Any], vulns: List[Dict[str, Any]], styles: Dict[str, ParagraphStyle]) -> Optional[Table]:
        assets = scan_data.get("assets", {}) if isinstance(scan_data.get("assets", {}), dict) else {}
        software = [s for s in ReportGeneratorFixedSafe._as_list(assets.get("software")) if isinstance(s, dict)]
        services = [s for s in ReportGeneratorFixedSafe._as_list(assets.get("services")) if isinstance(s, dict)]
        compliance = scan_data.get("compliance", {}) if isinstance(scan_data.get("compliance", {}), dict) else {}
        checks = ReportGeneratorFixedSafe._get_compliance_checks(compliance)

        xc_assets = [x for x in software + services if ReportGeneratorFixedSafe._is_xinchuang_related(x)]
        xc_vulns = [v for v in vulns if ReportGeneratorFixedSafe._is_xinchuang_related(v)]
        xc_checks = [c for c in checks if ReportGeneratorFixedSafe._is_xinchuang_related(c)]

        if not (xc_assets or xc_vulns or xc_checks):
            # 即使没命中，也给报告一个明确章节，方便竞赛展示当前环境未发现信创组件。
            data = [["项目", "结果"], ["信创专项识别", "当前扫描数据中未识别到明显的银河麒麟、统信UOS、达梦、金仓、东方通等关键词。"]]
            return ReportGeneratorFixedSafe._make_table(data, [1.6 * inch, 4.4 * inch], "#0f766e", 8)

        data = [["类型", "对象", "说明"]]
        for item in xc_assets[:8]:
            data.append([
                "信创资产",
                ReportGeneratorFixedSafe._paragraph(item.get("name") or item.get("service") or "未知", styles, max_len=32),
                ReportGeneratorFixedSafe._paragraph(item.get("version") or item.get("type") or item.get("status") or "-", styles, max_len=60),
            ])
        for item in xc_checks[:8]:
            data.append([
                "信创基线",
                ReportGeneratorFixedSafe._paragraph(item.get("name") or item.get("check") or "未知", styles, max_len=32),
                ReportGeneratorFixedSafe._paragraph(item.get("description") or item.get("remediation") or "-", styles, max_len=60),
            ])
        for item in xc_vulns[:8]:
            data.append([
                "信创风险",
                ReportGeneratorFixedSafe._paragraph(item.get("vuln_id") or item.get("title") or "未知", styles, max_len=32),
                ReportGeneratorFixedSafe._paragraph(item.get("affected_target") or item.get("description") or "-", styles, max_len=60),
            ])
        return ReportGeneratorFixedSafe._make_table(data, [0.8 * inch, 1.8 * inch, 3.4 * inch], "#0f766e", 7)

    @staticmethod
    def _create_detector_metrics_table(metrics: Any, styles: Dict[str, ParagraphStyle]) -> Optional[Table]:
        if not metrics:
            return None

        rows = []
        if isinstance(metrics, dict):
            iterable = metrics.items()
            for name, info in iterable:
                if isinstance(info, dict):
                    rows.append({"name": name, **info})
                else:
                    rows.append({"name": name, "elapsed_seconds": info})
        elif isinstance(metrics, list):
            rows = [m for m in metrics if isinstance(m, dict)]

        if not rows:
            return None

        data = [["检测器", "状态", "耗时(s)", "发现数量"]]
        for row in rows:
            data.append([
                ReportGeneratorFixedSafe._paragraph(row.get("name") or row.get("detector") or row.get("detector_name") or "未知", styles, max_len=34),
                ReportGeneratorFixedSafe._paragraph(row.get("status") or ("成功" if row.get("success", True) else "失败"), styles, max_len=12),
                ReportGeneratorFixedSafe._paragraph(row.get("elapsed_seconds") or row.get("duration") or row.get("elapsed") or "-", styles, max_len=10),
                ReportGeneratorFixedSafe._paragraph(row.get("vulnerability_count") or row.get("count") or row.get("findings") or "0", styles, max_len=10),
            ])
        return ReportGeneratorFixedSafe._make_table(data, [2.2 * inch, 0.9 * inch, 0.8 * inch, 0.9 * inch], "#4b5563", 7)

    # ------------------------------------------------------------------
    # 主入口
    # ------------------------------------------------------------------
    @staticmethod
    def generate_pdf_report(scan_data: Dict[str, Any], output_path: str) -> bool:
        """生成 SecKeeper PDF 报告。"""
        try:
            if not isinstance(scan_data, dict):
                raise ValueError("scan_data 必须是 dict")

            os.makedirs(os.path.dirname(os.path.abspath(output_path)) or ".", exist_ok=True)
            ReportGeneratorFixedSafe._setup_fonts()
            styles = ReportGeneratorFixedSafe._create_styles()

            doc = SimpleDocTemplate(
                output_path,
                pagesize=A4,
                rightMargin=42,
                leftMargin=42,
                topMargin=54,
                bottomMargin=36,
                title="SecKeeper 安全巡检报告",
            )

            elements = []
            elements.append(Paragraph("SecKeeper 安全巡检报告", styles["title"]))
            elements.append(Paragraph("基于双核验证的信创生态系统安全检测平台", styles["subtitle"]))

            elements.append(Paragraph("一、巡检概览", styles["heading2"]))
            elements.append(ReportGeneratorFixedSafe._create_overview_table(scan_data))
            elements.append(Spacer(1, 14))

            payload = ReportGeneratorFixedSafe._get_vulnerability_payload(scan_data)
            vulns = ReportGeneratorFixedSafe._get_vulnerability_list({"vulnerabilities": payload})
            existing_summary = payload.get("scan_summary") or payload.get("summary") or scan_data.get("scan_summary") or {}
            vuln_summary = ReportGeneratorFixedSafe._compute_vuln_summary(vulns, existing_summary)

            elements.append(Paragraph("二、漏洞风险与双核验证统计", styles["heading2"]))
            elements.append(ReportGeneratorFixedSafe._create_risk_summary_table(vuln_summary))
            elements.append(Spacer(1, 8))
            elements.append(Paragraph(
                "说明：Local Verify 表示通过本地 Python PoC 或主机行为特征进行验证；Network Verify 表示通过 Nuclei YAML 对网络服务进行验证。待人工确认通常用于内核 Backport 等仅凭版本号难以准确判断的场景。",
                styles["normal"],
            ))
            elements.append(Spacer(1, 14))

            elements.append(Paragraph("三、信创专项识别", styles["heading2"]))
            xinchuang_table = ReportGeneratorFixedSafe._create_xinchuang_table(scan_data, vulns, styles)
            if xinchuang_table:
                elements.append(xinchuang_table)
            elements.append(Spacer(1, 14))

            assets = scan_data.get("assets", {}) if isinstance(scan_data.get("assets", {}), dict) else {}
            software_list = [x for x in ReportGeneratorFixedSafe._as_list(assets.get("software")) if isinstance(x, dict)]
            services_list = [x for x in ReportGeneratorFixedSafe._as_list(assets.get("services")) if isinstance(x, dict)]

            if software_list:
                elements.append(Paragraph("四、软件资产摘要", styles["heading2"]))
                table = ReportGeneratorFixedSafe._create_software_table(software_list, styles)
                if table:
                    elements.append(table)
                    if len(software_list) > 20:
                        elements.append(Paragraph(f"注：软件资产共 {len(software_list)} 项，报告仅展示前 20 项。", styles["small"]))
                elements.append(Spacer(1, 12))

            if services_list:
                elements.append(Paragraph("五、服务资产摘要", styles["heading2"]))
                table = ReportGeneratorFixedSafe._create_services_table(services_list, styles)
                if table:
                    elements.append(table)
                    if len(services_list) > 15:
                        elements.append(Paragraph(f"注：服务资产共 {len(services_list)} 项，报告仅展示前 15 项。", styles["small"]))
                elements.append(Spacer(1, 12))

            compliance = scan_data.get("compliance", {}) if isinstance(scan_data.get("compliance", {}), dict) else {}
            compliance_table = ReportGeneratorFixedSafe._create_compliance_table(compliance, styles)
            if compliance_table:
                elements.append(Paragraph("六、合规检查详情", styles["heading2"]))
                elements.append(compliance_table)
                elements.append(Spacer(1, 12))

            vuln_table = ReportGeneratorFixedSafe._create_vulnerabilities_table(vulns, styles)
            if vuln_table:
                elements.append(PageBreak())
                elements.append(Paragraph("七、漏洞明细", styles["heading2"]))
                elements.append(vuln_table)
                if len(vulns) > 25:
                    elements.append(Paragraph(f"注：漏洞共 {len(vulns)} 项，报告仅展示前 25 项。", styles["small"]))
                elements.append(Spacer(1, 12))
            else:
                elements.append(Paragraph("七、漏洞明细", styles["heading2"]))
                elements.append(Paragraph("本次扫描未发现可展示的漏洞记录。", styles["normal"]))
                elements.append(Spacer(1, 12))

            metrics = payload.get("detector_metrics") or scan_data.get("detector_metrics")
            metrics_table = ReportGeneratorFixedSafe._create_detector_metrics_table(metrics, styles)
            if metrics_table:
                elements.append(Paragraph("八、检测器执行状态", styles["heading2"]))
                elements.append(metrics_table)
                elements.append(Spacer(1, 12))

            errors = payload.get("errors") or scan_data.get("errors") or []
            warnings = payload.get("warnings") or scan_data.get("warnings") or []
            if errors or warnings:
                elements.append(Paragraph("九、异常与告警", styles["heading2"]))
                issue_rows = [["类型", "内容"]]
                for err in ReportGeneratorFixedSafe._as_list(errors)[:10]:
                    issue_rows.append(["错误", ReportGeneratorFixedSafe._paragraph(err, styles, max_len=120)])
                for warn in ReportGeneratorFixedSafe._as_list(warnings)[:10]:
                    issue_rows.append(["告警", ReportGeneratorFixedSafe._paragraph(warn, styles, max_len=120)])
                elements.append(ReportGeneratorFixedSafe._make_table(issue_rows, [0.8 * inch, 5.0 * inch], "#6b7280", 7))
                elements.append(Spacer(1, 12))

            elements.append(Paragraph("十、结论与建议", styles["heading2"]))
            conclusion = (
                f"本次巡检共发现 {vuln_summary.get('total_vulnerabilities', 0)} 个漏洞或风险项，"
                f"其中已验证 {vuln_summary.get('verified', 0)} 个，待人工确认 {vuln_summary.get('needs_manual_check', 0)} 个。"
                "建议优先修复严重和高危漏洞；对待确认的内核类风险，应结合发行版安全公告、补丁回溯记录和业务影响进一步确认。"
                "对于 Network Verify 命中的服务漏洞，应优先限制暴露面并升级组件；对于 Local Verify 命中的主机漏洞，应结合权限、补丁和配置进行闭环整改。"
            )
            elements.append(Paragraph(conclusion, styles["normal"]))

            doc.build(elements)

            if os.path.exists(output_path) and os.path.getsize(output_path) > 0:
                with open(output_path, "rb") as f:
                    if not f.read(4).startswith(b"%PDF"):
                        print("❌ PDF文件头校验失败")
                        return False
                print(f"✅ SecKeeper PDF报告生成成功: {output_path}")
                return True

            print("❌ PDF文件未生成")
            return False

        except Exception as e:
            print(f"❌ SecKeeper PDF报告生成失败: {e}")
            traceback.print_exc()
            return False


# 保持旧行为：模块导入时提前初始化字体，首次生成报告更稳定。
ReportGeneratorFixedSafe._setup_fonts()
