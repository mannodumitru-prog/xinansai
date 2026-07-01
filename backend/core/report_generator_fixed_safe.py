# core/report_generator_fixed_safe.py
"""
SecKeeper PDF 报告生成器 - 用户展示增强版

约束：
1. 保持 ReportGeneratorFixedSafe.generate_pdf_report(scan_data, output_path) 调用方式不变。
2. 不修改 Flask app.py、前端、Detector 或规则库接口。
3. 继续使用 ReportLab，避免新增运行时依赖。
4. 兼容旧版与新版 scan_data 数据结构。
"""

from datetime import datetime
import os
import re
import traceback
from typing import Any, Dict, List, Optional, Tuple

from reportlab.lib import colors
from reportlab.lib.colors import Color
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import inch, mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfbase.cidfonts import UnicodeCIDFont
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    KeepTogether,
    Flowable,
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle


class _SecKeeperDivider(Flowable):
    """兼容老版 ReportLab 的水平分割线。"""

    def __init__(self, width="100%", thickness=1, color=colors.HexColor("#D7E3F0"), space_before=3, space_after=8):
        Flowable.__init__(self)
        self.width_spec = width
        self.thickness = thickness
        self.color = color
        self.space_before = space_before
        self.space_after = space_after
        self.height = space_before + thickness + space_after

    def wrap(self, avail_width, avail_height):
        self._avail_width = avail_width
        return avail_width, self.height

    def draw(self):
        width = getattr(self, "_avail_width", 0)
        if isinstance(self.width_spec, str) and self.width_spec.endswith("%"):
            try:
                width = width * float(self.width_spec[:-1]) / 100.0
            except Exception:
                pass
        elif isinstance(self.width_spec, (int, float)):
            width = float(self.width_spec)

        self.canv.saveState()
        self.canv.setStrokeColor(self.color)
        self.canv.setLineWidth(self.thickness)
        y = self.space_after + self.thickness / 2.0
        self.canv.line(0, y, width, y)
        self.canv.restoreState()


class ReportGeneratorFixedSafe:
    """SecKeeper 安全巡检 PDF 报告生成器。"""

    CHINESE_FONT = "Helvetica"
    ENGLISH_FONT = "Helvetica"
    FONTS_CONFIGURED = False

    # 商业安全报告配色：白底 + 深蓝 + 科技蓝
    COLOR_NAVY = "#0B1F3A"
    COLOR_NAVY_2 = "#102A4C"
    COLOR_BLUE = "#0EA5E9"
    COLOR_BLUE_DARK = "#0369A1"
    COLOR_BLUE_SOFT = "#E0F2FE"
    COLOR_BORDER = "#AFC7DF"
    COLOR_TEXT = "#0B1220"
    COLOR_MUTED = "#1E293B"
    COLOR_PANEL = "#EEF6FF"
    COLOR_CARD = "#FFFFFF"

    SEVERITY_LABELS = {
        "critical": "严重",
        "high": "高危",
        "medium": "中危",
        "low": "低危",
        "info": "提示",
        "unknown": "未知",
    }

    SEVERITY_COLORS = {
        "critical": "#B42318",  # 深红，控制面积，仅用于风险强调
        "high": "#C2410C",      # 深橙
        "medium": "#A16207",    # 暗金
        "low": "#2563EB",       # 科技蓝
        "info": "#64748B",
        "unknown": "#64748B",
    }

    VERIFY_LABELS = {
        "verified": "已验证",
        "unverified": "疑似漏洞",
        "needs_manual_check": "待确认",
        "no_poc": "暂无 PoC",
        "failed": "验证失败",
        "tool_missing": "工具缺失",
        "timeout": "验证超时",
        "exec_error": "执行异常",
        "unknown": "未知",
    }

    METHOD_LABELS = {
        "local": "本地验证",
        "network": "网络验证",
        "version_match": "版本匹配",
        "rule_match": "规则初筛",
        "manual": "人工确认",
        None: "未标注",
        "": "未标注",
    }

    SAFETY_LABELS = {
        "safe_probe": "安全探针",
        "environment_probe": "环境探针",
        "version_probe": "版本探针",
        "auth_probe": "口令/授权探测",
        "sensitive_read": "敏感读取验证",
        "active_probe": "主动验证",
        "oob_probe": "OOB 验证",
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
                "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
                "/usr/share/fonts/truetype/noto/NotoSansCJK-Regular.ttc",
                "/usr/share/fonts/truetype/noto/NotoSansSC-Regular.otf",
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

            if ReportGeneratorFixedSafe.CHINESE_FONT == "Helvetica":
                try:
                    pdfmetrics.registerFont(UnicodeCIDFont("STSong-Light"))
                    ReportGeneratorFixedSafe.CHINESE_FONT = "STSong-Light"
                except Exception:
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
        base = getSampleStyleSheet()
        font = ReportGeneratorFixedSafe.CHINESE_FONT

        styles = {
            "cover_brand": ParagraphStyle(
                "SecKeeperCoverBrand", parent=base["Title"], fontName=font,
                fontSize=32, leading=40, textColor=colors.HexColor(ReportGeneratorFixedSafe.COLOR_NAVY),
                alignment=0, spaceAfter=8,
            ),
            "cover_title": ParagraphStyle(
                "SecKeeperCoverTitle", parent=base["Heading1"], fontName=font,
                fontSize=21, leading=29, textColor=colors.HexColor(ReportGeneratorFixedSafe.COLOR_NAVY_2),
                alignment=0, spaceAfter=4,
            ),
            "cover_subtitle": ParagraphStyle(
                "SecKeeperCoverSubTitle", parent=base["Normal"], fontName=font,
                fontSize=13.2, leading=18.4, textColor=colors.HexColor(ReportGeneratorFixedSafe.COLOR_TEXT),
                alignment=0, spaceAfter=12,
            ),
            "section": ParagraphStyle(
                "SecKeeperSection", parent=base["Heading2"], fontName=font,
                fontSize=18, leading=24, textColor=colors.HexColor(ReportGeneratorFixedSafe.COLOR_NAVY),
                spaceBefore=12, spaceAfter=8,
            ),
            "section_hint": ParagraphStyle(
                "SecKeeperSectionHint", parent=base["Normal"], fontName=font,
                fontSize=11.0, leading=15.8, textColor=colors.HexColor("#111827"),
                spaceAfter=8,
            ),
            "card_title": ParagraphStyle(
                "SecKeeperCardTitle", parent=base["Heading3"], fontName=font,
                fontSize=13.0, leading=17.2, textColor=colors.HexColor(ReportGeneratorFixedSafe.COLOR_NAVY),
                spaceAfter=4,
            ),
            "normal": ParagraphStyle(
                "SecKeeperNormal", parent=base["Normal"], fontName=font,
                fontSize=11.6, leading=16.6, textColor=colors.HexColor(ReportGeneratorFixedSafe.COLOR_TEXT),
                spaceAfter=5,
            ),
            "small": ParagraphStyle(
                "SecKeeperSmall", parent=base["Normal"], fontName=font,
                fontSize=10.4, leading=14.4, textColor=colors.HexColor("#111827"),
            ),
            "tiny": ParagraphStyle(
                "SecKeeperTiny", parent=base["Normal"], fontName=font,
                fontSize=9.8, leading=13.8, textColor=colors.HexColor("#0F172A"),
            ),
            "metric_value": ParagraphStyle(
                "SecKeeperMetricValue", parent=base["Normal"], fontName=font,
                fontSize=20.0, leading=24.5, textColor=colors.HexColor(ReportGeneratorFixedSafe.COLOR_NAVY),
                alignment=1,
            ),
            "metric_label": ParagraphStyle(
                "SecKeeperMetricLabel", parent=base["Normal"], fontName=font,
                fontSize=9.8, leading=12.6, textColor=colors.HexColor(ReportGeneratorFixedSafe.COLOR_MUTED),
                alignment=1,
            ),
            "tag": ParagraphStyle(
                "SecKeeperTag", parent=base["Normal"], fontName=font,
                fontSize=9.4, leading=12.2, textColor=colors.white,
                alignment=1,
            ),
        }
        # CJK word wrapping prevents awkward line breaks and keeps Chinese text readable.
        for _style in styles.values():
            try:
                _style.wordWrap = "CJK"
                _style.splitLongWords = 0
            except Exception:
                pass
        return styles

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

        # 移除面向开发/内部提示的参考性话术，报告面向最终用户展示。
        reference_patterns = [
            r"本条结果仅供参考[^。；;\n]*[。；;]?",
            r"该结果仅供参考[^。；;\n]*[。；;]?",
            r"仅供参考[^。；;\n]*[。；;]?",
            r"结果仅供参考[^。；;\n]*[。；;]?",
        ]
        for pattern in reference_patterns:
            text = re.sub(pattern, "", text, flags=re.IGNORECASE)

        # 避免部分老旧 PDF 字体缺字导致方块乱码；保留语义，替换为常见 ASCII/中文字符。
        replacements = {
            "✅": "通过", "✔": "通过", "✓": "通过",
            "❌": "失败", "✖": "失败", "✕": "失败",
            "⚠️": "警告", "⚠": "警告", "🔴": "", "🟠": "", "🟡": "", "🔵": "",
            "→": "->", "⇒": "=>", "↔": "<->",
            "•": "-", "·": "-", "●": "-", "■": "-", "□": "", "☐": "", "☑": "", "☒": "", "▪": "-", "▫": "-", "◆": "-", "◇": "-", "�": "",
            "Ⅰ": "I", "Ⅱ": "II", "Ⅲ": "III", "Ⅳ": "IV",
            "—": "-", "–": "-", "−": "-", "…": "...",
            "“": """, "”": """, "‘": "'", "’": "'",
            "（": "(", "）": ")", "：": ": ", "；": "; ",
        }
        for src, dst in replacements.items():
            text = text.replace(src, dst)

        # 面向用户展示：将常见英文状态、风险和运行状态转为中文，避免报告出现 failed / passed 等开发侧字段。
        word_map = {
            "failed": "失败", "failure": "失败", "error": "错误",
            "success": "成功", "successful": "成功",
            "passed": "通过", "pass": "通过",
            "true": "是", "false": "否",
            "running": "运行中", "active": "运行中", "stopped": "已停止", "inactive": "未运行",
            "enabled": "已启用", "disabled": "已禁用", "open": "开启", "closed": "关闭",
            "unknown": "未知", "none": "无", "null": "无",
            "critical": "严重", "high": "高危", "medium": "中危", "low": "低危", "info": "提示",
            "verified": "已验证", "unverified": "疑似漏洞", "timeout": "超时",
            "needs_manual_check": "待确认", "need_manual_check": "待确认", "manual_check": "待确认",
        }
        for word, cn in word_map.items():
            text = re.sub(rf"(?<![A-Za-z0-9_]){re.escape(word)}(?![A-Za-z0-9_])", cn, text, flags=re.IGNORECASE)

        # 移除常见 emoji / 私有区字符，避免老版 ReportLab 或缺字字体显示方块。
        text = re.sub(r"[\U00010000-\U0010ffff]", "", text)
        text = re.sub(r"[\ue000-\uf8ff]", "", text)
        text = re.sub(r"[\u25a0-\u25ff]", "", text)
        text = re.sub(r"[\u200b-\u200f\u2028\u2029\u2060\ufeff\ufe0e\ufe0f]", "", text)
        text = re.sub(r"[\u2600-\u27bf]", "", text)
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
        vuln_payload = scan_data.get("vulnerabilities", {}) if isinstance(scan_data, dict) else {}
        if isinstance(vuln_payload, list):
            return {"vulnerabilities": vuln_payload}
        if not isinstance(vuln_payload, dict):
            return {"vulnerabilities": []}
        return vuln_payload

    @staticmethod
    def _get_vulnerability_list(scan_data_or_payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        payload = scan_data_or_payload
        if isinstance(payload, dict) and "vulnerabilities" in payload and isinstance(payload.get("vulnerabilities"), dict):
            payload = payload.get("vulnerabilities", {})
        vulns = payload.get("vulnerabilities", []) if isinstance(payload, dict) else []
        return [v for v in vulns if isinstance(v, dict)]

    @staticmethod
    def _get_compliance_checks(compliance_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        checks = compliance_data.get("checks") if isinstance(compliance_data, dict) else []
        if not isinstance(checks, list):
            checks = compliance_data.get("details", []) if isinstance(compliance_data, dict) else []
        return [c for c in checks if isinstance(c, dict)]

    @staticmethod
    def _normalize_verify_status(vuln: Dict[str, Any]) -> str:
        status = vuln.get("verification_status") or vuln.get("verify_status") or vuln.get("status") or "unverified"
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
        method = vuln.get("verification_method") or vuln.get("verify_method") or vuln.get("engine") or ""
        method = str(method).strip().lower()
        detector_name = str(vuln.get("detector_name", "")).lower()
        category = str(vuln.get("category", "")).lower()

        if method in {"local", "python", "python_poc", "poc", "pocs"}:
            return "local"
        if method in {"network", "nuclei", "yaml", "yaml_pocs"}:
            return "network"
        if method in {"version", "version_match", "package", "cpe"}:
            return "version_match"
        if "service" in detector_name or "network" in category:
            return "network"
        if "cve" in detector_name or "privilege" in detector_name or "kernel" in category:
            return "local"
        return method or "version_match"

    @staticmethod
    def _compute_vuln_summary(vulns: List[Dict[str, Any]], existing_summary: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        summary = {
            "total_vulnerabilities": len(vulns),
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
            "verified": 0, "unverified": 0, "needs_manual_check": 0,
            "local": 0, "network": 0, "version_match": 0,
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
            else:
                summary["version_match"] += 1

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

    @staticmethod
    def _get_rule_version(scan_data: Dict[str, Any]) -> str:
        payload = ReportGeneratorFixedSafe._get_vulnerability_payload(scan_data)
        candidates = [
            scan_data.get("rule_version"), scan_data.get("rules_version"), scan_data.get("rule_db_version"),
            ReportGeneratorFixedSafe._safe_get_data(scan_data, ["rules", "version"], None),
            ReportGeneratorFixedSafe._safe_get_data(scan_data, ["rule_status", "version"], None),
            payload.get("rule_version"), payload.get("rules_version"), payload.get("rule_db_version"),
        ]
        for c in candidates:
            if c not in (None, "", "未知"):
                return str(c)
        return "未提供"

    @staticmethod
    def _get_host_info(scan_data: Dict[str, Any]) -> Dict[str, Any]:
        assets = scan_data.get("assets", {}) if isinstance(scan_data.get("assets", {}), dict) else {}
        host = {}
        for key in ("host_info", "system_info", "hostInfo", "systemInfo"):
            if isinstance(scan_data.get(key), dict):
                host.update(scan_data[key])
            if isinstance(assets.get(key), dict):
                host.update(assets[key])
        if isinstance(scan_data.get("systemInfo"), dict):
            host.update(scan_data["systemInfo"])
        return host

    @staticmethod
    def _extract_context(scan_data: Dict[str, Any]) -> Dict[str, Any]:
        payload = ReportGeneratorFixedSafe._get_vulnerability_payload(scan_data)
        vulns = ReportGeneratorFixedSafe._get_vulnerability_list({"vulnerabilities": payload})
        existing_summary = payload.get("scan_summary") or payload.get("summary") or scan_data.get("scan_summary") or {}
        vuln_summary = ReportGeneratorFixedSafe._compute_vuln_summary(vulns, existing_summary)
        assets = scan_data.get("assets", {}) if isinstance(scan_data.get("assets", {}), dict) else {}
        compliance = scan_data.get("compliance", {}) if isinstance(scan_data.get("compliance", {}), dict) else {}
        checks = ReportGeneratorFixedSafe._get_compliance_checks(compliance)
        compliance_summary = compliance.get("summary", {}) if isinstance(compliance.get("summary", {}), dict) else {}
        software_list = [x for x in ReportGeneratorFixedSafe._as_list(assets.get("software")) if isinstance(x, dict)]
        services_list = [x for x in ReportGeneratorFixedSafe._as_list(assets.get("services")) if isinstance(x, dict)]

        compliance_total = int(compliance_summary.get("total", len(checks)) or 0)
        compliance_passed = int(compliance_summary.get("passed", sum(1 for c in checks if c.get("passed") is True or c.get("status") in {"通过", "pass", "passed"})) or 0)
        compliance_failed = max(compliance_total - compliance_passed, 0)
        compliance_rate = compliance_summary.get("compliance_rate")
        if compliance_rate in (None, "", "未知"):
            compliance_rate = round((compliance_passed / compliance_total) * 100, 1) if compliance_total else 0

        xc_assets = [x for x in software_list + services_list if ReportGeneratorFixedSafe._is_xinchuang_related(x)]
        xc_vulns = [v for v in vulns if ReportGeneratorFixedSafe._is_xinchuang_related(v)]
        xc_checks = [c for c in checks if ReportGeneratorFixedSafe._is_xinchuang_related(c)]
        xinchuang_hits = len(xc_assets) + len(xc_vulns) + len(xc_checks)

        critical = int(vuln_summary.get("critical", 0) or 0)
        high = int(vuln_summary.get("high", 0) or 0)
        medium = int(vuln_summary.get("medium", 0) or 0)
        if critical > 0:
            overall_risk = "严重"
            overall_key = "critical"
        elif high > 0:
            overall_risk = "高危"
            overall_key = "high"
        elif medium > 0 or compliance_failed > 0:
            overall_risk = "中危"
            overall_key = "medium"
        else:
            overall_risk = "低危"
            overall_key = "low"

        scan_time = scan_data.get("timestamp") or scan_data.get("scan_timestamp") or payload.get("scan_timestamp") or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        scan_id = scan_data.get("scan_id") or payload.get("scan_id") or f"SK-{datetime.now().strftime('%Y%m%d%H%M%S')}"

        categories = compliance.get("categories") if isinstance(compliance.get("categories"), dict) else {}
        if not categories and isinstance(compliance_summary.get("categories"), dict):
            categories = compliance_summary.get("categories")
        xinchuang_summary = compliance.get("xinchuang_summary") if isinstance(compliance.get("xinchuang_summary"), dict) else {}
        if not xinchuang_summary and isinstance(scan_data.get("xinchuangSummary"), dict):
            xinchuang_summary = scan_data.get("xinchuangSummary")

        return {
            "payload": payload,
            "vulns": vulns,
            "vuln_summary": vuln_summary,
            "assets": assets,
            "compliance": compliance,
            "checks": checks,
            "software_list": software_list,
            "services_list": services_list,
            "compliance_total": compliance_total,
            "compliance_passed": compliance_passed,
            "compliance_failed": compliance_failed,
            "compliance_rate": compliance_rate,
            "xinchuang_hits": xinchuang_hits,
            "xc_assets": xc_assets,
            "xc_vulns": xc_vulns,
            "xc_checks": xc_checks,
            "overall_risk": overall_risk,
            "overall_key": overall_key,
            "scan_time": scan_time,
            "scan_id": scan_id,
            "rule_version": ReportGeneratorFixedSafe._get_rule_version(scan_data),
            "host_info": ReportGeneratorFixedSafe._get_host_info(scan_data),
            "compliance_categories": categories,
            "xinchuang_summary": xinchuang_summary,
        }

    # ------------------------------------------------------------------
    # 基础视觉组件
    # ------------------------------------------------------------------
    @staticmethod
    def _hex(value: str) -> Color:
        return colors.HexColor(value)

    @staticmethod
    def _divider(width: str = "100%", thickness: float = 1.0, color: Optional[str] = None, space_before: float = 3, space_after: float = 8) -> _SecKeeperDivider:
        """兼容老版 ReportLab 的水平分割线。"""
        return _SecKeeperDivider(
            width=width,
            thickness=thickness,
            color=ReportGeneratorFixedSafe._hex(color or ReportGeneratorFixedSafe.COLOR_BORDER),
            space_before=space_before,
            space_after=space_after,
        )

    @staticmethod
    def _section_title(title: str, styles: Dict[str, ParagraphStyle], hint: Optional[str] = None) -> List[Any]:
        # 面向用户的报告不展示版式/实现说明，只保留清晰章节标题。
        return [
            Spacer(1, 8),
            ReportGeneratorFixedSafe._divider(thickness=1.1, color=ReportGeneratorFixedSafe.COLOR_BLUE, space_before=2, space_after=6),
            Paragraph(title, styles["section"]),
        ]

    @staticmethod
    def _make_table(data: List[List[Any]], col_widths: List[float], header_color: str = COLOR_NAVY, font_size: float = 9.0) -> Table:
        table = Table(data, colWidths=col_widths, repeatRows=1, hAlign="LEFT")
        table.setStyle(TableStyle([
            ("FONT", (0, 0), (-1, -1), ReportGeneratorFixedSafe.CHINESE_FONT),
            ("FONTSIZE", (0, 0), (-1, -1), font_size),
            ("BACKGROUND", (0, 0), (-1, 0), ReportGeneratorFixedSafe._hex(header_color)),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("TEXTCOLOR", (0, 1), (-1, -1), ReportGeneratorFixedSafe._hex(ReportGeneratorFixedSafe.COLOR_TEXT)),
            ("ALIGN", (0, 0), (-1, 0), "CENTER"),
            ("ALIGN", (0, 1), (-1, -1), "LEFT"),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("WORDWRAP", (0, 0), (-1, -1), "CJK"),
            ("GRID", (0, 0), (-1, -1), 0.35, ReportGeneratorFixedSafe._hex(ReportGeneratorFixedSafe.COLOR_BORDER)),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, ReportGeneratorFixedSafe._hex("#F8FBFF")]),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        return table

    @staticmethod
    def _metric_cell(value: Any, label: str, styles: Dict[str, ParagraphStyle], accent: str = COLOR_BLUE) -> Table:
        # 执行摘要统一使用深蓝/科技蓝，避免颜色过杂。
        inner = Table([
            [Paragraph(ReportGeneratorFixedSafe._clean_text(value), styles["metric_value"])],
            [Paragraph(ReportGeneratorFixedSafe._clean_text(label), styles["metric_label"])],
        ], colWidths=[1.38 * inch])
        inner.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), ReportGeneratorFixedSafe._hex("#FFFFFF")),
            ("BOX", (0, 0), (-1, -1), 0.85, ReportGeneratorFixedSafe._hex("#BFD7F0")),
            ("LINEABOVE", (0, 0), (-1, 0), 3.0, ReportGeneratorFixedSafe._hex(ReportGeneratorFixedSafe.COLOR_BLUE_DARK)),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ]))
        return inner

    @staticmethod
    def _tag(text: str, styles: Dict[str, ParagraphStyle], bg: str) -> Table:
        t = Table([[Paragraph(ReportGeneratorFixedSafe._clean_text(text), styles["tag"])]], colWidths=[0.72 * inch])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), ReportGeneratorFixedSafe._hex(bg)),
            ("BOX", (0, 0), (-1, -1), 0.1, ReportGeneratorFixedSafe._hex(bg)),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        return t

    @staticmethod
    def _card(rows: List[List[Any]], col_widths: List[float], top_color: str = COLOR_BLUE, bg: str = COLOR_CARD) -> Table:
        table = Table(rows, colWidths=col_widths, hAlign="LEFT")
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), ReportGeneratorFixedSafe._hex(bg)),
            ("BOX", (0, 0), (-1, -1), 0.7, ReportGeneratorFixedSafe._hex(ReportGeneratorFixedSafe.COLOR_BORDER)),
            ("LINEABOVE", (0, 0), (-1, 0), 2.4, ReportGeneratorFixedSafe._hex(top_color)),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ]))
        return table

    # ------------------------------------------------------------------
    # 页眉页脚与封面背景
    # ------------------------------------------------------------------
    @staticmethod
    def _draw_header_footer(canvas, doc) -> None:
        """统一页眉页脚与正文页科技背景。正文页不再使用实体盾牌水印，改为低透明线框盾牌 + 六边形/线路装饰。"""
        canvas.saveState()
        width, height = A4
        font = ReportGeneratorFixedSafe.CHINESE_FONT

        # 打印友好的浅蓝背景。
        canvas.setFillColor(ReportGeneratorFixedSafe._hex("#F6FAFF"))
        canvas.rect(0, 0, width, height, stroke=0, fill=1)

        # 顶部深蓝信息条与左侧科技导轨。
        canvas.setFillColor(ReportGeneratorFixedSafe._hex("#EAF4FF"))
        canvas.rect(0, 0, 18, height, stroke=0, fill=1)
        canvas.setFillColor(ReportGeneratorFixedSafe._hex(ReportGeneratorFixedSafe.COLOR_NAVY))
        canvas.rect(0, height - 43, width, 43, stroke=0, fill=1)
        canvas.setFillColor(ReportGeneratorFixedSafe._hex(ReportGeneratorFixedSafe.COLOR_BLUE))
        canvas.rect(0, height - 46, width * 0.38, 3, stroke=0, fill=1)

        # 非封面页统一使用同一套线框盾牌水印，保证整份报告视觉一致。

        # 低对比科技网格。
        canvas.setStrokeColor(ReportGeneratorFixedSafe._hex("#D7E9FA"))
        canvas.setLineWidth(0.25)
        for x in range(48, int(width), 74):
            canvas.line(x, 76, x, height - 82)
        for y in range(76, int(height - 82), 74):
            canvas.line(34, y, width - 34, y)

        # 右下角六边形蜂窝：位置下移并缩小，避免与盾牌水印、正文图形重叠。
        def hexagon(cx: float, cy: float, r: float) -> None:
            pts = []
            for i in range(6):
                import math
                a = math.pi / 6 + i * math.pi / 3
                pts.append((cx + r * math.cos(a), cy + r * math.sin(a)))
            p = canvas.beginPath()
            p.moveTo(*pts[0])
            for pt in pts[1:]:
                p.lineTo(*pt)
            p.close()
            canvas.drawPath(p, stroke=1, fill=0)

        canvas.setStrokeColor(ReportGeneratorFixedSafe._hex("#C9E2FA"))
        canvas.setLineWidth(0.38)
        base_x, base_y = width - 178, 96
        for row in range(3):
            for col in range(3):
                x = base_x + col * 27 + (row % 2) * 13.5
                y = base_y + row * 23
                hexagon(x, y, 10.5)

        # 右侧主水印：统一为“盾牌 + 锁”的简洁线稿，避免复杂节点导致形状怪异。
        wm_x, wm_y = width - 108, height - 190

        # 外层盾牌：圆润、对称、低对比，仅作为安全主题水印。
        canvas.setStrokeColor(ReportGeneratorFixedSafe._hex("#9ECBF2"))
        canvas.setLineWidth(1.15)
        outer = canvas.beginPath()
        outer.moveTo(wm_x, wm_y + 66)
        outer.curveTo(wm_x + 34, wm_y + 56, wm_x + 55, wm_y + 43, wm_x + 59, wm_y + 35)
        outer.curveTo(wm_x + 56, wm_y - 25, wm_x + 35, wm_y - 57, wm_x, wm_y - 76)
        outer.curveTo(wm_x - 35, wm_y - 57, wm_x - 56, wm_y - 25, wm_x - 59, wm_y + 35)
        outer.curveTo(wm_x - 55, wm_y + 43, wm_x - 34, wm_y + 56, wm_x, wm_y + 66)
        outer.close()
        canvas.drawPath(outer, stroke=1, fill=0)

        # 内层盾牌：减少视觉空洞，保持统一科技感。
        canvas.setStrokeColor(ReportGeneratorFixedSafe._hex("#D2E7FA"))
        canvas.setLineWidth(0.85)
        inner = canvas.beginPath()
        inner.moveTo(wm_x, wm_y + 46)
        inner.curveTo(wm_x + 24, wm_y + 39, wm_x + 39, wm_y + 30, wm_x + 42, wm_y + 24)
        inner.curveTo(wm_x + 39, wm_y - 17, wm_x + 24, wm_y - 40, wm_x, wm_y - 55)
        inner.curveTo(wm_x - 24, wm_y - 40, wm_x - 39, wm_y - 17, wm_x - 42, wm_y + 24)
        inner.curveTo(wm_x - 39, wm_y + 30, wm_x - 24, wm_y + 39, wm_x, wm_y + 46)
        inner.close()
        canvas.drawPath(inner, stroke=1, fill=0)

        # 中心锁：只保留锁体与锁梁，避免电路线、节点与六边形叠加。
        canvas.setStrokeColor(ReportGeneratorFixedSafe._hex("#69AEEA"))
        canvas.setLineWidth(1.05)
        canvas.roundRect(wm_x - 20, wm_y - 28, 40, 34, 5, stroke=1, fill=0)
        canvas.arc(wm_x - 16, wm_y - 2, wm_x + 16, wm_y + 36, 0, 180)
        canvas.line(wm_x - 16, wm_y + 17, wm_x - 16, wm_y + 6)
        canvas.line(wm_x + 16, wm_y + 17, wm_x + 16, wm_y + 6)
        canvas.circle(wm_x, wm_y - 12, 3.2, stroke=1, fill=0)
        canvas.line(wm_x, wm_y - 15, wm_x, wm_y - 23)

        # 底部流线与节点网络：增强科技感但保持单色系.
        canvas.setStrokeColor(ReportGeneratorFixedSafe._hex("#9FD3FA"))
        canvas.setLineWidth(0.65)
        for i in range(3):
            y0 = 48 + i * 6
            canvas.bezier(width - 270, y0, width - 198, y0 + 24, width - 124, y0 - 12, width - 36, y0 + 10)

        canvas.setStrokeColor(ReportGeneratorFixedSafe._hex("#83C1F2"))
        canvas.setLineWidth(0.5)
        base_y = 58
        for i in range(6):
            x0 = width - 220 + i * 37
            y0 = base_y + (i % 2) * 11
            canvas.line(x0, y0, x0 + 70, base_y + 22)
            canvas.circle(x0 + 70, base_y + 22, 1.7, stroke=1, fill=0)

        # 页眉文字。
        canvas.setFillColor(colors.white)
        canvas.setFont(font, 10.0)
        canvas.drawString(doc.leftMargin, height - 26, "SecKeeper")
        canvas.setFillColor(ReportGeneratorFixedSafe._hex("#CFE7FF"))
        canvas.setFont(font, 9.0)
        canvas.drawString(doc.leftMargin + 64, height - 26, "安全巡检报告")

        # 页脚。
        canvas.setFillColor(ReportGeneratorFixedSafe._hex("#111827"))
        canvas.setFont(font, 9.0)
        canvas.drawString(doc.leftMargin, 23, "SecKeeper 安全巡检")
        canvas.drawRightString(width - doc.rightMargin, 23, f"Page {doc.page}")
        canvas.setStrokeColor(ReportGeneratorFixedSafe._hex(ReportGeneratorFixedSafe.COLOR_BLUE))
        canvas.setLineWidth(1.4)
        canvas.line(doc.leftMargin, 35, doc.leftMargin + 52, 35)
        canvas.restoreState()

    @staticmethod
    def _draw_cover(canvas, doc) -> None:
        canvas.saveState()
        width, height = A4

        # 封面浅科技背景：白底、深蓝、科技蓝，避免大面积杂色。
        canvas.setFillColor(ReportGeneratorFixedSafe._hex("#F5FAFF"))
        canvas.rect(0, 0, width, height, stroke=0, fill=1)
        canvas.setFillColor(ReportGeneratorFixedSafe._hex(ReportGeneratorFixedSafe.COLOR_NAVY))
        canvas.rect(0, height - 86, width, 86, stroke=0, fill=1)
        canvas.setFillColor(ReportGeneratorFixedSafe._hex(ReportGeneratorFixedSafe.COLOR_BLUE))
        canvas.rect(0, height - 91, width * 0.48, 5, stroke=0, fill=1)

        # 细网格。
        canvas.setStrokeColor(ReportGeneratorFixedSafe._hex("#DCEBFA"))
        canvas.setLineWidth(0.28)
        for x in range(48, int(width), 58):
            canvas.line(x, 104, x, height - 126)
        for y in range(104, int(height - 126), 58):
            canvas.line(38, y, width - 38, y)

        # 底部科技节点装饰，替代空白但保持简洁。
        canvas.setStrokeColor(ReportGeneratorFixedSafe._hex("#8EC8F4"))
        canvas.setLineWidth(0.8)
        node_y = 126
        for i in range(7):
            nx = 64 + i * 58
            ny = node_y + (i % 3) * 16
            canvas.circle(nx, ny, 2.2, stroke=1, fill=0)
            if i > 0:
                px = 64 + (i - 1) * 58
                py = node_y + ((i - 1) % 3) * 16
                canvas.line(px + 3, py, nx - 3, ny)

        # 右侧大盾牌：改为简洁的“盾牌 + 锁”主题图形，和正文页水印保持一致。
        cx, cy = width - 145, height - 338

        # 盾牌主体使用浅蓝填充与科技蓝描边，避免原先折线形状显得生硬。
        canvas.setFillColor(ReportGeneratorFixedSafe._hex("#E6F3FF"))
        canvas.setStrokeColor(ReportGeneratorFixedSafe._hex("#78BDF2"))
        canvas.setLineWidth(1.35)
        shield_path = canvas.beginPath()
        shield_path.moveTo(cx, cy + 88)
        shield_path.curveTo(cx + 42, cy + 76, cx + 68, cy + 58, cx + 75, cy + 45)
        shield_path.curveTo(cx + 71, cy - 38, cx + 43, cy - 82, cx, cy - 108)
        shield_path.curveTo(cx - 43, cy - 82, cx - 71, cy - 38, cx - 75, cy + 45)
        shield_path.curveTo(cx - 68, cy + 58, cx - 42, cy + 76, cx, cy + 88)
        shield_path.close()
        canvas.drawPath(shield_path, stroke=1, fill=1)

        # 盾牌内层高光轮廓。
        canvas.setStrokeColor(ReportGeneratorFixedSafe._hex("#B7DAF7"))
        canvas.setLineWidth(0.9)
        inner_path = canvas.beginPath()
        inner_path.moveTo(cx, cy + 60)
        inner_path.curveTo(cx + 28, cy + 51, cx + 45, cy + 39, cx + 49, cy + 31)
        inner_path.curveTo(cx + 46, cy - 24, cx + 28, cy - 55, cx, cy - 75)
        inner_path.curveTo(cx - 28, cy - 55, cx - 46, cy - 24, cx - 49, cy + 31)
        inner_path.curveTo(cx - 45, cy + 39, cx - 28, cy + 51, cx, cy + 60)
        inner_path.close()
        canvas.drawPath(inner_path, stroke=1, fill=0)

        # 中心锁图标。
        canvas.setStrokeColor(ReportGeneratorFixedSafe._hex(ReportGeneratorFixedSafe.COLOR_BLUE_DARK))
        canvas.setLineWidth(2.0)
        canvas.roundRect(cx - 26, cy - 32, 52, 42, 7, stroke=1, fill=0)
        canvas.arc(cx - 22, cy + 4, cx + 22, cy + 56, 0, 180)
        canvas.line(cx - 22, cy + 29, cx - 22, cy + 10)
        canvas.line(cx + 22, cy + 29, cx + 22, cy + 10)
        canvas.circle(cx, cy - 13, 4.0, stroke=1, fill=0)
        canvas.line(cx, cy - 17, cx, cy - 27)

        # 环形与节点装饰。
        canvas.setStrokeColor(ReportGeneratorFixedSafe._hex("#BFDDF8"))
        canvas.setLineWidth(0.8)
        for r in (62, 88, 112):
            canvas.circle(cx, cy - 8, r, stroke=1, fill=0)
        for i in range(9):
            x = 70 + i * 48
            y = 130 + (i % 3) * 22
            canvas.setStrokeColor(ReportGeneratorFixedSafe._hex("#BFDDF8"))
            canvas.line(x, y, x + 42, y + 18)
            canvas.setFillColor(ReportGeneratorFixedSafe._hex(ReportGeneratorFixedSafe.COLOR_BLUE))
            canvas.circle(x + 42, y + 18, 2, stroke=0, fill=1)

        # 底部流线。
        canvas.setFillColor(ReportGeneratorFixedSafe._hex("#E7F1FF"))
        p2 = canvas.beginPath()
        p2.moveTo(0, 58)
        p2.curveTo(width * 0.28, 98, width * 0.62, 20, width, 72)
        p2.lineTo(width, 0)
        p2.lineTo(0, 0)
        p2.close()
        canvas.drawPath(p2, stroke=0, fill=1)
        canvas.setStrokeColor(ReportGeneratorFixedSafe._hex(ReportGeneratorFixedSafe.COLOR_BLUE))
        canvas.setLineWidth(1.0)
        canvas.line(54, 74, 190, 74)
        canvas.restoreState()

    # ------------------------------------------------------------------
    # 章节构建
    # ------------------------------------------------------------------
    @staticmethod
    def _build_cover(ctx: Dict[str, Any], styles: Dict[str, ParagraphStyle]) -> List[Any]:
        meta = Table([
            ["报告编号", ReportGeneratorFixedSafe._clean_text(ctx["scan_id"])],
            ["扫描时间", ReportGeneratorFixedSafe._clean_text(ctx["scan_time"])],
            ["生成时间", datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
        ], colWidths=[1.25 * inch, 3.75 * inch])
        meta.setStyle(TableStyle([
            ("FONT", (0, 0), (-1, -1), ReportGeneratorFixedSafe.CHINESE_FONT),
            ("FONTSIZE", (0, 0), (-1, -1), 10.2),
            ("TEXTCOLOR", (0, 0), (0, -1), ReportGeneratorFixedSafe._hex("#1E3A5F")),
            ("TEXTCOLOR", (1, 0), (1, -1), ReportGeneratorFixedSafe._hex(ReportGeneratorFixedSafe.COLOR_TEXT)),
            ("BACKGROUND", (0, 0), (-1, -1), colors.white),
            ("BOX", (0, 0), (-1, -1), 0.7, ReportGeneratorFixedSafe._hex(ReportGeneratorFixedSafe.COLOR_BORDER)),
            ("INNERGRID", (0, 0), (-1, -1), 0.35, ReportGeneratorFixedSafe._hex(ReportGeneratorFixedSafe.COLOR_BORDER)),
            ("LEFTPADDING", (0, 0), (-1, -1), 9),
            ("RIGHTPADDING", (0, 0), (-1, -1), 9),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ]))

        return [
            Spacer(1, 118),
            Paragraph("SecKeeper", styles["cover_brand"]),
            Paragraph("基于双核验证的信创生态主机安全巡检平台", styles["cover_title"]),
            Paragraph("Security Inspection Report", styles["cover_subtitle"]),
            Spacer(1, 126),
            meta,
            Spacer(1, 132),
            PageBreak(),
        ]

    @staticmethod
    def _build_executive_summary(ctx: Dict[str, Any], styles: Dict[str, ParagraphStyle]) -> List[Any]:
        vs = ctx["vuln_summary"]
        total_assets = len(ctx["software_list"]) + len(ctx["services_list"])
        verified = int(vs.get("verified", 0) or 0)
        suspicious = int(vs.get("unverified", 0) or 0)
        visible_risks = verified + suspicious

        # 面向用户的摘要只保留关键业务指标，去掉“漏洞总数/待确认漏洞”等分析过程指标。
        rows = [
            [
                ReportGeneratorFixedSafe._metric_cell(ctx["overall_risk"], "总体风险等级", styles),
                ReportGeneratorFixedSafe._metric_cell(total_assets, "资产数量", styles),
                ReportGeneratorFixedSafe._metric_cell(f"{ctx['compliance_rate']}%", "合规率", styles),
            ],
            [
                ReportGeneratorFixedSafe._metric_cell(verified, "已验证漏洞", styles),
                ReportGeneratorFixedSafe._metric_cell(suspicious, "疑似风险", styles),
                ReportGeneratorFixedSafe._metric_cell(ctx["xinchuang_hits"], "信创专项命中数", styles),
            ],
        ]
        t = Table(rows, colWidths=[2.05 * inch] * 3, hAlign="LEFT")
        t.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 3),
            ("RIGHTPADDING", (0, 0), (-1, -1), 3),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        narrative = (
            f"本次巡检覆盖 {total_assets} 个资产对象，合规通过率为 {ctx['compliance_rate']}%。"
            f"报告重点展示已验证和疑似风险，共 {visible_risks} 项。"
            "建议优先处理严重和高危风险，并在完成修复后重新执行巡检。"
        )
        return ReportGeneratorFixedSafe._section_title("1. 执行摘要", styles) + [
            t,
            Spacer(1, 10),
            ReportGeneratorFixedSafe._card([[Paragraph(narrative, styles["normal"])]], [6.25 * inch], ReportGeneratorFixedSafe.COLOR_BLUE_DARK, "#EEF6FF"),
        ]

    @staticmethod
    def _build_risk_statistics(ctx: Dict[str, Any], styles: Dict[str, ParagraphStyle]) -> List[Any]:
        vs = ctx["vuln_summary"]
        data = [
            ["风险等级", "数量", "验证状态", "数量", "验证方式", "数量", "合规状态", "数量"],
            ["严重", str(vs.get("critical", 0)), "已验证", str(vs.get("verified", 0)), "本地验证", str(vs.get("local", 0)), "通过", str(ctx["compliance_passed"])],
            ["高危", str(vs.get("high", 0)), "疑似漏洞", str(vs.get("unverified", 0)), "网络验证", str(vs.get("network", 0)), "未通过", str(ctx["compliance_failed"])],
            ["中危", str(vs.get("medium", 0)), "待确认", str(vs.get("needs_manual_check", 0)), "版本匹配", str(vs.get("version_match", 0)), "总检查项", str(ctx["compliance_total"])],
            ["低危", str(vs.get("low", 0)), "-", "-", "-", "-", "合规率", f"{ctx['compliance_rate']}%"],
        ]
        table = ReportGeneratorFixedSafe._make_table(data, [0.82*inch, 0.60*inch, 0.92*inch, 0.60*inch, 0.92*inch, 0.60*inch, 0.92*inch, 0.60*inch], ReportGeneratorFixedSafe.COLOR_NAVY_2, 9.0)
        return ReportGeneratorFixedSafe._section_title("2. 风险统计", styles) + [table]

    @staticmethod
    def _build_asset_info(ctx: Dict[str, Any], styles: Dict[str, ParagraphStyle]) -> List[Any]:
        host = ctx["host_info"]
        assets = ctx["assets"]
        def first(*keys):
            for k in keys:
                if host.get(k) not in (None, "", "未知"):
                    return host.get(k)
                if assets.get(k) not in (None, "", "未知"):
                    return assets.get(k)
            return "未知"
        ip = first("ip", "ip_address", "host_ip", "address")
        rows = [
            ["主机名", ReportGeneratorFixedSafe._paragraph(first("hostname", "host_name", "name"), styles, "small", 45), "IP", ReportGeneratorFixedSafe._paragraph(ip, styles, "small", 40)],
            ["操作系统", ReportGeneratorFixedSafe._paragraph(first("os", "os_name", "operating_system", "platform"), styles, "small", 55), "内核版本", ReportGeneratorFixedSafe._paragraph(first("kernel", "kernel_version", "kernel_release"), styles, "small", 45)],
            ["架构", ReportGeneratorFixedSafe._paragraph(first("architecture", "arch", "machine"), styles, "small", 35), "软件数量", str(len(ctx["software_list"]))],
            ["服务数量", str(len(ctx["services_list"])), "扫描对象", ReportGeneratorFixedSafe._paragraph(first("target", "scan_target", "host"), styles, "small", 45)],
        ]
        table = Table(rows, colWidths=[0.82*inch, 2.18*inch, 0.82*inch, 2.18*inch], hAlign="LEFT")
        table.setStyle(TableStyle([
            ("FONT", (0, 0), (-1, -1), ReportGeneratorFixedSafe.CHINESE_FONT),
            ("FONTSIZE", (0, 0), (-1, -1), 8.7),
            ("BACKGROUND", (0, 0), (-1, -1), colors.white),
            ("BACKGROUND", (0, 0), (0, -1), ReportGeneratorFixedSafe._hex("#EFF6FF")),
            ("BACKGROUND", (2, 0), (2, -1), ReportGeneratorFixedSafe._hex("#EFF6FF")),
            ("TEXTCOLOR", (0, 0), (0, -1), ReportGeneratorFixedSafe._hex(ReportGeneratorFixedSafe.COLOR_NAVY)),
            ("TEXTCOLOR", (2, 0), (2, -1), ReportGeneratorFixedSafe._hex(ReportGeneratorFixedSafe.COLOR_NAVY)),
            ("BOX", (0, 0), (-1, -1), 0.7, ReportGeneratorFixedSafe._hex(ReportGeneratorFixedSafe.COLOR_BORDER)),
            ("INNERGRID", (0, 0), (-1, -1), 0.35, ReportGeneratorFixedSafe._hex(ReportGeneratorFixedSafe.COLOR_BORDER)),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ]))

        elems = ReportGeneratorFixedSafe._section_title("3. 资产信息", styles)
        elems.append(table)
        if ctx["software_list"]:
            sw_rows = [["软件名称", "版本", "类型/包管理器"]]
            for software in ctx["software_list"][:12]:
                sw_rows.append([
                    ReportGeneratorFixedSafe._paragraph(software.get("name", "未知"), styles, "tiny", 38),
                    ReportGeneratorFixedSafe._paragraph(software.get("version", "未知"), styles, "tiny", 26),
                    ReportGeneratorFixedSafe._paragraph(software.get("type") or software.get("package_manager") or "未知", styles, "tiny", 32),
                ])
            sw_table = ReportGeneratorFixedSafe._make_table(sw_rows, [2.65*inch, 1.75*inch, 1.95*inch], ReportGeneratorFixedSafe.COLOR_BLUE_DARK, 8.8)
            elems.extend([Spacer(1, 10), Paragraph("软件资产摘要", styles["card_title"]), sw_table])
        if ctx["services_list"]:
            svc_rows = [["服务名称", "运行状态/服务说明"]]
            for svc in ctx["services_list"][:10]:
                svc_rows.append([
                    ReportGeneratorFixedSafe._clean_text(svc.get("name", "未知"), 42),
                    ReportGeneratorFixedSafe._clean_text(svc.get("status") or svc.get("type") or svc.get("url") or svc.get("address") or "未知", 72),
                ])
            svc_table = ReportGeneratorFixedSafe._make_table(svc_rows, [2.70*inch, 3.65*inch], "#0F766E", 8.8)
            svc_table.setStyle(TableStyle([
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]))
            elems.extend([Spacer(1, 10), Paragraph("服务资产摘要", styles["card_title"]), svc_table])
        return elems

    @staticmethod
    def _build_compliance(ctx: Dict[str, Any], styles: Dict[str, ParagraphStyle]) -> List[Any]:
        checks = ctx["checks"]
        elems = ReportGeneratorFixedSafe._section_title("4. 合规检查", styles)

        # 前端中有价值且不重复的信息：检查总数、通过/未通过、信创专项命中、分类统计。
        overview_rows = [
            ["检查总数", str(ctx.get("compliance_total", 0)), "通过项", str(ctx.get("compliance_passed", 0))],
            ["未通过项", str(ctx.get("compliance_failed", 0)), "合规率", f"{ctx.get('compliance_rate', 0)}%"],
            ["信创专项命中", str(ctx.get("xinchuang_hits", 0)), "检查类型", "通用基线 / 信创专项"],
        ]
        elems.append(ReportGeneratorFixedSafe._make_table(
            overview_rows,
            [1.25 * inch, 1.45 * inch, 1.25 * inch, 1.45 * inch],
            ReportGeneratorFixedSafe.COLOR_NAVY_2,
            8.5,
        ))
        elems.append(Spacer(1, 10))

        categories = ctx.get("compliance_categories") or {}
        if categories:
            cat_rows = [["分类", "数量"]]
            for name, value in list(categories.items())[:8]:
                if isinstance(value, dict):
                    count = value.get("total") or value.get("failed") or value.get("passed") or 0
                else:
                    count = value
                cat_rows.append([
                    ReportGeneratorFixedSafe._clean_text(name, 30),
                    ReportGeneratorFixedSafe._clean_text(count, 12),
                ])
            cat_table = ReportGeneratorFixedSafe._make_table(cat_rows, [3.8 * inch, 1.2 * inch], ReportGeneratorFixedSafe.COLOR_BLUE_DARK, 9.2)
            cat_table.setStyle(TableStyle([
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]))
            elems.extend([Paragraph("合规分类统计", styles["card_title"]), cat_table, Spacer(1, 10)])

        xinchuang_summary = ctx.get("xinchuang_summary") or {}
        xinchuang_labels = {
            "kylin": "银河麒麟",
            "uos": "统信 UOS",
            "dameng": "达梦数据库",
            "kingbase": "人大金仓",
            "tongweb": "东方通 TongWeb",
        }
        xc_rows = []
        for key, label in xinchuang_labels.items():
            value = xinchuang_summary.get(key, 0)
            try:
                value_num = int(value)
            except Exception:
                value_num = 0
            if value_num > 0:
                xc_rows.append([label, str(value_num)])
        if xc_rows:
            xc_table = ReportGeneratorFixedSafe._make_table([["专项对象", "命中数量"]] + xc_rows, [3.8 * inch, 1.2 * inch], "#0F766E", 9.2)
            xc_table.setStyle(TableStyle([
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]))
            elems.extend([Paragraph("信创专项命中分布", styles["card_title"]), xc_table, Spacer(1, 10)])

        if not checks:
            elems.append(ReportGeneratorFixedSafe._card([[Paragraph("本次扫描未返回合规检查明细。", styles["normal"])]], [6.0*inch], ReportGeneratorFixedSafe.COLOR_BLUE))
            return elems

        general = [c for c in checks if not ReportGeneratorFixedSafe._is_xinchuang_related(c)]
        xc = [c for c in checks if ReportGeneratorFixedSafe._is_xinchuang_related(c)]

        def build_table(title: str, rows_src: List[Dict[str, Any]], accent: str) -> List[Any]:
            if not rows_src:
                return []
            rows = [["检查项", "状态", "风险", "说明"]]
            for c in rows_src[:14]:
                passed = c.get("passed")
                status = c.get("status")
                if status is None:
                    status = "通过" if passed is True else "未通过" if passed is False else "未知"
                rows.append([
                    ReportGeneratorFixedSafe._paragraph(c.get("name") or c.get("check") or "未知", styles, "tiny", 36),
                    ReportGeneratorFixedSafe._clean_text(status, 10),
                    ReportGeneratorFixedSafe._clean_text(c.get("risk_level") or c.get("severity") or "-", 12),
                    ReportGeneratorFixedSafe._paragraph(c.get("description") or c.get("remediation") or "-", styles, "tiny", 120),
                ])
            compliance_table = ReportGeneratorFixedSafe._make_table(rows, [1.85*inch, 0.75*inch, 0.75*inch, 3.05*inch], accent, 9.0)
            compliance_table.setStyle(TableStyle([
                ("ALIGN", (1, 0), (2, -1), "CENTER"),
                ("VALIGN", (1, 0), (2, -1), "MIDDLE"),
            ]))
            return [Paragraph(title, styles["card_title"]), compliance_table, Spacer(1, 8)]

        elems.extend(build_table("通用等保基线", general, ReportGeneratorFixedSafe.COLOR_NAVY_2))
        elems.extend(build_table("信创专项基线", xc, "#0F766E"))
        if not xc:
            elems.append(ReportGeneratorFixedSafe._card([[Paragraph("当前合规明细中未识别到明显的信创专项基线命中项。", styles["normal"])]], [6.0*inch], "#0F766E", "#F0FDFA"))
        return elems

    @staticmethod
    def _vuln_card(vuln: Dict[str, Any], styles: Dict[str, ParagraphStyle]) -> Table:
        severity = str(vuln.get("severity", "unknown")).lower()
        if severity not in ReportGeneratorFixedSafe.SEVERITY_COLORS:
            severity = "unknown"
        status = ReportGeneratorFixedSafe._normalize_verify_status(vuln)
        method = ReportGeneratorFixedSafe._normalize_method(vuln)
        safety = str(vuln.get("verification_safety") or "").strip().lower()
        title = vuln.get("title") or vuln.get("name") or vuln.get("vuln_name") or vuln.get("cve_id") or vuln.get("vuln_id") or "未命名漏洞"
        vuln_id = vuln.get("vuln_id") or vuln.get("cve_id") or vuln.get("id") or "-"
        affected = vuln.get("affected_target") or vuln.get("target") or vuln.get("package") or vuln.get("service") or "-"
        desc = vuln.get("description") or vuln.get("summary") or vuln.get("detail") or "暂无详细说明。"
        remediation = vuln.get("remediation") or vuln.get("solution") or vuln.get("fix") or "建议结合业务影响、补丁状态与暴露面进行修复验证。"
        color = ReportGeneratorFixedSafe.SEVERITY_COLORS[severity]

        title_row = [
            Paragraph(f"{ReportGeneratorFixedSafe._clean_text(title, 90)}", styles["card_title"]),
            ReportGeneratorFixedSafe._tag({"critical": "严重", "high": "高危", "medium": "中危", "low": "低危", "info": "提示", "unknown": "未知"}.get(severity, severity), styles, color),
        ]
        meta_rows = [
            ["漏洞编号", ReportGeneratorFixedSafe._paragraph(vuln_id, styles, "tiny", 32), "验证状态", ReportGeneratorFixedSafe._paragraph(ReportGeneratorFixedSafe.VERIFY_LABELS.get(status, status), styles, "tiny", 18)],
            ["验证方式", ReportGeneratorFixedSafe._paragraph(ReportGeneratorFixedSafe.METHOD_LABELS.get(method, method), styles, "tiny", 38), "验证类型", ReportGeneratorFixedSafe._paragraph(ReportGeneratorFixedSafe.SAFETY_LABELS.get(safety, safety or "未标注"), styles, "tiny", 26)],
        ]
        if str(affected).strip() not in {"", "-", "未知", "None", "none", "null"}:
            meta_rows.append(["影响对象", ReportGeneratorFixedSafe._paragraph(affected, styles, "tiny", 95), "", ""])
        meta = Table(meta_rows, colWidths=[0.68*inch, 2.22*inch, 0.68*inch, 1.92*inch])
        meta.setStyle(TableStyle([
            ("FONT", (0, 0), (-1, -1), ReportGeneratorFixedSafe.CHINESE_FONT),
            ("FONTSIZE", (0, 0), (-1, -1), 8.8),
            ("TEXTCOLOR", (0, 0), (0, -1), ReportGeneratorFixedSafe._hex(ReportGeneratorFixedSafe.COLOR_MUTED)),
            ("TEXTCOLOR", (2, 0), (2, 1), ReportGeneratorFixedSafe._hex(ReportGeneratorFixedSafe.COLOR_MUTED)),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 2), ("RIGHTPADDING", (0, 0), (-1, -1), 2),
            ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ]))
        body = [
            [Paragraph("漏洞说明", styles["tiny"]), ReportGeneratorFixedSafe._paragraph(desc, styles, "tiny", 150)],
            [Paragraph("修复建议", styles["tiny"]), ReportGeneratorFixedSafe._paragraph(remediation, styles, "tiny", 150)],
        ]
        body_t = Table(body, colWidths=[0.82*inch, 4.88*inch])
        body_t.setStyle(TableStyle([
            ("FONT", (0, 0), (-1, -1), ReportGeneratorFixedSafe.CHINESE_FONT),
            ("BACKGROUND", (0, 0), (0, -1), ReportGeneratorFixedSafe._hex("#F1F5F9")),
            ("TEXTCOLOR", (0, 0), (0, -1), ReportGeneratorFixedSafe._hex(ReportGeneratorFixedSafe.COLOR_NAVY)),
            ("BOX", (0, 0), (-1, -1), 0.35, ReportGeneratorFixedSafe._hex(ReportGeneratorFixedSafe.COLOR_BORDER)),
            ("INNERGRID", (0, 0), (-1, -1), 0.25, ReportGeneratorFixedSafe._hex(ReportGeneratorFixedSafe.COLOR_BORDER)),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))

        card = Table([[title_row[0], title_row[1]], [meta, ""], [body_t, ""]], colWidths=[5.05*inch, 0.85*inch])
        card.setStyle(TableStyle([
            ("SPAN", (0, 1), (1, 1)),
            ("SPAN", (0, 2), (1, 2)),
            ("BACKGROUND", (0, 0), (-1, -1), colors.white),
            ("BOX", (0, 0), (-1, -1), 0.7, ReportGeneratorFixedSafe._hex(ReportGeneratorFixedSafe.COLOR_BORDER)),
            ("LINEABOVE", (0, 0), (-1, 0), 2.6, ReportGeneratorFixedSafe._hex(color)),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 7), ("RIGHTPADDING", (0, 0), (-1, -1), 7),
            ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ]))
        return card

    @staticmethod
    def _split_long_text(value: Any, chunk_size: int = 210) -> List[str]:
        """将超长说明拆为多个表格行，避免 ReportLab 单行过高无法分页，同时不省略内容。"""
        text = ReportGeneratorFixedSafe._clean_text(value)
        if not text or text == "-":
            return ["-"]
        chunks: List[str] = []
        while len(text) > chunk_size:
            cut = chunk_size
            # 尽量在中文/英文标点附近切分，减少生硬断行。
            for sep in ["。", "；", ";", "，", ",", " "]:
                pos = text.rfind(sep, 0, chunk_size)
                if pos >= int(chunk_size * 0.55):
                    cut = pos + 1
                    break
            chunks.append(text[:cut].strip())
            text = text[cut:].strip()
        if text:
            chunks.append(text)
        return chunks or ["-"]

    @staticmethod
    def _filter_user_visible_vulns(vulns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """面向用户的最终报告中过滤待确认项，仅展示已验证和疑似风险。"""
        result: List[Dict[str, Any]] = []
        for v in vulns:
            if ReportGeneratorFixedSafe._normalize_verify_status(v) == "needs_manual_check":
                continue
            result.append(v)
        return result

    @staticmethod
    def _build_vulnerability_overview(sorted_vulns: List[Dict[str, Any]], ctx: Dict[str, Any], styles: Dict[str, ParagraphStyle]) -> List[Any]:
        """漏洞详情总表：不展示待确认项；保留完整漏洞说明，不展示验证方式和修复建议。"""
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for v in sorted_vulns:
            sev = str(v.get("severity", "low")).lower()
            if sev not in severity_counts:
                sev = "low"
            severity_counts[sev] += 1

        severity_parts = []
        for key, label in [("critical", "严重"), ("high", "高危"), ("medium", "中危"), ("low", "低危"), ("info", "提示")]:
            count = int(severity_counts.get(key, 0) or 0)
            if count > 0:
                severity_parts.append(f"{label} {count} 项")
        severity_text = "，".join(severity_parts) if severity_parts else "暂无风险项"
        summary_text = (
            f"已验证和疑似风险，共 {len(sorted_vulns)} 项：{severity_text}。"
            "建议优先处理严重和高危风险，并在完成修复后重新执行巡检。"
        )

        def has_value(value: Any) -> bool:
            return value not in (None, "", "-", "未知", "无", "None", "none", "null")

        has_target = any(has_value(v.get("affected_target") or v.get("target") or v.get("package") or v.get("service")) for v in sorted_vulns)
        if has_target:
            header = ["风险", "漏洞名称", "影响对象", "漏洞说明"]
            widths = [0.80 * inch, 1.90 * inch, 1.50 * inch, 3.05 * inch]
        else:
            header = ["风险", "漏洞名称", "漏洞说明"]
            widths = [0.85 * inch, 2.25 * inch, 4.15 * inch]

        rows: List[List[Any]] = []
        for vuln in sorted_vulns[:80]:
            sev = str(vuln.get("severity", "unknown")).lower()
            if sev not in ReportGeneratorFixedSafe.SEVERITY_LABELS:
                sev = "unknown"
            title = vuln.get("title") or vuln.get("name") or vuln.get("vuln_name") or vuln.get("cve_id") or vuln.get("vuln_id") or "未命名漏洞"
            target = vuln.get("affected_target") or vuln.get("target") or vuln.get("package") or vuln.get("service") or ""
            desc = vuln.get("description") or vuln.get("summary") or vuln.get("detail") or vuln.get("reason") or "建议结合业务环境进一步确认影响范围。"
            desc_chunks = ReportGeneratorFixedSafe._split_long_text(desc, 260)

            first_row_index = len(rows) + 1
            for idx, chunk in enumerate(desc_chunks):
                if idx == 0:
                    row: List[Any] = [
                        ReportGeneratorFixedSafe._paragraph(ReportGeneratorFixedSafe.SEVERITY_LABELS.get(sev, sev), styles, "tiny"),
                        ReportGeneratorFixedSafe._paragraph(title, styles, "tiny"),
                    ]
                    if has_target:
                        row.append(ReportGeneratorFixedSafe._paragraph(target if has_value(target) else "-", styles, "tiny"))
                    row.append(ReportGeneratorFixedSafe._paragraph(chunk, styles, "tiny"))
                else:
                    # 说明过长时拆为连续行，左侧留空，避免单行过高导致分页失败或内容串行。
                    row = ["", ""]
                    if has_target:
                        row.append("")
                    row.append(ReportGeneratorFixedSafe._paragraph(chunk, styles, "tiny"))
                rows.append(row)

        elems: List[Any] = []
        elems.append(ReportGeneratorFixedSafe._card([
            [Paragraph("漏洞概览", styles["card_title"])],
            [Paragraph(summary_text, styles["normal"])],
        ], [7.15 * inch], ReportGeneratorFixedSafe.COLOR_BLUE_DARK, "#FFFFFF"))
        elems.append(Spacer(1, 10))

        if not rows:
            elems.append(ReportGeneratorFixedSafe._card([[Paragraph("本次扫描未发现已验证或疑似漏洞。", styles["normal"])]], [7.15 * inch], ReportGeneratorFixedSafe.COLOR_BLUE_DARK))
            return elems

        table = ReportGeneratorFixedSafe._make_table([header] + rows, widths, ReportGeneratorFixedSafe.COLOR_NAVY_2, 9.2)
        table.setStyle(TableStyle([
            ("ALIGN", (0, 1), (0, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        try:
            table.splitByRow = 1
            table.repeatRows = 1
        except Exception:
            pass
        elems.append(table)
        elems.append(Spacer(1, 10))
        return elems

    @staticmethod
    def _build_vulnerabilities(ctx: Dict[str, Any], styles: Dict[str, ParagraphStyle]) -> List[Any]:
        visible_vulns = ReportGeneratorFixedSafe._filter_user_visible_vulns(ctx["vulns"])
        elems = ReportGeneratorFixedSafe._section_title("5. 漏洞详情", styles)
        if not visible_vulns:
            elems.append(ReportGeneratorFixedSafe._card([[Paragraph("本次扫描未发现已验证或疑似漏洞。", styles["normal"])]], [7.15*inch], ReportGeneratorFixedSafe.COLOR_BLUE_DARK))
            return elems
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_vulns = sorted(visible_vulns, key=lambda v: severity_order.get(str(v.get("severity", "low")).lower(), 9))
        elems.extend(ReportGeneratorFixedSafe._build_vulnerability_overview(sorted_vulns, ctx, styles))
        if len(visible_vulns) > 80:
            elems.append(Paragraph(f"漏洞共 {len(visible_vulns)} 项，表格展示风险优先级最高的前 80 项。", styles["small"]))
        return elems

    @staticmethod
    def _build_remediation(ctx: Dict[str, Any], styles: Dict[str, ParagraphStyle]) -> List[Any]:
        vulns = ReportGeneratorFixedSafe._filter_user_visible_vulns(ctx["vulns"])
        elems = ReportGeneratorFixedSafe._section_title("6. 修复建议", styles)
        if not vulns:
            elems.append(ReportGeneratorFixedSafe._card([[Paragraph("当前无已验证或疑似漏洞修复项。建议保留周期性巡检和规则库更新。", styles["normal"])]], [7.15*inch], ReportGeneratorFixedSafe.COLOR_BLUE_DARK))
            return elems
        severity_order = ["critical", "high", "medium", "low", "info"]
        rows = [["优先级", "风险对象", "建议动作"]]
        for sev in severity_order:
            sev_items = [v for v in vulns if str(v.get("severity", "low")).lower() == sev]
            for v in sev_items[:10]:
                title = v.get("title") or v.get("vuln_id") or v.get("cve_id") or "未命名漏洞"
                target = v.get("affected_target") or v.get("target") or v.get("package") or v.get("service")
                obj = title if target in (None, "", "-", "未知") else f"{title} / {target}"
                rows.append([
                    ReportGeneratorFixedSafe._paragraph(ReportGeneratorFixedSafe.SEVERITY_LABELS.get(sev, sev), styles, "tiny"),
                    ReportGeneratorFixedSafe._paragraph(obj, styles, "tiny"),
                    ReportGeneratorFixedSafe._paragraph(v.get("remediation") or v.get("solution") or "优先升级受影响组件，收敛暴露面，并在修复后重新执行巡检。", styles, "tiny"),
                ])
        table = ReportGeneratorFixedSafe._make_table(rows, [0.95*inch, 3.20*inch, 3.10*inch], ReportGeneratorFixedSafe.COLOR_NAVY_2, 9.2)
        table.setStyle(TableStyle([
            ("ALIGN", (0, 1), (0, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        try:
            table.splitByRow = 1
            table.repeatRows = 1
        except Exception:
            pass
        elems.append(table)
        return elems

    @staticmethod
    def _build_appendix(ctx: Dict[str, Any], styles: Dict[str, ParagraphStyle]) -> List[Any]:
        elems: List[Any] = []
        metrics = ctx["payload"].get("detector_metrics") or ctx.get("detector_metrics")
        rows = []
        if isinstance(metrics, dict):
            for name, info in metrics.items():
                if isinstance(info, dict):
                    rows.append({"name": name, **info})
                else:
                    rows.append({"name": name, "elapsed_seconds": info})
        elif isinstance(metrics, list):
            rows = [m for m in metrics if isinstance(m, dict)]
        if rows:
            elems.extend(ReportGeneratorFixedSafe._section_title("附录 A. 检测器执行状态", styles))
            data = [["检测器", "状态", "耗时(s)", "发现数量"]]
            for row in rows:
                data.append([
                    ReportGeneratorFixedSafe._paragraph(row.get("name") or row.get("detector") or row.get("detector_name") or "未知", styles, "tiny", 40),
                    ReportGeneratorFixedSafe._paragraph(row.get("status") or ("成功" if row.get("success", True) else "失败"), styles, "tiny", 12),
                    ReportGeneratorFixedSafe._paragraph(row.get("elapsed_seconds") or row.get("duration") or row.get("elapsed") or "-", styles, "tiny", 10),
                    ReportGeneratorFixedSafe._paragraph(row.get("vulnerability_count") or row.get("count") or row.get("findings") or "0", styles, "tiny", 10),
                ])
            elems.append(ReportGeneratorFixedSafe._make_table(data, [2.35*inch, 1.0*inch, 0.85*inch, 0.9*inch], "#475569", 8.8))
        errors = ctx["payload"].get("errors") or []
        warnings = ctx["payload"].get("warnings") or []
        if errors or warnings:
            elems.extend(ReportGeneratorFixedSafe._section_title("附录 B. 异常与告警", styles))
            issue_rows = [["类型", "内容"]]
            for err in ReportGeneratorFixedSafe._as_list(errors)[:10]:
                issue_rows.append(["错误", ReportGeneratorFixedSafe._paragraph(err, styles, "tiny", 130)])
            for warn in ReportGeneratorFixedSafe._as_list(warnings)[:10]:
                issue_rows.append(["告警", ReportGeneratorFixedSafe._paragraph(warn, styles, "tiny", 130)])
            elems.append(ReportGeneratorFixedSafe._make_table(issue_rows, [0.75*inch, 5.15*inch], "#64748B", 8.8))
        return elems

    # ------------------------------------------------------------------
    # 主入口
    # ------------------------------------------------------------------
    @staticmethod
    def generate_pdf_report(scan_data: Dict[str, Any], output_path: str) -> bool:
        """生成 SecKeeper PDF 报告。保持原接口不变。"""
        try:
            if not isinstance(scan_data, dict):
                raise ValueError("scan_data 必须是 dict")

            os.makedirs(os.path.dirname(os.path.abspath(output_path)) or ".", exist_ok=True)
            ReportGeneratorFixedSafe._setup_fonts()
            styles = ReportGeneratorFixedSafe._create_styles()
            ctx = ReportGeneratorFixedSafe._extract_context(scan_data)

            doc = SimpleDocTemplate(
                output_path,
                pagesize=A4,
                rightMargin=20,
                leftMargin=44,
                topMargin=56,
                bottomMargin=42,
                title="SecKeeper 安全巡检报告",
                author="SecKeeper",
            )

            elements: List[Any] = []
            elements.extend(ReportGeneratorFixedSafe._build_cover(ctx, styles))
            elements.extend(ReportGeneratorFixedSafe._build_executive_summary(ctx, styles))
            elements.extend(ReportGeneratorFixedSafe._build_risk_statistics(ctx, styles))

            # 第三部分：资产信息强制从新页开始，避免与前一部分混排。
            elements.append(PageBreak())
            elements.extend(ReportGeneratorFixedSafe._build_asset_info(ctx, styles))

            # 第四部分：合规检查强制从新页开始，保证章节完整性。
            elements.append(PageBreak())
            elements.extend(ReportGeneratorFixedSafe._build_compliance(ctx, styles))

            elements.append(PageBreak())
            elements.extend(ReportGeneratorFixedSafe._build_vulnerabilities(ctx, styles))
            elements.extend(ReportGeneratorFixedSafe._build_remediation(ctx, styles))

            doc.build(
                elements,
                onFirstPage=ReportGeneratorFixedSafe._draw_cover,
                onLaterPages=ReportGeneratorFixedSafe._draw_header_footer,
            )

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
