#!/usr/bin/env python3
"""
SecKeeper 网络安全扫描与报告生成系统
主应用程序文件 - 完整生产版本
"""

import os
import json
import uuid
import tempfile
import threading
import time
import logging
from datetime import datetime
from flask import Flask, request, jsonify, send_file, make_response
from werkzeug.utils import secure_filename
from flask_cors import CORS
import traceback

try:
    from core.rule_updater import RuleUpdater

    rule_updater = RuleUpdater()
    print("✅ 规则更新引擎加载成功")
except ImportError as e:
    print(f"❌ 规则更新引擎加载失败: {e}")

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('seckeeper.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger("SecKeeper")

try:
    from core.real_asset_scanner import RealAssetScanner
    from core.real_compliance_checker import RealComplianceChecker
    from core.real_vulnerability_scanner import RealVulnerabilityScanner
    import sys

    sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'core'))
    print("✅ 真实核心模块导入成功")

    asset_scanner = RealAssetScanner()
    compliance_checker = RealComplianceChecker()
    vulnerability_scanner = RealVulnerabilityScanner()

except ImportError as e:
    print(f"❌ 核心模块导入失败: {e}")
    raise e

try:
    from core.report_generator_fixed_safe import ReportGeneratorFixedSafe as ReportGeneratorFixed

    print("✅ 使用安全版PDF生成器")
except ImportError as e:
    print(f"❌ PDF生成器导入失败: {e}")
    raise e

app = Flask(__name__)
CORS(app)


class ThreadSafeScanManager:
    def __init__(self):
        self.lock = threading.Lock()
        self.status = {
            "is_scanning": False,
            "progress": 0,
            "current_step": "",
            "last_scan_time": None,
            "current_scan_id": None
        }

    def start_scan(self, scan_id):
        with self.lock:
            if self.status['is_scanning']:
                return False, "扫描正在进行中，请稍后重试", self.status['current_scan_id']

            self.status.update({
                "is_scanning": True,
                "progress": 0,
                "current_step": "初始化扫描",
                "current_scan_id": scan_id,
                "last_scan_time": datetime.now().isoformat()
            })
            return True, "扫描已开始", scan_id

    def update_progress(self, step, progress):
        with self.lock:
            self.status.update({"current_step": step, "progress": progress})

    def complete_scan(self):
        with self.lock:
            self.status.update({"is_scanning": False, "progress": 100, "current_step": "扫描完成"})

    def get_status(self):
        with self.lock:
            return self.status.copy()

    def force_reset(self):
        with self.lock:
            self.status.update({"is_scanning": False, "progress": 0, "current_step": "", "current_scan_id": None})
            return True


def _empty_vulnerability_payload():
    """返回兼容前端的空漏洞结构。"""
    return {
        "scan_summary": {
            "total_vulnerabilities": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "verified": 0,
            "unverified": 0,
            "needs_manual_check": 0,
            "local_verify": 0,
            "network_verify": 0,
            "version_match": 0
        },
        "details": [],
        "verification_summary": {
            "by_status": {"verified": 0, "unverified": 0, "needs_manual_check": 0},
            "by_method": {"local": 0, "network": 0, "version": 0, "unknown": 0},
            "by_safety": {}
        }
    }


def _build_vulnerability_summary(vulnerabilities):
    """基于漏洞明细生成风险与双核验证统计。"""
    summary = _empty_vulnerability_payload()["scan_summary"].copy()
    verification_summary = _empty_vulnerability_payload()["verification_summary"]

    summary["total_vulnerabilities"] = len(vulnerabilities)

    for vuln in vulnerabilities:
        severity = str(vuln.get("severity", "low")).lower()
        if severity in ("critical", "high", "medium", "low"):
            summary[severity] += 1

        status = str(vuln.get("verification_status", "unverified")).lower()
        if status not in verification_summary["by_status"]:
            verification_summary["by_status"][status] = 0
        verification_summary["by_status"][status] += 1

        if status in summary:
            summary[status] += 1

        method = str(vuln.get("verification_method", "unknown")).lower()
        if method not in verification_summary["by_method"]:
            verification_summary["by_method"][method] = 0
        verification_summary["by_method"][method] += 1

        if method == "local":
            summary["local_verify"] += 1
        elif method == "network":
            summary["network_verify"] += 1
        elif method in ("version", "version_match"):
            summary["version_match"] += 1

        safety = str(vuln.get("verification_safety", "unknown")).lower()
        verification_summary["by_safety"][safety] = verification_summary["by_safety"].get(safety, 0) + 1

    return summary, verification_summary


def aggregate_cve_results(raw_vulnerabilities):
    """
    聚合漏洞结果，同时保留验证方式、验证类型等 Knowledge Metadata。

    兼容旧前端：继续返回 scan_summary + details。
    增强新版前端：增加 verification_summary。
    """
    aggregated = {}

    for vuln in raw_vulnerabilities or []:
        c_id = vuln.get('vuln_id') or vuln.get('id') or f"UNKNOWN-{len(aggregated) + 1}"

        if c_id not in aggregated:
            aggregated[c_id] = vuln.copy()
            target = vuln.get('affected_target')
            aggregated[c_id]['affected_targets'] = [target] if target else []
            aggregated[c_id].pop('affected_target', None)
        else:
            target = vuln.get('affected_target')
            if target:
                aggregated[c_id]['affected_targets'].append(target)

            # 多个目标命中同一漏洞时，以最高可信状态为准。
            if vuln.get('verification_status') == 'verified':
                aggregated[c_id]['verification_status'] = 'verified'
                old_title = aggregated[c_id].get('title') or vuln.get('title') or c_id
                aggregated[c_id]['title'] = old_title.replace('🟡[疑似漏洞]', '🔴[实锤漏洞]')

            # 保留更具体的验证元数据。
            for key in ('verification_method', 'verification_engine', 'verification_safety', 'offline_supported'):
                if vuln.get(key) and not aggregated[c_id].get(key):
                    aggregated[c_id][key] = vuln.get(key)

    details = list(aggregated.values())
    summary, verification_summary = _build_vulnerability_summary(details)

    return {
        "scan_summary": summary,
        "summary": summary,  # 兼容新版 Core 命名
        "details": details,
        "vulnerabilities": details,
        "verification_summary": verification_summary
    }


def _extract_xinchuang_summary(compliance_data):
    """从合规检查结果中提取信创专项统计。"""
    if not isinstance(compliance_data, dict):
        return {}

    summary = compliance_data.get("xinchuang_summary")
    if isinstance(summary, dict):
        return summary

    # 兼容旧结构：从检查项文本中做轻量统计。
    keywords = {
        "kylin": ["银河麒麟", "kylin", "麒麟"],
        "uos": ["统信", "uos", "deepin"],
        "dameng": ["达梦", "dm8", "dameng"],
        "kingbase": ["金仓", "kingbase"],
        "tongweb": ["东方通", "tongweb"]
    }

    results = compliance_data.get("results") or compliance_data.get("checks") or []
    computed = {k: 0 for k in keywords}
    for item in results:
        if not isinstance(item, dict):
            continue
        text = json.dumps(item, ensure_ascii=False).lower()
        for key, words in keywords.items():
            if any(w.lower() in text for w in words):
                computed[key] += 1

    computed["total"] = sum(computed.values())
    return computed


def _build_scan_overview(scan_result):
    """为 Dashboard 统一生成概览数据。"""
    assets = scan_result.get('assets', {}) if isinstance(scan_result, dict) else {}
    compliance = scan_result.get('compliance', {}) if isinstance(scan_result, dict) else {}
    vuln_data = scan_result.get('vulnerabilities', {}) if isinstance(scan_result, dict) else {}

    vuln_summary = vuln_data.get('scan_summary') or vuln_data.get('summary') or _empty_vulnerability_payload()["scan_summary"]
    compliance_summary = compliance.get('summary', {}) if isinstance(compliance, dict) else {}

    return {
        "assets": {
            "software_count": len(assets.get('software', [])) if isinstance(assets, dict) else 0,
            "service_count": len(assets.get('services', [])) if isinstance(assets, dict) else 0,
            "xinchuang_os": assets.get('system_info', {}).get('xinchuang_os') if isinstance(assets, dict) else None
        },
        "compliance": {
            "total_checks": compliance_summary.get('total', 0),
            "passed_checks": compliance_summary.get('passed', 0),
            "failed_checks": compliance_summary.get('failed', 0),
            "compliance_rate": compliance_summary.get('compliance_rate', 0),
            "xinchuang_summary": _extract_xinchuang_summary(compliance)
        },
        "vulnerabilities": vuln_summary,
        "verification": vuln_data.get('verification_summary', _empty_vulnerability_payload()["verification_summary"]),
        "system_health": "healthy" if vuln_summary.get('critical', 0) == 0 else "warning"
    }



scan_manager = ThreadSafeScanManager()
scan_results = {}


def background_scan(scan_id, callback):
    try:
        logger.info(f"后台扫描开始: {scan_id}")

        def run_vulnerability_scan():
            scan_data = vulnerability_scanner.run_souffle_scan()
            raw_vulnerabilities = scan_data.get('vulnerabilities', [])
            aggregated = aggregate_cve_results(raw_vulnerabilities)

            # 透传 Core 扫描器提供的诊断信息，便于前端/报告展示。
            for key in ('success', 'status', 'scan_mode', 'detectors_used', 'detector_metrics', 'errors', 'warnings'):
                if key in scan_data:
                    aggregated[key] = scan_data[key]
            return aggregated

        steps = [
            ("资产清点", asset_scanner.scan_assets, 25),
            ("合规检查", compliance_checker.run_compliance_checks, 50),
            ("漏洞扫描", run_vulnerability_scan, 80),
            ("结果汇总", None, 100)
        ]

        results = {}
        step_errors = []

        for step_name, step_func, progress in steps:
            scan_manager.update_progress(step_name, progress)
            logger.info(f"执行步骤: {step_name}")
            if step_func:
                try:
                    step_result = step_func()
                    results[step_name] = step_result
                    logger.info(f"步骤完成: {step_name}")
                except Exception as e:
                    logger.exception(f"步骤失败: {step_name}")
                    step_errors.append({"step": step_name, "error": str(e)})
                    results[step_name] = {"success": False, "error": str(e)}

        scan_result = {
            "success": len(step_errors) == 0,
            "status": "completed" if len(step_errors) == 0 else "partial_success",
            "scan_id": scan_id,
            "timestamp": datetime.now().isoformat(),
            "assets": results.get("资产清点", {}),
            "compliance": results.get("合规检查", {}),
            "vulnerabilities": results.get("漏洞扫描", _empty_vulnerability_payload()),
            "errors": step_errors
        }
        scan_result["overview"] = _build_scan_overview(scan_result)

        scan_manager.complete_scan()
        logger.info(f"后台扫描完成: {scan_id}")
        callback(scan_result)

    except Exception as e:
        logger.exception("后台扫描异常")
        scan_manager.complete_scan()
        callback({"success": False, "status": "failed", "error": str(e), "scan_id": scan_id})


@app.route('/api/assets', methods=['GET'])
def get_assets():
    try:
        assets_data = asset_scanner.scan_assets()
        return jsonify({"success": True, "data": assets_data, "timestamp": datetime.now().isoformat()})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/compliance', methods=['GET'])
def get_compliance():
    try:
        compliance_data = compliance_checker.run_compliance_checks()
        return jsonify({"success": True, "data": compliance_data, "timestamp": datetime.now().isoformat()})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# 🟢 修复1：完全禁止在此接口执行耗时的 run_souffle_scan()
@app.route('/api/vulnerabilities', methods=['GET'])
def get_vulnerabilities():
    try:
        status = scan_manager.get_status()
        current_id = status.get('current_scan_id')

        # 直接从后端内存获取最近一次完整扫描结果
        if current_id and current_id in scan_results:
            vuln_data = scan_results[current_id].get('vulnerabilities', {})
            return jsonify({
                "success": True,
                "data": vuln_data,
                "timestamp": datetime.now().isoformat()
            })
        else:
            return jsonify({
                "success": True,
                "data": _empty_vulnerability_payload(),
                "timestamp": datetime.now().isoformat()
            })
    except Exception as e:
        logger.error(f"漏洞数据读取错误: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


# 🟢 修复2：禁止在获取首页状态时重新触发耗时扫描
@app.route('/api/dashboard', methods=['GET'])
def get_dashboard():
    try:
        status = scan_manager.get_status()
        current_id = status.get('current_scan_id')

        if current_id and current_id in scan_results:
            res = scan_results[current_id]
            overview = res.get('overview') or _build_scan_overview(res)
        else:
            overview = _build_scan_overview({
                "assets": {},
                "compliance": {},
                "vulnerabilities": _empty_vulnerability_payload()
            })

        return jsonify({
            "success": True,
            "data": {
                "overview": overview,
                "scan_status": scan_manager.get_status(),
                "timestamp": datetime.now().isoformat()
            }
        })
    except Exception as e:
        logger.error(f"Dashboard错误: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


# 🟢 修复重点：重写状态获取接口，直接解析本地 manifest.json 提取真实版本
@app.route('/api/rules/status', methods=['GET'])
def get_rule_status():
    """获取当前规则库版本与状态"""
    try:
        manifest_path = os.path.join(rule_updater.rules_dir, "manifest.json")
        if os.path.exists(manifest_path):
            with open(manifest_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                # 假设 manifest.json 里有 {"version": "xxx"} 的字段
                return jsonify({
                    "success": True,
                    "data": {
                        "db_version": data.get("version", "内置默认版"),
                        "last_updated": data.get("last_updated"),
                        "file_count": len(data.get("files", {})) if isinstance(data.get("files", {}), dict) else 0
                    }
                })

        return jsonify({
            "success": True,
            "data": {"db_version": "1.0.0 (基础版)"}
        })
    except Exception as e:
        logger.error(f"规则库状态获取失败: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/rules/check', methods=['GET'])
def check_rule_update():
    try:
        result = rule_updater.check_update_available()
        return jsonify({"success": True, "data": result})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/rules/update', methods=['POST'])
def perform_rule_update():
    try:
        result = rule_updater.download_updates()
        return jsonify({"success": result.get("success", False), "data": result})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500



@app.route('/api/rules/import-offline', methods=['POST'])
def import_offline_rules():
    """离线导入规则包：前端上传 zip，后端调用 RuleUpdater.import_offline_package。"""
    package_path = None
    try:
        if 'file' not in request.files:
            return jsonify({"success": False, "error": "未上传规则包文件"}), 400

        file = request.files['file']
        if not file or not file.filename:
            return jsonify({"success": False, "error": "规则包文件名为空"}), 400

        filename = secure_filename(file.filename)
        if not filename.lower().endswith('.zip'):
            return jsonify({"success": False, "error": "仅支持 zip 格式离线规则包"}), 400

        with tempfile.NamedTemporaryFile(delete=False, suffix='.zip') as tmp_file:
            package_path = tmp_file.name
            file.save(package_path)

        if not hasattr(rule_updater, 'import_offline_package'):
            return jsonify({"success": False, "error": "当前 RuleUpdater 不支持离线导入接口"}), 500

        result = rule_updater.import_offline_package(package_path)
        return jsonify({"success": result.get("success", False), "data": result})

    except Exception as e:
        logger.exception("离线规则包导入失败")
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        if package_path and os.path.exists(package_path):
            os.unlink(package_path)


@app.route('/api/scan', methods=['POST'])
def perform_scan():
    scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
    success, message, current_scan_id = scan_manager.start_scan(scan_id)

    if not success:
        return jsonify({"success": False, "error": message, "current_scan_id": current_scan_id}), 409

    def scan_complete_callback(result):
        scan_results[scan_id] = result
        print(f"📝 扫描结果已保存: {scan_id}")

    try:
        scan_thread = threading.Thread(target=background_scan, args=(scan_id, scan_complete_callback), daemon=True)
        scan_thread.start()
        return jsonify({
            "success": True,
            "data": {"scan_id": scan_id, "message": "扫描已开始，请稍后查看结果",
                     "status_url": f"/api/scan/{scan_id}/status"}
        })
    except Exception as e:
        scan_manager.force_reset()
        logger.error(f"启动扫描失败: {e}")
        return jsonify({"success": False, "error": f"启动扫描失败: {str(e)}"}), 500


@app.route('/api/scan/status', methods=['GET'])
def get_scan_status():
    return jsonify({"success": True, "data": scan_manager.get_status()})


@app.route('/api/scan/<scan_id>/status', methods=['GET'])
def get_specific_scan_status(scan_id):
    status = scan_manager.get_status()

    if status.get('current_scan_id') == scan_id and status.get('is_scanning'):
        return jsonify({
            "success": True,
            "data": {
                "scan_id": scan_id,
                "status": "running",
                "progress": status.get('progress', 0),
                "current_step": status.get('current_step', '')
            }
        })

    result = scan_results.get(scan_id)
    if result:
        return jsonify({"success": True, "data": {"scan_id": scan_id, "status": result.get('status', 'completed'), "result": result}})

    return jsonify({"success": False, "error": "扫描结果未找到"}), 404





@app.route('/api/report', methods=['POST'])
def generate_report():
    report_path = None
    try:
        data = request.get_json()
        if not data: return jsonify({"success": False, "error": "未提供扫描数据"}), 400
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as tmp_file:
            report_path = tmp_file.name
        success = ReportGeneratorFixed.generate_pdf_report(data, report_path)
        if success and os.path.exists(report_path):
            if os.path.getsize(report_path) > 100:
                return send_file(report_path, as_attachment=True,
                                 download_name=f"seckeeper_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                                 mimetype='application/pdf')
            else:
                return jsonify({"success": False, "error": "生成的PDF文件为空"}), 500
        else:
            return jsonify({"success": False, "error": "PDF报告生成失败"}), 500
    except Exception as e:
        return jsonify({"success": False, "error": f"生成报告时出错: {str(e)}"}), 500
    finally:
        if report_path and os.path.exists(report_path): os.unlink(report_path)


@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({
        "status": "healthy", "timestamp": datetime.now().isoformat(),
        "service": "SecKeeper Backend", "version": "2.0.0", "scan_status": scan_manager.get_status()
    })


if __name__ == '__main__':
    print("=" * 60)
    print("🚀 SecKeeper 真实环境后端服务启动")
    print("=" * 60)
    app.run(debug=True, host='0.0.0.0', port=5000, threaded=True)