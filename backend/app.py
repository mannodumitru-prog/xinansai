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


def aggregate_cve_results(raw_vulnerabilities):
    aggregated = {}
    for vuln in raw_vulnerabilities:
        c_id = vuln.get('vuln_id')
        if c_id not in aggregated:
            aggregated[c_id] = vuln.copy()
            aggregated[c_id]['affected_targets'] = [vuln.get('affected_target')]
            aggregated[c_id].pop('affected_target', None)
        else:
            aggregated[c_id]['affected_targets'].append(vuln.get('affected_target'))
            if vuln.get('verification_status') == 'verified':
                aggregated[c_id]['verification_status'] = 'verified'
                aggregated[c_id]['title'] = vuln.get('title').replace('🟡[疑似漏洞]', '🔴[实锤漏洞]')

    summary = {"total_vulnerabilities": len(aggregated), "critical": 0, "high": 0, "medium": 0, "low": 0}
    for v in aggregated.values():
        sev = v.get('severity', 'low').lower()
        if sev in summary: summary[sev] += 1

    return {"scan_summary": summary, "details": list(aggregated.values())}


scan_manager = ThreadSafeScanManager()
scan_results = {}


def background_scan(scan_id, callback):
    try:
        print(f"🚀 后台扫描开始: {scan_id}")

        def run_new_cve_scan():
            scan_data = vulnerability_scanner.run_souffle_scan()
            raw_vulnerabilities = scan_data.get('vulnerabilities', [])
            return aggregate_cve_results(raw_vulnerabilities)

        steps = [
            ("资产清点", asset_scanner.scan_assets, 25),
            ("合规检查", compliance_checker.run_compliance_checks, 50),
            ("漏洞扫描", run_new_cve_scan, 75),
            ("生成报告", None, 100)
        ]

        results = {}
        for step_name, step_func, progress in steps:
            scan_manager.update_progress(step_name, progress)
            print(f"🔧 执行步骤: {step_name}")
            if step_func:
                try:
                    step_result = step_func()
                    results[step_name] = step_result
                    print(f"✅ 步骤完成: {step_name}")
                    time.sleep(2)
                except Exception as e:
                    print(f"❌ 步骤失败: {step_name}, 错误: {e}")
                    results[step_name] = {"error": str(e)}

        scan_result = {
            "scan_id": scan_id,
            "timestamp": datetime.now().isoformat(),
            "assets": results.get("资产清点", {}),
            "compliance": results.get("合规检查", {}),
            "vulnerabilities": results.get("漏洞扫描", {}),
            "status": "completed"
        }

        scan_manager.complete_scan()
        print(f"🎉 后台扫描完成: {scan_id}")
        callback(scan_result)

    except Exception as e:
        print(f"❌ 后台扫描异常: {e}")
        traceback.print_exc()
        scan_manager.complete_scan()
        callback({"error": str(e)})


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
                "data": {"scan_summary": {"total_vulnerabilities": 0}, "details": []},
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
            vuln_data = res.get('vulnerabilities', {})
            overview = {
                "assets": {
                    "software_count": len(res.get('assets', {}).get('software', [])),
                    "service_count": len(res.get('assets', {}).get('services', []))
                },
                "compliance": {
                    "total_checks": res.get('compliance', {}).get('summary', {}).get('total', 0),
                    "passed_checks": res.get('compliance', {}).get('summary', {}).get('passed', 0),
                    "compliance_rate": res.get('compliance', {}).get('summary', {}).get('compliance_rate', 0)
                },
                "vulnerabilities": vuln_data.get('scan_summary', {
                    "total_vulnerabilities": 0, "critical": 0, "high": 0, "medium": 0, "low": 0
                }),
                "system_health": "healthy" if vuln_data.get('scan_summary', {}).get('critical', 0) == 0 else "warning"
            }
        else:
            overview = {
                "assets": {"software_count": 0, "service_count": 0},
                "compliance": {"total_checks": 0, "passed_checks": 0, "compliance_rate": 0},
                "vulnerabilities": {"total_vulnerabilities": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
                "system_health": "healthy"
            }

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
                    "data": {"db_version": data.get("version", "内置默认版")}
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
    if status['current_scan_id'] == scan_id:
        if status['is_scanning']:
            return jsonify({
                "success": True,
                "data": {"scan_id": scan_id, "status": "running", "progress": status['progress'],
                         "current_step": status['current_step']}
            })
        else:
            result = scan_results.get(scan_id)
            if result:
                return jsonify({"success": True, "data": {"scan_id": scan_id, "status": "completed", "result": result}})

            result = scan_results.get(scan_id)
            if result:
                return jsonify({"success": True, "data": {"scan_id": scan_id, "status": "completed", "result": result}})
            else:
                return jsonify({"success": False, "error": "扫描结果未找到"}), 404
    else:
        return jsonify({"success": False, "error": "扫描ID不匹配或扫描已结束"}), 404




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