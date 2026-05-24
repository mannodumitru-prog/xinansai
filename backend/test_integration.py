#!/usr/bin/env python3
"""SecKeeper 2.0 CVE模块集成测试"""

import sys
import json
sys.path.insert(0, "core")

print("=" * 60)
print("SecKeeper 2.0 集成测试")
print("=" * 60)

# 测试1：规则加载
print("\n[1/4] 测试规则加载...")
import os
rules_path = os.path.join("core", "rules", "cve_rules.json")
with open(rules_path, "r") as f:
    rules = json.load(f)
print(f"  ✅ 加载成功: {len(rules['rules'])} 条规则")

# 测试2：调度器扫描
print("\n[2/4] 测试调度器扫描...")
from real_vulnerability_scanner import RealVulnerabilityScanner
scanner = RealVulnerabilityScanner()
result = scanner.run_souffle_scan()
print(f"  ✅ 扫描完成: {result['scan_summary']['total_vulnerabilities']} 个漏洞")
print(f"  📊 严重:{result['scan_summary']['critical']} 高危:{result['scan_summary']['high']} 中危:{result['scan_summary']['medium']} 低危:{result['scan_summary']['low']}")

# 测试3：规则状态
print("\n[3/4] 测试规则状态...")
from rule_updater import RuleUpdater
updater = RuleUpdater()
status = updater.get_current_status()
print(f"  ✅ 版本: {status['db_version']}")
print(f"  ✅ 上次更新: {status['last_updated']}")
print(f"  ✅ 需提醒: {updater.needs_update_reminder()}")

# 测试4：检出漏洞详情
print("\n[4/4] 检测到的漏洞:")
for v in result.get("vulnerabilities", []):
    print(f"  [{v['severity'].upper()}] {v['vuln_id']} → {v['affected_target']}")

print("\n" + "=" * 60)
print("✅ 全部测试通过")
print("=" * 60)