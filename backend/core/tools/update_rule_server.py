#!/usr/bin/env python3
"""
规则服务器更新工具

功能：
1. 扫描 core/rules/ 目录
2. 自动统计规则文件
3. 计算 SHA256 校验值
4. 自动生成 manifest.json
5. 自动递增规则库版本号

用法：
python tools/update_rule_server.py
"""

import os
import json
import hashlib

from datetime import datetime


def calculate_sha256(file_path: str) -> str:
    """计算文件 SHA256"""
    try:
        sha256_hash = hashlib.sha256()

        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)

        return sha256_hash.hexdigest()

    except Exception as e:
        print(f"❌ SHA256 计算失败: {e}")
        return ""


def get_next_version(manifest_path: str) -> str:
    """自动递增版本号"""
    try:
        if not os.path.exists(manifest_path):
            return "1.0.0"

        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)

        current_version = manifest.get("version", "1.0.0")

        parts = current_version.split(".")

        while len(parts) < 3:
            parts.append("0")

        major = int(parts[0])
        minor = int(parts[1])
        patch = int(parts[2])

        patch += 1

        return f"{major}.{minor}.{patch}"

    except Exception as e:
        print(f"❌ 版本号生成失败: {e}")
        return "1.0.0"


def process_json_file(file_path: str, version: str) -> dict:
    """处理 JSON 规则文件，统计规则数量"""
    sha256_value = calculate_sha256(file_path)
    file_size = os.path.getsize(file_path)
    rule_count = 0

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        if isinstance(data, dict):
            rules = data.get("rules", [])
            if isinstance(rules, list):
                rule_count = len(rules)
    except Exception as e:
        print(f"⚠️ 规则统计失败 {os.path.basename(file_path)}: {e}")

    return {
        "sha256": sha256_value,
        "size": file_size,
        "rule_count": rule_count
    }


def process_yaml_file(file_path: str, version: str) -> dict:
    """处理 YAML PoC 文件"""
    sha256_value = calculate_sha256(file_path)
    file_size = os.path.getsize(file_path)

    return {
        "sha256": sha256_value,
        "size": file_size,
        "rule_count": 1
    }


def main():
    """主函数"""
    try:
        print("🚀 开始生成规则清单文件...")

        project_root = os.path.abspath(
            os.path.join(
                os.path.dirname(__file__),
                "..",
                ".."
            )
        )

        rules_dir = os.path.join(project_root, "core", "rules")
        manifest_path = os.path.join(rules_dir, "manifest.json")

        if not os.path.exists(rules_dir):
            print(f"❌ 规则目录不存在: {rules_dir}")
            return

        version = get_next_version(manifest_path)
        print(f"📦 新版本号: {version}")

        files_info = {}
        rules_breakdown = {}
        total_rules = 0
        yaml_poc_count = 0
        python_poc_count = 0

        print(f"📂 开始扫描 {rules_dir} 及其子目录...")

        for root, dirs, files in os.walk(rules_dir):
            for filename in files:
                if filename == "manifest.json":
                    continue

                try:
                    file_path = os.path.join(root, filename)
                    rel_path = os.path.relpath(file_path, rules_dir).replace(os.sep, '/')
                    print(f"🔍 处理文件: {rel_path}")

                    if filename.endswith('.json'):
                        result = process_json_file(file_path, version)
                        rules_breakdown[rel_path] = result["rule_count"]
                        total_rules += result["rule_count"]
                    elif filename.endswith('.yaml') or filename.endswith('.yml'):
                        result = process_yaml_file(file_path, version)
                        yaml_poc_count += 1
                    elif filename.endswith('.py'):
                        result = process_yaml_file(file_path, version)  # 复用相同逻辑
                        python_poc_count += 1
                    else:
                        # 对于其他文件类型，也作为通用文件处理
                        result = {
                            "sha256": calculate_sha256(file_path),
                            "size": os.path.getsize(file_path),
                            "rule_count": 1
                        }
                        print(f"   📄 通用文件, rule_count 设为 1")

                    files_info[rel_path] = {
                        "version": version,
                        "sha256": result["sha256"],
                        "size": result["size"],
                        "rule_count": result["rule_count"]
                    }

                    print(
                        f"✅ {rel_path} | "
                        f"规则数: {result['rule_count']} | "
                        f"大小: {result['size']} bytes"
                    )

                except Exception as e:
                    print(f"❌ 文件处理失败 {filename}: {e}")

        # 将统计数加入 rules_breakdown
        if yaml_poc_count > 0:
            rules_breakdown["yaml_poc_count"] = yaml_poc_count
        if python_poc_count > 0:
            rules_breakdown["python_poc_count"] = python_poc_count

        manifest = {
            "version": version,
            "last_updated": datetime.now().strftime("%Y-%m-%d"),
            "update_url": (
                "https://raw.githubusercontent.com/"
                "YOUR_USERNAME/seckeeper-rules/main/"
            ),
            "rules_breakdown": rules_breakdown,
            "files": files_info
        }

        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=4, ensure_ascii=False)

        print("🎉 manifest.json 生成完成")
        print(f"📄 输出文件: {manifest_path}")
        print(f"📊 总规则数: {total_rules}")
        print(f"🔧 YAML PoC 模板数: {yaml_poc_count}")
        print(f"📦 当前版本: {version}")

    except Exception as e:
        print(f"❌ manifest 生成失败: {e}")


if __name__ == "__main__":
    main()