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


def main():
    """主函数"""
    try:
        print("🚀 开始生成规则清单文件...")

        project_root = os.path.abspath(
            os.path.join(
                os.path.dirname(__file__),
                ".."
            )
        )

        rules_dir = os.path.join(
            project_root,
            "core",
            "rules"
        )

        manifest_path = os.path.join(
            rules_dir,
            "manifest.json"
        )

        if not os.path.exists(rules_dir):
            print(f"❌ 规则目录不存在: {rules_dir}")
            return

        version = get_next_version(manifest_path)

        print(f"📦 新版本号: {version}")

        files_info = {}

        rules_breakdown = {}

        total_rules = 0

        json_files = [
            f for f in os.listdir(rules_dir)
            if f.endswith(".json") and f != "manifest.json"
        ]

        print(f"📂 发现 {len(json_files)} 个规则文件")

        for filename in json_files:

            try:
                file_path = os.path.join(
                    rules_dir,
                    filename
                )

                print(f"🔍 处理规则文件: {filename}")

                sha256_value = calculate_sha256(file_path)

                file_size = os.path.getsize(file_path)

                rule_count = 0

                try:
                    with open(
                        file_path,
                        "r",
                        encoding="utf-8"
                    ) as f:

                        data = json.load(f)

                    if isinstance(data, dict):
                        rules = data.get("rules", [])

                        if isinstance(rules, list):
                            rule_count = len(rules)

                except Exception as e:
                    print(f"⚠️ 规则统计失败 {filename}: {e}")

                rules_breakdown[filename] = rule_count

                total_rules += rule_count

                files_info[filename] = {
                    "version": version,
                    "sha256": sha256_value,
                    "size": file_size,
                    "rule_count": rule_count
                }

                print(
                    f"✅ {filename} | "
                    f"规则数: {rule_count} | "
                    f"大小: {file_size} bytes"
                )

            except Exception as e:
                print(f"❌ 文件处理失败 {filename}: {e}")

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

        with open(
            manifest_path,
            "w",
            encoding="utf-8"
        ) as f:
            json.dump(
                manifest,
                f,
                indent=4,
                ensure_ascii=False
            )

        print("🎉 manifest.json 生成完成")
        print(f"📄 输出文件: {manifest_path}")
        print(f"📊 总规则数: {total_rules}")
        print(f"📦 当前版本: {version}")

    except Exception as e:
        print(f"❌ manifest 生成失败: {e}")


if __name__ == "__main__":
    main()