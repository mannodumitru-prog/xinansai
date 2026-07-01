#!/usr/bin/env python3
"""
SecKeeper 规则服务器 manifest 生成工具

功能：
1. 递归扫描 core/rules/ 目录
2. 统计 JSON 规则数量，同时纳入 yaml_pocs/ 与 pocs/ 中的 YAML/Python PoC
3. 计算 SHA256
4. 生成 manifest.json
5. 自动递增版本号

用法：
python core/tools/update_rule_server.py
或：
python update_rule_server.py --rules-dir /path/to/core/rules --remote-url https://.../
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from datetime import datetime
from typing import Dict, Tuple

ALLOWED_EXTENSIONS = (".json", ".yaml", ".yml", ".py")
EXCLUDED_FILES = {"manifest.json"}


def calculate_sha256(file_path: str) -> str:
    """计算文件 SHA256。"""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()


def get_next_version(manifest_path: str) -> str:
    """自动递增 patch 版本号。"""
    try:
        if not os.path.exists(manifest_path):
            return "1.0.0"
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)
        current_version = manifest.get("version", "1.0.0")
        parts = current_version.split(".")
        while len(parts) < 3:
            parts.append("0")
        major, minor, patch = [int(x) for x in parts[:3]]
        return f"{major}.{minor}.{patch + 1}"
    except Exception as e:
        print(f"⚠️ 版本号生成失败，回退到 1.0.0: {e}")
        return "1.0.0"


def count_rules(file_path: str) -> int:
    """统计 JSON 规则数量。YAML/Python PoC 默认按 1 个载荷计数。"""
    ext = os.path.splitext(file_path)[1].lower()
    if ext in (".yaml", ".yml", ".py"):
        return 1
    if ext != ".json":
        return 0

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict) and isinstance(data.get("rules"), list):
            return len(data["rules"])
        if isinstance(data, list):
            return len(data)
    except Exception as e:
        print(f"⚠️ 规则统计失败 {file_path}: {e}")
    return 0


def iter_rule_files(rules_dir: str):
    """递归枚举规则文件，返回相对路径与绝对路径。"""
    for root, _, files in os.walk(rules_dir):
        for filename in files:
            if filename in EXCLUDED_FILES:
                continue
            ext = os.path.splitext(filename)[1].lower()
            if ext not in ALLOWED_EXTENSIONS:
                continue
            abs_path = os.path.join(root, filename)
            rel_path = os.path.relpath(abs_path, rules_dir).replace(os.sep, "/")
            if rel_path.startswith("../") or rel_path.startswith("/"):
                continue
            yield rel_path, abs_path


def build_manifest(rules_dir: str, remote_url: str, version: str) -> Tuple[Dict, int]:
    files_info: Dict[str, Dict] = {}
    rules_breakdown: Dict[str, int] = {}
    total_rules = 0

    for rel_path, abs_path in sorted(iter_rule_files(rules_dir)):
        try:
            rule_count = count_rules(abs_path)
            file_size = os.path.getsize(abs_path)
            sha256_value = calculate_sha256(abs_path)

            files_info[rel_path] = {
                "version": version,
                "sha256": sha256_value,
                "size": file_size,
                "rule_count": rule_count,
            }
            rules_breakdown[rel_path] = rule_count
            total_rules += rule_count

            print(f"✅ {rel_path} | 规则/载荷数: {rule_count} | 大小: {file_size} bytes")
        except Exception as e:
            print(f"❌ 文件处理失败 {rel_path}: {e}")

    manifest = {
        "version": version,
        "last_updated": datetime.now().strftime("%Y-%m-%d"),
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "update_url": remote_url.rstrip("/") + "/",
        "rules_breakdown": rules_breakdown,
        "total_rules": total_rules,
        "files": files_info,
    }
    return manifest, total_rules


def resolve_default_rules_dir() -> str:
    """兼容脚本位于 core/tools 或项目根工具目录两种情况。"""
    here = os.path.abspath(os.path.dirname(__file__))
    candidates = [
        os.path.abspath(os.path.join(here, "..", "rules")),          # core/tools -> core/rules
        os.path.abspath(os.path.join(here, "..", "core", "rules")),  # tools -> core/rules
        os.path.abspath(os.path.join(here, "core", "rules")),         # project root
    ]
    for path in candidates:
        if os.path.isdir(path):
            return path
    return candidates[0]


def main():
    parser = argparse.ArgumentParser(description="Generate SecKeeper rule manifest.json")
    parser.add_argument("--rules-dir", default=resolve_default_rules_dir(), help="规则目录，默认自动探测 core/rules")
    parser.add_argument("--remote-url", default="https://raw.githubusercontent.com/mannodumitru-prog/seckeeper-rules/main/", help="规则仓库 raw URL")
    parser.add_argument("--version", default=None, help="指定版本号；不指定则自动递增 patch")
    args = parser.parse_args()

    rules_dir = os.path.abspath(args.rules_dir)
    manifest_path = os.path.join(rules_dir, "manifest.json")

    print("🚀 开始生成规则清单文件...")
    print(f"📂 规则目录: {rules_dir}")

    if not os.path.isdir(rules_dir):
        print(f"❌ 规则目录不存在: {rules_dir}")
        return

    version = args.version or get_next_version(manifest_path)
    print(f"📦 新版本号: {version}")

    manifest, total_rules = build_manifest(rules_dir, args.remote_url, version)

    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=4, ensure_ascii=False)

    print("🎉 manifest.json 生成完成")
    print(f"📄 输出文件: {manifest_path}")
    print(f"📊 总规则/载荷数: {total_rules}")
    print(f"📦 当前版本: {version}")


if __name__ == "__main__":
    main()
