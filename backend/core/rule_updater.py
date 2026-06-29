#!/usr/bin/env python3
"""
规则更新引擎模块 (架构师稳健终极版)
功能：
1. 自动处理子目录 (如 yaml_pocs/)
2. 内置扩展名白名单安全过滤 (.py 穿甲弹已解封)
3. 智能双条件触发（版本号 OR 哈希值任一变动即更新）
4. 严谨幂等台账（无新子弹落盘，绝不篡改清单印章）
"""

import os
import json
import hashlib
import shutil
import requests
from datetime import datetime
from typing import Dict, List, Optional, Callable

class RuleUpdater:
    def __init__(self, rules_dir: str = None, manifest_file: str = None, remote_url: str = None):
        try:
            self.rules_dir = rules_dir or os.path.abspath(
                os.path.join(os.path.dirname(__file__), "rules")
            )
            self.manifest_file = manifest_file or os.path.join(self.rules_dir, "manifest.json")
            self.remote_url = remote_url or "https://raw.githubusercontent.com/mannodumitru-prog/seckeeper-rules/main/"
            self.allowed_extensions = ('.json', '.yaml', '.yml', '.py')
            print(f"✅ RuleUpdater 初始化完成, 规则路径: {self.rules_dir}")
        except Exception as e:
            print(f"❌ 初始化失败: {e}")

    def download_updates(self, progress_callback: Optional[Callable] = None) -> Dict:
        """支持子目录下载、安全过滤与幂等台账的更新逻辑"""
        try:
            update_info = self.check_update_available()
            if not update_info.get("update_available", False):
                return {"success": True, "updated_files": [], "message": "No updates available"}

            print("⬇️ 开始下载更新...")
            response = requests.get(self.remote_url + "manifest.json", timeout=15)
            response.raise_for_status()
            remote_manifest = response.json()
            files_to_update = update_info.get("files_to_update", [])
            updated_files = []

            for filename in files_to_update:
                # 1. 安全防护：白名单校验
                if not filename.endswith(self.allowed_extensions):
                    print(f"⚠️ 拦截不安全文件: {filename}")
                    continue

                print(f"⬇️ 处理文件: {filename}")
                file_url = self.remote_url + filename
                response = requests.get(file_url, timeout=15)
                response.raise_for_status()

                # 2. 自动处理子目录
                target_path = os.path.join(self.rules_dir, filename)
                os.makedirs(os.path.dirname(target_path), exist_ok=True)
                
                tmp_path = target_path + ".tmp"
                with open(tmp_path, "wb") as f:
                    f.write(response.content)

                # 3. SHA256 校验
                expected_sha256 = remote_manifest.get("files", {}).get(filename, {}).get("sha256")
                if expected_sha256 and not self._verify_checksum(tmp_path, expected_sha256):
                    print(f"❌ 校验失败: {filename}")
                    os.remove(tmp_path)
                    continue

                # 原子替换
                shutil.move(tmp_path, target_path)
                updated_files.append(filename)
                print(f"✅ 更新成功: {filename}")

            # 【核心架构修正：严禁无脑全量覆盖本地清单！】
            if len(updated_files) > 0:
                local_m = {}
                if os.path.exists(self.manifest_file):
                    with open(self.manifest_file, "r", encoding="utf-8") as f:
                        local_m = json.load(f)

                if "files" not in local_m:
                    local_m["files"] = {}
                for uf in updated_files:
                    local_m["files"][uf] = remote_manifest["files"][uf]

                local_m["version"] = remote_manifest.get("version", "1.0.0")

                with open(self.manifest_file, "w", encoding="utf-8") as f:
                    json.dump(local_m, f, indent=4, ensure_ascii=False)

                print(f"📦 本地台账清单已同步变更至: v{local_m['version']}")
            else:
                print("💤 本轮无新载荷落盘，本地台账清单保持原状。")

            return {"success": True, "updated_files": updated_files}
        except Exception as e:
            return {"success": False, "message": str(e)}

    def check_update_available(self) -> Dict:
        """检查远程更新（双保险触发机制）"""
        try:
            local_manifest = {}
            if os.path.exists(self.manifest_file):
                with open(self.manifest_file, "r", encoding="utf-8") as f:
                    local_manifest = json.load(f)

            response = requests.get(self.remote_url + "manifest.json", timeout=10)
            response.raise_for_status()
            remote_manifest = response.json()
            
            files_to_update = []
            for filename, remote_info in remote_manifest.get("files", {}).items():
                local_info = local_manifest.get("files", {}).get(filename, {})
                
                # 双条件触发：只要版本号不同，或者哈希值不同，立刻判定需要更新！
                if (local_info.get("version") != remote_info.get("version")) or \
                   (local_info.get("sha256") != remote_info.get("sha256")):
                    files_to_update.append(filename)
            
            return {"update_available": len(files_to_update) > 0, "files_to_update": files_to_update}
        except Exception as e:
            return {"update_available": False, "error": str(e)}

    def _verify_checksum(self, file_path: str, expected_sha256: str) -> bool:
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""): sha256_hash.update(chunk)
        return sha256_hash.hexdigest().lower() == expected_sha256.lower()

if __name__ == "__main__":
    updater = RuleUpdater()
    print(updater.download_updates())
