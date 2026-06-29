#!/usr/bin/env python3
"""
规则更新引擎模块 (架构师稳健版)
功能：
1. 自动处理子目录 (如 yaml_pocs/)
2. 内置扩展名白名单安全过滤
3. 智能SHA256校验与原子性更新
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
            # 自动锚定到当前文件所在目录的上一级 rules 文件夹
            self.rules_dir = rules_dir or os.path.abspath(
                os.path.join(os.path.dirname(__file__), "rules")
            )
            self.manifest_file = manifest_file or os.path.join(self.rules_dir, "manifest.json")
            self.remote_url = remote_url or "https://raw.githubusercontent.com/mannodumitru-prog/seckeeper-rules/main/"
            self.allowed_extensions = ('.json', '.yaml', '.yml')
            print(f"✅ RuleUpdater 初始化完成, 规则路径: {self.rules_dir}")
        except Exception as e:
            print(f"❌ 初始化失败: {e}")

    def download_updates(self, progress_callback: Optional[Callable] = None) -> Dict:
        """支持子目录下载与安全过滤的更新逻辑"""
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

            # 更新本地清单
            with open(self.manifest_file, "w", encoding="utf-8") as f:
                json.dump(remote_manifest, f, indent=4, ensure_ascii=False)
            
            return {"success": True, "updated_files": updated_files}
        except Exception as e:
            return {"success": False, "message": str(e)}

    def check_update_available(self) -> Dict:
        """检查远程更新"""
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
                if local_info.get("version") != remote_info.get("version"):
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
