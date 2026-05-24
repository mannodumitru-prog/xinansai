#!/usr/bin/env python3
"""
规则更新引擎模块

功能：
1. 检查规则库更新
2. 下载最新规则文件
3. 校验规则文件完整性
4. 更新本地规则数据库
5. 提供规则状态与更新提醒
"""

import os
import json
import time
import hashlib
import shutil
import requests

from datetime import datetime
from typing import Dict, List, Optional, Callable


class RuleUpdater:
    """规则更新引擎"""

    def __init__(
        self,
        rules_dir: str = None,
        manifest_file: str = None,
        remote_url: str = None
    ):
        """初始化规则更新器"""
        try:
            self.rules_dir = rules_dir or os.path.join(
                os.path.dirname(__file__),
                "rules"
            )

            self.manifest_file = manifest_file or os.path.join(
                self.rules_dir,
                "manifest.json"
            )

            self.remote_url = remote_url or (
                "https://raw.githubusercontent.com/"
                "mannodumitru-prog/seckeeper-rules/main/"
            )

            self.update_interval_days = 7

            print("✅ RuleUpdater 初始化完成")

        except Exception as e:
            print(f"❌ RuleUpdater 初始化失败: {e}")

    def get_current_status(self) -> Dict:
        """获取当前规则库状态"""
        try:
            if not os.path.exists(self.manifest_file):
                return {
                    "db_version": "0.0.0",
                    "error": "manifest not found"
                }

            with open(self.manifest_file, "r", encoding="utf-8") as f:
                manifest = json.load(f)

            last_updated = manifest.get("last_updated", "")

            days_since_update = 0

            try:
                if last_updated:
                    last_date = datetime.fromisoformat(last_updated)
                    days_since_update = (
                        datetime.now() - last_date
                    ).days
            except Exception:
                days_since_update = 0

            return {
                "db_version": manifest.get("version", "0.0.0"),
                "last_updated": last_updated,
                "days_since_update": days_since_update,
                "rules_breakdown": manifest.get("rules_breakdown", {})
            }

        except Exception as e:
            print(f"❌ 获取规则状态失败: {e}")

            return {
                "db_version": "0.0.0",
                "error": str(e)
            }

    def check_update_available(self) -> Dict:
        """检查是否有可用更新"""
        try:
            local_manifest = {}

            local_version = "0.0.0"

            if os.path.exists(self.manifest_file):
                with open(self.manifest_file, "r", encoding="utf-8") as f:
                    local_manifest = json.load(f)

                local_version = local_manifest.get("version", "0.0.0")

            print("🌐 检查远程规则更新...")

            response = requests.get(
                self.remote_url + "manifest.json",
                timeout=10
            )

            response.raise_for_status()

            remote_manifest = response.json()

            remote_version = remote_manifest.get("version", "0.0.0")

            local_files = local_manifest.get("files", {})
            remote_files = remote_manifest.get("files", {})

            files_to_update = []

            for filename, remote_info in remote_files.items():

                local_info = local_files.get(filename, {})

                local_file_version = local_info.get("version", "0.0.0")
                remote_file_version = remote_info.get("version", "0.0.0")

                if local_file_version != remote_file_version:
                    files_to_update.append(filename)

            update_available = len(files_to_update) > 0

            return {
                "update_available": update_available,
                "local_version": local_version,
                "remote_version": remote_version,
                "files_to_update": files_to_update
            }

        except Exception as e:
            print(f"❌ 检查更新失败: {e}")

            return {
                "update_available": False,
                "error": str(e)
            }

    def needs_update_reminder(self) -> bool:
        """检查是否需要更新提醒"""
        try:
            status = self.get_current_status()

            if "error" in status:
                return True

            days_since_update = status.get("days_since_update", 0)

            return days_since_update >= self.update_interval_days

        except Exception as e:
            print(f"❌ 更新提醒检查失败: {e}")
            return False

    def download_updates(
        self,
        progress_callback: Optional[Callable] = None
    ) -> Dict:
        """下载规则更新"""
        try:
            update_info = self.check_update_available()

            if not update_info.get("update_available", False):
                return {
                    "success": True,
                    "updated_files": [],
                    "message": "No updates available"
                }

            print("⬇️ 开始下载规则更新...")

            response = requests.get(
                self.remote_url + "manifest.json",
                timeout=10
            )

            response.raise_for_status()

            remote_manifest = response.json()

            files_to_update = update_info.get(
                "files_to_update",
                []
            )

            updated_files = []

            total_files = len(files_to_update)

            for index, filename in enumerate(files_to_update):

                try:
                    percent = int(
                        ((index + 1) / total_files) * 100
                    )

                    if progress_callback:
                        progress_callback(
                            percent,
                            f"Downloading {filename}"
                        )

                    print(f"⬇️ 下载文件: {filename}")

                    file_url = self.remote_url + filename

                    response = requests.get(
                        file_url,
                        timeout=10
                    )

                    response.raise_for_status()

                    target_path = os.path.join(
                        self.rules_dir,
                        filename
                    )

                    tmp_path = target_path + ".tmp"

                    os.makedirs(
                        os.path.dirname(target_path),
                        exist_ok=True
                    )

                    with open(tmp_path, "wb") as f:
                        f.write(response.content)

                    expected_sha256 = (
                        remote_manifest
                        .get("files", {})
                        .get(filename, {})
                        .get("sha256")
                    )

                    if expected_sha256:

                        if not self._verify_checksum(
                            tmp_path,
                            expected_sha256
                        ):
                            print(
                                f"❌ SHA256校验失败: {filename}"
                            )

                            os.remove(tmp_path)

                            continue

                    try:
                        shutil.move(tmp_path, target_path)
                    except Exception:
                        os.rename(tmp_path, target_path)

                    updated_files.append(filename)

                    print(f"✅ 更新完成: {filename}")

                except Exception as e:
                    print(f"❌ 文件更新失败 {filename}: {e}")

            remote_manifest["last_updated"] = (
                datetime.now().isoformat()
            )

            """to do 合并而不是全部替代 """
            with open(
                self.manifest_file,
                "w",
                encoding="utf-8"
            ) as f:
                json.dump(
                    remote_manifest,
                    f,
                    indent=4,
                    ensure_ascii=False
                )

            if progress_callback:
                progress_callback(
                    100,
                    "Update completed"
                )

            return {
                "success": True,
                "updated_files": updated_files,
                "message": f"Updated {len(updated_files)} files"
            }

        except Exception as e:
            print(f"❌ 规则更新失败: {e}")

            return {
                "success": False,
                "updated_files": [],
                "message": str(e)
            }

    def _verify_checksum(
        self,
        file_path: str,
        expected_sha256: str
    ) -> bool:
        """校验文件SHA256"""
        try:
            sha256_hash = hashlib.sha256()

            with open(file_path, "rb") as f:

                for chunk in iter(
                    lambda: f.read(4096),
                    b""
                ):
                    sha256_hash.update(chunk)

            calculated_hash = sha256_hash.hexdigest()

            return (
                calculated_hash.lower() ==
                expected_sha256.lower()
            )

        except Exception as e:
            print(f"❌ SHA256校验失败: {e}")
            return False



""" 测试；"""
if __name__ == "__main__":
    updater = RuleUpdater()

    # 测试1：获取本地状态
    print("=" * 50)
    print("测试：本地状态")
    status = updater.get_current_status()
    print(json.dumps(status, indent=2, ensure_ascii=False))

    # 测试2：更新提醒
    print("\n" + "=" * 50)
    print("测试：更新提醒")
    print(f"需要提醒: {updater.needs_update_reminder()}")

    # 测试3：检查更新（会尝试联网，网络不通会走error分支，正常）
    print("\n" + "=" * 50)
    print("测试：检查更新")
    result = updater.check_update_available()
    print(json.dumps(result, indent=2, ensure_ascii=False))

    # 测试4：执行真实下载更新
    print("\n" + "=" * 50)
    print("测试：执行规则下载")

    # 定义一个简单的进度回调函数，让输出更好看
    def print_progress(percent, message):
        print(f"[{percent}%] {message}")

    download_result = updater.download_updates(progress_callback=print_progress)
    print(json.dumps(download_result, indent=2, ensure_ascii=False))