#!/usr/bin/env python3
"""
SecKeeper 规则更新引擎

目标：
1. 在线规则更新：manifest.json -> 文件下载 -> SHA256 校验 -> 原子替换
2. 安全防护：阻止路径穿越、限制文件类型、校验 manifest 结构
3. 稳定性：下载失败不破坏本地规则；只有成功落盘的文件才写入本地 manifest
4. 可扩展：保留离线规则包导入接口 import_offline_package()
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import zipfile
from datetime import datetime, timedelta
from typing import Callable, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urljoin

import requests


class RuleUpdater:
    """规则更新器。"""

    DEFAULT_REMOTE_URL = "https://raw.githubusercontent.com/mannodumitru-prog/seckeeper-rules/main/"
    DEFAULT_UPDATE_INTERVAL_HOURS = 24

    def __init__(
        self,
        rules_dir: str = None,
        manifest_file: str = None,
        remote_url: str = None,
        update_interval_hours: int = DEFAULT_UPDATE_INTERVAL_HOURS,
    ):
        self.rules_dir = os.path.abspath(
            rules_dir or os.path.join(os.path.dirname(__file__), "rules")
        )
        self.manifest_file = os.path.abspath(
            manifest_file or os.path.join(self.rules_dir, "manifest.json")
        )
        configured_remote_url = remote_url or self._read_manifest_update_url(self.manifest_file) or self.DEFAULT_REMOTE_URL
        self.remote_url = configured_remote_url.rstrip("/") + "/"
        self.update_interval_hours = update_interval_hours

        # .py 是本地 PoC 规则的一部分，但必须配合路径穿越校验一起使用。
        self.allowed_extensions = (".json", ".yaml", ".yml", ".py")
        os.makedirs(self.rules_dir, exist_ok=True)

        print(f"✅ RuleUpdater 初始化完成, 规则路径: {self.rules_dir}")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def needs_update_reminder(self) -> bool:
        """
        判断是否需要尝试在线更新。
        只根据本地 manifest 的 last_checked 字段节流，避免每次扫描都联网。
        """
        manifest = self._load_json_file(self.manifest_file, default={})
        last_checked = manifest.get("last_checked")
        if not last_checked:
            return True

        try:
            checked_at = datetime.fromisoformat(last_checked)
            return datetime.now() - checked_at >= timedelta(hours=self.update_interval_hours)
        except Exception:
            return True

    def check_update_available(self) -> Dict:
        """检查远程是否存在可用更新，不修改本地文件。"""
        try:
            local_manifest = self._load_json_file(self.manifest_file, default={})
            remote_manifest = self._fetch_remote_manifest()
            valid, error = self._validate_manifest(remote_manifest)
            if not valid:
                return {"update_available": False, "error": error, "files_to_update": []}

            files_to_update = []
            skipped_files = []

            for filename, remote_info in remote_manifest.get("files", {}).items():
                if not self._is_safe_rule_path(filename):
                    skipped_files.append({"file": filename, "reason": "unsafe_path_or_extension"})
                    continue

                local_info = local_manifest.get("files", {}).get(filename, {})
                if (
                    local_info.get("version") != remote_info.get("version")
                    or local_info.get("sha256") != remote_info.get("sha256")
                ):
                    files_to_update.append(filename)

            return {
                "update_available": len(files_to_update) > 0,
                "files_to_update": files_to_update,
                "remote_version": remote_manifest.get("version", "unknown"),
                "local_version": local_manifest.get("version", "unknown"),
                "skipped_files": skipped_files,
            }
        except Exception as e:
            return {"update_available": False, "error": str(e), "files_to_update": []}

    def download_updates(self, progress_callback: Optional[Callable] = None) -> Dict:
        """下载并应用在线规则更新。"""
        try:
            update_info = self.check_update_available()
            if not update_info.get("update_available", False):
                self._touch_last_checked()
                return {
                    "success": True,
                    "updated_files": [],
                    "skipped_files": update_info.get("skipped_files", []),
                    "message": update_info.get("error") or "No updates available",
                }

            remote_manifest = self._fetch_remote_manifest()
            files_to_update = update_info.get("files_to_update", [])
            updated_files: List[str] = []
            failed_files: List[Dict] = []
            skipped_files: List[Dict] = update_info.get("skipped_files", [])

            print(f"⬇️ 开始下载更新，待更新文件数: {len(files_to_update)}")

            for index, filename in enumerate(files_to_update, start=1):
                if progress_callback:
                    progress_callback(index, len(files_to_update), filename)

                ok, reason = self._download_one_file(filename, remote_manifest)
                if ok:
                    updated_files.append(filename)
                    print(f"✅ 更新成功: {filename}")
                else:
                    failed_files.append({"file": filename, "reason": reason})
                    print(f"❌ 更新失败: {filename} | {reason}")

            if updated_files:
                self._merge_local_manifest(remote_manifest, updated_files)
                print(f"📦 本地 manifest 已同步，成功更新 {len(updated_files)} 个文件")
            else:
                self._touch_last_checked()
                print("💤 本轮无文件成功落盘，本地规则保持不变")

            return {
                "success": len(failed_files) == 0,
                "updated_files": updated_files,
                "failed_files": failed_files,
                "skipped_files": skipped_files,
                "remote_version": remote_manifest.get("version", "unknown"),
            }
        except Exception as e:
            return {"success": False, "message": str(e), "updated_files": []}

    def import_offline_package(self, package_path: str) -> Dict:
        """
        导入离线规则包。

        规则包格式：zip 文件，根目录必须包含 manifest.json，其他文件路径与 rules/ 下路径一致。
        该接口暂不绑定前端，但后续可直接接入“上传 Rule Package”。
        """
        package_path = os.path.abspath(package_path)
        if not os.path.exists(package_path):
            return {"success": False, "message": f"离线规则包不存在: {package_path}"}
        if not zipfile.is_zipfile(package_path):
            return {"success": False, "message": "离线规则包必须是 zip 格式"}

        updated_files: List[str] = []
        failed_files: List[Dict] = []

        try:
            with tempfile.TemporaryDirectory(prefix="seckeeper_rules_") as tmp_dir:
                with zipfile.ZipFile(package_path, "r") as zf:
                    failed_files.extend(self._safe_extract_offline_zip(zf, tmp_dir))

                manifest_path = os.path.join(tmp_dir, "manifest.json")
                remote_manifest = self._load_json_file(manifest_path, default={})
                valid, error = self._validate_manifest(remote_manifest)
                if not valid:
                    return {"success": False, "message": error, "updated_files": []}

                for filename, info in remote_manifest.get("files", {}).items():
                    if not self._is_safe_rule_path(filename):
                        failed_files.append({"file": filename, "reason": "unsafe_path_or_extension"})
                        continue

                    src = os.path.join(tmp_dir, filename)
                    if not os.path.exists(src):
                        failed_files.append({"file": filename, "reason": "missing_in_package"})
                        continue

                    expected_sha = info.get("sha256")
                    if expected_sha and not self._verify_checksum(src, expected_sha):
                        failed_files.append({"file": filename, "reason": "sha256_mismatch"})
                        continue

                    dst = self._safe_target_path(filename)
                    os.makedirs(os.path.dirname(dst), exist_ok=True)
                    shutil.copy2(src, dst)
                    updated_files.append(filename)

                if updated_files:
                    self._merge_local_manifest(remote_manifest, updated_files)
                else:
                    self._touch_last_checked()

            return {
                "success": len(failed_files) == 0,
                "updated_files": updated_files,
                "failed_files": failed_files,
                "message": "offline package imported",
            }
        except Exception as e:
            return {"success": False, "message": str(e), "updated_files": []}

    # ------------------------------------------------------------------
    # Download helpers
    # ------------------------------------------------------------------
    def _fetch_remote_manifest(self) -> Dict:
        response = requests.get(urljoin(self.remote_url, "manifest.json"), timeout=10)
        response.raise_for_status()
        return response.json()

    def _download_one_file(self, filename: str, remote_manifest: Dict) -> Tuple[bool, str]:
        """下载单个规则文件。失败只影响当前文件，不中断整批更新。"""
        tmp_path = None
        try:
            if not self._is_safe_rule_path(filename):
                return False, "unsafe_path_or_extension"

            expected_sha256 = remote_manifest.get("files", {}).get(filename, {}).get("sha256")
            if not expected_sha256:
                return False, "missing_sha256_in_manifest"

            target_path = self._safe_target_path(filename)
            os.makedirs(os.path.dirname(target_path), exist_ok=True)

            response = requests.get(urljoin(self.remote_url, filename), timeout=20)
            response.raise_for_status()

            fd, tmp_path = tempfile.mkstemp(prefix=".rule_", suffix=".tmp", dir=os.path.dirname(target_path))
            with os.fdopen(fd, "wb") as f:
                f.write(response.content)

            if not self._verify_checksum(tmp_path, expected_sha256):
                return False, "sha256_mismatch"

            os.replace(tmp_path, target_path)
            tmp_path = None
            return True, "ok"
        except Exception as e:
            return False, str(e)
        finally:
            if tmp_path and os.path.exists(tmp_path):
                os.remove(tmp_path)


    def _safe_extract_offline_zip(self, zf: zipfile.ZipFile, tmp_dir: str) -> List[Dict]:
        """安全解压离线规则包，禁止路径穿越。"""
        failed_files: List[Dict] = []
        tmp_root = os.path.abspath(tmp_dir) + os.sep

        for member in zf.infolist():
            raw_name = member.filename
            normalized = raw_name.replace("\\", "/").lstrip("/")

            if member.is_dir():
                continue

            if normalized == "manifest.json":
                target_path = os.path.abspath(os.path.join(tmp_dir, "manifest.json"))
            elif self._is_safe_rule_path(normalized):
                target_path = os.path.abspath(os.path.join(tmp_dir, normalized))
            else:
                failed_files.append({"file": raw_name, "reason": "unsafe_path_or_extension"})
                continue

            if not target_path.startswith(tmp_root):
                failed_files.append({"file": raw_name, "reason": "path_traversal"})
                continue

            os.makedirs(os.path.dirname(target_path), exist_ok=True)
            with zf.open(member, "r") as src, open(target_path, "wb") as dst:
                shutil.copyfileobj(src, dst)

        return failed_files

    # ------------------------------------------------------------------
    # Manifest helpers
    # ------------------------------------------------------------------
    def _validate_manifest(self, manifest: Dict) -> Tuple[bool, str]:
        if not isinstance(manifest, dict):
            return False, "manifest must be a JSON object"
        if not isinstance(manifest.get("files"), dict):
            return False, "manifest.files must be an object"

        for filename, info in manifest.get("files", {}).items():
            if not isinstance(filename, str):
                return False, "manifest file name must be string"
            if not self._is_safe_rule_path(filename):
                return False, f"unsafe file path in manifest: {filename}"
            if not isinstance(info, dict):
                return False, f"manifest info must be object: {filename}"
            sha = info.get("sha256")
            if not sha or not isinstance(sha, str) or len(sha) != 64:
                return False, f"invalid sha256 for {filename}"
        return True, "ok"

    def _merge_local_manifest(self, remote_manifest: Dict, updated_files: Iterable[str]) -> None:
        local_manifest = self._load_json_file(self.manifest_file, default={})
        local_manifest.setdefault("files", {})

        for filename in updated_files:
            local_manifest["files"][filename] = remote_manifest["files"][filename]

        local_manifest["version"] = remote_manifest.get("version", local_manifest.get("version", "1.0.0"))
        local_manifest["last_updated"] = datetime.now().strftime("%Y-%m-%d")
        local_manifest["last_checked"] = datetime.now().isoformat(timespec="seconds")
        local_manifest["update_url"] = self.remote_url

        os.makedirs(os.path.dirname(self.manifest_file), exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(prefix=".manifest_", suffix=".tmp", dir=os.path.dirname(self.manifest_file))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(local_manifest, f, indent=4, ensure_ascii=False)
            os.replace(tmp_path, self.manifest_file)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def _touch_last_checked(self) -> None:
        manifest = self._load_json_file(self.manifest_file, default={})
        manifest.setdefault("files", {})
        manifest["last_checked"] = datetime.now().isoformat(timespec="seconds")
        os.makedirs(os.path.dirname(self.manifest_file), exist_ok=True)
        with open(self.manifest_file, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=4, ensure_ascii=False)

    # ------------------------------------------------------------------
    # Path and checksum helpers
    # ------------------------------------------------------------------
    def _is_safe_rule_path(self, filename: str) -> bool:
        if not filename or not isinstance(filename, str):
            return False
        normalized = filename.replace("\\", "/")
        if normalized.startswith("/") or ".." in normalized.split("/"):
            return False
        if normalized == "manifest.json":
            return False
        return normalized.endswith(self.allowed_extensions)

    def _safe_target_path(self, filename: str) -> str:
        target_path = os.path.abspath(os.path.join(self.rules_dir, filename))
        rules_root = self.rules_dir + os.sep
        if not (target_path + os.sep).startswith(rules_root) and not target_path.startswith(rules_root):
            raise ValueError(f"Unsafe rule path: {filename}")
        return target_path

    def _verify_checksum(self, file_path: str, expected_sha256: str) -> bool:
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest().lower() == expected_sha256.lower()


    @staticmethod
    def _read_manifest_update_url(manifest_file: str) -> Optional[str]:
        """从本地 manifest 读取规则仓库地址，便于匹配自维护 GitHub 规则库。"""
        try:
            if not os.path.exists(manifest_file):
                return None
            with open(manifest_file, "r", encoding="utf-8") as f:
                manifest = json.load(f)
            update_url = manifest.get("update_url")
            return update_url if isinstance(update_url, str) and update_url.strip() else None
        except Exception:
            return None

    @staticmethod
    def _load_json_file(file_path: str, default):
        try:
            if not os.path.exists(file_path):
                return default
            with open(file_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return default


if __name__ == "__main__":
    updater = RuleUpdater()
    print(updater.download_updates())
