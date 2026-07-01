#!/usr/bin/env python3
"""
真实资产扫描模块 - 完整生产版本
扫描系统软件、服务、网络配置和系统信息
"""

import os
import platform
import socket
import subprocess
import json
import re
import psutil
import uuid
import shlex
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple


# 资产名称规范化说明：
# CveDetector 中维护了信创/国产发行版包名到 NVD 软件名的映射。
# 资产扫描模块只“复用映射结果”，不迁移漏洞匹配逻辑，避免两套规则漂移。
_FALLBACK_ALIAS_MAP = {
    "openssl": ["openssl", "libssl3", "libssl3t64", "libssl1.1", "libssl-dev"],
    "openssh": ["openssh-server", "openssh-client", "openssh-sftp-server", "libssh2-1", "libssh-4"],
    "glibc": ["libc6", "libc6-dev", "libc-bin", "glibc"],
    "curl": ["curl", "libcurl4", "libcurl4t64", "libcurl3", "libcurl4-openssl-dev"],
    "nginx": ["nginx", "nginx-core", "nginx-full", "nginx-common"],
    "apache2": ["apache2", "apache2-bin", "apache2-utils"],
    "mysql": ["mysql-server", "mysql-client", "mysql-common", "mariadb-server", "mariadb-client"],
    "postgresql": ["postgresql", "postgresql-common", "postgresql-client", "libpq5"],
    "sudo": ["sudo", "sudo-ldap"],
    "systemd": ["systemd", "libsystemd0", "systemd-sysv", "udev"],
    "polkit": ["polkit", "policykit-1", "libpolkit-agent-1-0", "libpolkit-gobject-1-0"],
    "python": ["python3", "python3-minimal", "python3-dev", "python2.7"],
    "bash": ["bash"],
    "dbus": ["dbus", "libdbus-1-3"],
    "pam": ["libpam0g", "libpam-modules", "libpam-runtime"],
    "docker": ["docker.io", "docker-ce", "docker-ce-cli", "docker-compose", "docker-compose-plugin"],
    "containerd": ["containerd", "containerd.io"],
    "runc": ["runc"],
}

_XINCHUANG_KEYWORDS = [
    "kylin", "麒麟", "uos", "统信", "deepin", "openEuler", "openeuler",
    "anolis", "龙蜥", "loongnix", "loongarch", "兆芯", "飞腾", "鲲鹏", "海光"
]

class RealAssetScanner:
    """真实资产扫描器 - 生产环境实现"""

    COMMAND_TIMEOUT = 30

    @staticmethod
    def _run_command(cmd: List[str], timeout: int = None) -> Tuple[int, str, str]:
        """统一执行外部命令，避免各扫描函数重复处理 subprocess 异常。"""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout or RealAssetScanner.COMMAND_TIMEOUT
            )
            return result.returncode, result.stdout or "", result.stderr or ""
        except FileNotFoundError:
            return 127, "", f"command not found: {cmd[0]}"
        except subprocess.TimeoutExpired:
            return 124, "", f"command timeout: {' '.join(cmd)}"
        except Exception as e:
            return 1, "", str(e)

    @staticmethod
    def _load_cve_alias_reverse_map() -> Dict[str, str]:
        """复用 CveDetector 的包名映射；失败时使用轻量兜底映射。"""
        try:
            try:
                from core.detectors.cve_detector import PACKAGE_ALIAS_MAP
            except Exception:
                from detectors.cve_detector import PACKAGE_ALIAS_MAP
            alias_map = PACKAGE_ALIAS_MAP
        except Exception:
            alias_map = _FALLBACK_ALIAS_MAP

        reverse = {}
        for normalized_name, names in alias_map.items():
            reverse.setdefault(normalized_name.lower(), normalized_name.lower())
            for name in names:
                reverse.setdefault(str(name).lower(), normalized_name.lower())
        return reverse

    @staticmethod
    def _normalize_security_name(package_name: str) -> Optional[str]:
        """将系统包名规范化为 CVE/NVD 维度的软件名，仅用于资产展示对齐。"""
        if not package_name:
            return None

        name = str(package_name).lower().strip()
        reverse = RealAssetScanner._load_cve_alias_reverse_map()

        if name in reverse:
            return reverse[name]

        stripped = re.sub(r'[\d]+t?\d*$', '', name).rstrip('-')
        if stripped in reverse:
            return reverse[stripped]

        base = re.sub(
            r'-(dev|common|bin|doc|utils|client|server|core|minimal|full|extras|light|static|dbg|debug|modules|runtime|plugin|tools|headers|libs|data)$',
            '',
            name
        )
        if base in reverse:
            return reverse[base]

        return None

    @staticmethod
    def _enrich_software_entry(software: Dict[str, Any]) -> Dict[str, Any]:
        """补充资产规范化字段，不改变原始 name，保证前端兼容。"""
        raw_name = software.get("raw_name") or software.get("name", "")
        software["raw_name"] = raw_name

        security_name = RealAssetScanner._normalize_security_name(raw_name)
        if security_name:
            software["security_name"] = security_name
            software["normalized_name"] = security_name
            software["xinchuang_package_mapped"] = str(raw_name).lower() != security_name
        else:
            software.setdefault("security_name", software.get("name", "unknown"))
            software.setdefault("normalized_name", software.get("name", "unknown"))
            software["xinchuang_package_mapped"] = False

        return software

    @staticmethod
    def _get_linux_distribution_info() -> Dict[str, Any]:
        """读取 /etc/os-release，识别银河麒麟、统信 UOS、Deepin、openEuler 等信创环境。"""
        info = {
            "distribution": "Unknown",
            "distribution_version": "Unknown",
            "distribution_id": "unknown",
            "is_xinchuang_os": False,
            "xinchuang_keywords": []
        }

        if platform.system().lower() != "linux":
            return info

        try:
            os_release = "/etc/os-release"
            if not os.path.exists(os_release):
                return info

            data = {}
            with open(os_release, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or "=" not in line:
                        continue
                    key, value = line.split("=", 1)
                    data[key] = value.strip().strip('"')

            combined = " ".join(str(v) for v in data.values())
            matched = [kw for kw in _XINCHUANG_KEYWORDS if kw.lower() in combined.lower()]
            info.update({
                "distribution": data.get("PRETTY_NAME") or data.get("NAME") or "Unknown",
                "distribution_version": data.get("VERSION_ID") or data.get("VERSION") or "Unknown",
                "distribution_id": data.get("ID", "unknown"),
                "is_xinchuang_os": len(matched) > 0,
                "xinchuang_keywords": matched
            })
        except Exception as e:
            info["distribution_error"] = str(e)

        return info

    
    @staticmethod
    def scan_assets() -> Dict[str, Any]:
        """执行完整的资产扫描"""
        try:
            print("🔍 开始系统资产扫描...")
            
            assets = {
                "software": [],
                "services": [],
                "system_info": {},
                "network_info": [],
                "hardware_info": {},
                "scan_timestamp": datetime.now().isoformat(),
                "scan_id": f"asset_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            }
            
            # 并行扫描不同维度的资产信息
            assets["system_info"] = RealAssetScanner._get_detailed_system_info()
            assets["software"] = RealAssetScanner._scan_installed_software()
            assets["services"] = RealAssetScanner._scan_running_services()
            assets["network_info"] = RealAssetScanner._scan_network_info()
            assets["hardware_info"] = RealAssetScanner._scan_hardware_info()
            assets["summary"] = RealAssetScanner._generate_asset_summary(assets)
            assets["success"] = True
            
            print(f"✅ 资产扫描完成: {len(assets['software'])}软件, {len(assets['services'])}服务")
            return assets
            
        except Exception as e:
            print(f"❌ 资产扫描错误: {e}")
            return {
                "software": [],
                "services": [],
                "system_info": {},
                "network_info": [],
                "error": str(e),
                "scan_timestamp": datetime.now().isoformat()
            }
    
    @staticmethod
    def _get_detailed_system_info() -> Dict[str, Any]:
        """获取详细的系统信息"""
        try:
            # 获取基础系统信息
            system_info = {
                "hostname": socket.gethostname(),
                "fqdn": socket.getfqdn(),
                "os": platform.system(),
                "os_version": platform.version(),
                "platform": platform.platform(),
                "architecture": platform.architecture()[0],
                "machine": platform.machine(),
                "processor": platform.processor() or "Unknown",
                "cpu_count_physical": psutil.cpu_count(logical=False),
                "cpu_count_logical": psutil.cpu_count(logical=True),
                "total_memory_gb": round(psutil.virtual_memory().total / (1024**3), 2),
                "total_swap_gb": round(psutil.swap_memory().total / (1024**3), 2),
                "boot_time": datetime.fromtimestamp(psutil.boot_time()).isoformat(),
                "current_user": os.getenv('USER', 'Unknown'),
                "system_uptime": str(datetime.now() - datetime.fromtimestamp(psutil.boot_time())),
                "python_version": platform.python_version()
            }
            
            # 识别发行版与信创环境
            system_info.update(RealAssetScanner._get_linux_distribution_info())
            
            # 获取详细的CPU信息
            try:
                if platform.system().lower() == "linux":
                    with open('/proc/cpuinfo', 'r') as f:
                        cpu_info = f.read()
                        model_match = re.search(r'model name\s*:\s*(.+)', cpu_info)
                        if model_match:
                            system_info["cpu_model"] = model_match.group(1).strip()
                        
                        # 获取CPU频率
                        freq_match = re.search(r'cpu MHz\s*:\s*(.+)', cpu_info)
                        if freq_match:
                            system_info["cpu_frequency_mhz"] = float(freq_match.group(1).strip())
            except Exception:
                system_info["cpu_model"] = "Unknown"
            
            # 获取磁盘信息
            try:
                disk_info = []
                for partition in psutil.disk_partitions():
                    try:
                        usage = psutil.disk_usage(partition.mountpoint)
                        disk_info.append({
                            "device": partition.device,
                            "mountpoint": partition.mountpoint,
                            "fstype": partition.fstype,
                            "total_gb": round(usage.total / (1024**3), 2),
                            "used_gb": round(usage.used / (1024**3), 2),
                            "free_gb": round(usage.free / (1024**3), 2),
                            "percent_used": usage.percent
                        })
                    except PermissionError:
                        continue
                system_info["disks"] = disk_info
            except Exception as e:
                print(f"⚠️ 磁盘信息获取失败: {e}")
                system_info["disks"] = []
            
            return system_info
            
        except Exception as e:
            print(f"❌ 系统信息获取错误: {e}")
            return {"error": str(e)}
    
    @staticmethod
    def _scan_installed_software() -> List[Dict[str, Any]]:
        """扫描已安装的软件 - 多包管理器支持"""
        software_list = []
        
        try:
            # Linux系统软件包扫描
            if platform.system().lower() == "linux":
                software_list.extend(RealAssetScanner._scan_linux_packages())
            
            # 扫描Python包
            software_list.extend(RealAssetScanner._scan_python_packages())
            
            # 扫描Node.js包
            software_list.extend(RealAssetScanner._scan_node_packages())
            
            # 扫描Docker容器和镜像
            software_list.extend(RealAssetScanner._scan_docker_assets())
            
            # 扫描系统库
            software_list.extend(RealAssetScanner._scan_system_libraries())
            
            # 去重处理
            software_list = RealAssetScanner._deduplicate_software(software_list)
                
        except Exception as e:
            print(f"❌ 软件扫描错误: {e}")
        
        return software_list
    
    @staticmethod
    def _scan_linux_packages() -> List[Dict[str, Any]]:
        """扫描Linux系统软件包 - 多包管理器支持"""
        packages = []
        
        # dpkg (Debian/Ubuntu)
        try:
            rc, stdout, stderr = RealAssetScanner._run_command(
                ['dpkg-query', '-W', '-f=${Package} ${Version} ${Architecture}\n'], timeout=30
            )
            if rc == 0:
                for line in stdout.split('\n'):
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 2:
                            pkg_name = parts[0]
                            pkg_version = parts[1]
                            architecture = parts[2] if len(parts) > 2 else "unknown"
                            
                            packages.append({
                                "name": pkg_name,
                                "version": pkg_version,
                                "type": "system_package",
                                "package_manager": "dpkg",
                                "architecture": architecture,
                                "status": "installed"
                            })
        except Exception as e:
            print(f"⚠️ dpkg扫描失败: {e}")
        
        # rpm (RedHat/CentOS/Fedora)
        try:
            rc, stdout, stderr = RealAssetScanner._run_command(
                ['rpm', '-qa', '--queryformat', '%{NAME} %{VERSION}-%{RELEASE} %{ARCH}\n'], timeout=30
            )
            if rc == 0:
                for line in stdout.split('\n'):
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 2:
                            name = parts[0]
                            version_release = parts[1]
                            architecture = parts[2] if len(parts) > 2 else "unknown"
                            version = version_release.split('-')[0]
                            
                            packages.append({
                                "name": name,
                                "version": version,
                                "type": "system_package", 
                                "package_manager": "rpm",
                                "architecture": architecture,
                                "status": "installed"
                            })
        except Exception as e:
            print(f"⚠️ rpm扫描失败: {e}")
        
        # pacman (Arch Linux)
        try:
            rc, stdout, stderr = RealAssetScanner._run_command(['pacman', '-Q'], timeout=30)
            if rc == 0:
                for line in stdout.split('\n'):
                    if line.strip():
                        name, version = line.split()[:2]
                        packages.append({
                            "name": name,
                            "version": version,
                            "type": "system_package",
                            "package_manager": "pacman",
                            "status": "installed"
                        })
        except Exception as e:
            print(f"⚠️ pacman扫描失败: {e}")
        
        return packages
    
    @staticmethod
    def _scan_python_packages() -> List[Dict[str, Any]]:
        """扫描Python包 - 多环境支持"""
        packages = []
        
        # 尝试不同的Python包管理器
        pip_commands = [
            ['pip', 'list', '--format=json'],
            ['pip3', 'list', '--format=json'],
            ['python', '-m', 'pip', 'list', '--format=json'],
            ['python3', '-m', 'pip', 'list', '--format=json']
        ]
        
        for cmd in pip_commands:
            try:
                rc, stdout, stderr = RealAssetScanner._run_command(cmd, timeout=30)
                if rc == 0:
                    pip_packages = json.loads(stdout)
                    for pkg in pip_packages:
                        packages.append({
                            "name": pkg['name'],
                            "version": pkg['version'],
                            "type": "python_package",
                            "package_manager": cmd[0],
                            "status": "installed"
                        })
                    break  # 成功一个即可
            except Exception:
                continue
        
        return packages
    
    @staticmethod
    def _scan_node_packages() -> List[Dict[str, Any]]:
        """扫描Node.js包"""
        packages = []
        
        # 检查当前目录的package.json
        if os.path.exists('package.json'):
            try:
                with open('package.json', 'r') as f:
                    package_data = json.load(f)
                
                dependencies = {
                    **package_data.get('dependencies', {}), 
                    **package_data.get('devDependencies', {}),
                    **package_data.get('peerDependencies', {})
                }
                
                for name, version in dependencies.items():
                    clean_version = re.sub(r'[\^~]', '', version)
                    packages.append({
                        "name": name,
                        "version": clean_version,
                        "type": "node_package", 
                        "package_manager": "npm",
                        "status": "dependency"
                    })
            except Exception as e:
                print(f"⚠️ package.json解析失败: {e}")
        
        # 检查全局安装的npm包
        try:
            rc, stdout, stderr = RealAssetScanner._run_command(['npm', 'list', '-g', '--json', '--depth=0'], timeout=30)
            if rc == 0:
                npm_data = json.loads(stdout)
                deps = npm_data.get('dependencies', {})
                for name, info in deps.items():
                    if isinstance(info, dict):
                        version = info.get('version', 'unknown')
                        packages.append({
                            "name": name,
                            "version": version,
                            "type": "node_package",
                            "package_manager": "npm",
                            "status": "global_installed"
                        })
        except Exception as e:
            print(f"⚠️ 全局npm包扫描失败: {e}")
        
        return packages
    
    @staticmethod
    def _scan_docker_assets() -> List[Dict[str, Any]]:
        """扫描Docker容器和镜像"""
        packages = []
        
        # 扫描运行的Docker容器
        try:
            rc, stdout, stderr = RealAssetScanner._run_command(
                ['docker', 'ps', '--format', '{{.Names}} {{.Image}} {{.Status}}'], timeout=15
            )
            if rc == 0:
                for line in stdout.split('\n'):
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 2:
                            container_name = parts[0]
                            image = parts[1]
                            status = ' '.join(parts[2:]) if len(parts) > 2 else "running"
                            
                            # 解析镜像名称和版本
                            if ':' in image:
                                name, version = image.split(':', 1)
                            else:
                                name, version = image, 'latest'
                            
                            packages.append({
                                "name": name,
                                "version": version,
                                "container_name": container_name,
                                "type": "docker_container",
                                "package_manager": "docker",
                                "status": status
                            })
        except Exception as e:
            print(f"⚠️ Docker容器扫描失败: {e}")
        
        # 扫描Docker镜像
        try:
            rc, stdout, stderr = RealAssetScanner._run_command(
                ['docker', 'images', '--format', '{{.Repository}} {{.Tag}} {{.ID}}'], timeout=15
            )
            if rc == 0:
                for line in stdout.split('\n'):
                    if line.strip():
                        repository, tag, image_id = line.split()[:3]
                        packages.append({
                            "name": repository,
                            "version": tag,
                            "image_id": image_id[:12],
                            "type": "docker_image",
                            "package_manager": "docker",
                            "status": "available"
                        })
        except Exception as e:
            print(f"⚠️ Docker镜像扫描失败: {e}")
        
        return packages
    
    @staticmethod
    def _scan_system_libraries() -> List[Dict[str, Any]]:
        """扫描系统库文件"""
        libraries = []
        
        # 常见库文件路径
        lib_paths = [
            '/usr/lib',
            '/usr/lib64', 
            '/usr/pocs/lib',
            '/lib',
            '/lib64'
        ]
        
        try:
            for lib_path in lib_paths:
                if os.path.exists(lib_path):
                    # 这里可以扩展为实际扫描.so文件版本
                    libraries.append({
                        "name": f"system_libraries_{os.path.basename(lib_path)}",
                        "version": "system",
                        "type": "system_library",
                        "path": lib_path,
                        "status": "installed"
                    })
        except Exception as e:
            print(f"⚠️ 系统库扫描失败: {e}")
        
        return libraries
    
    @staticmethod
    def _scan_running_services() -> List[Dict[str, Any]]:
        """扫描运行的服务和进程"""
        services_list = []
        
        try:
            # 使用psutil获取运行进程
            for proc in psutil.process_iter(['pid', 'name', 'status', 'username', 'memory_info', 'cpu_times']):
                try:
                    process_info = proc.info
                    services_list.append({
                        "name": process_info['name'],
                        "pid": process_info['pid'],
                        "status": process_info['status'],
                        "user": process_info.get('username', 'Unknown'),
                        "memory_mb": round(process_info['memory_info'].rss / (1024*1024), 2) if process_info['memory_info'] else 0,
                        "type": "process"
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # 扫描网络服务端口
            services_list.extend(RealAssetScanner._scan_network_services())
            
            # 扫描系统服务 (systemd)
            services_list.extend(RealAssetScanner._scan_systemd_services())
            
        except Exception as e:
            print(f"❌ 服务扫描错误: {e}")
        
        return services_list[:50]  # 限制返回数量
    
    @staticmethod
    def _scan_network_services() -> List[Dict[str, Any]]:
        """扫描网络服务端口"""
        services = []
        
        try:
            # 检查常见服务端口
            common_ports = {
                22: "ssh", 80: "http", 443: "https", 21: "ftp", 25: "smtp",
                53: "dns", 3306: "mysql", 5432: "postgresql", 27017: "mongodb",
                6379: "redis", 8080: "http-proxy", 8443: "https-alt",
                9200: "elasticsearch", 9300: "elasticsearch-cluster",
                5601: "kibana", 5044: "logstash", 11211: "memcached"
            }
            
            for port, service_name in common_ports.items():
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex(('127.0.0.1', port))
                sock.close()
                
                if result == 0:
                    services.append({
                        "name": service_name,
                        "port": port,
                        "status": "listening",
                        "type": "network_service"
                    })
                    
        except Exception as e:
            print(f"⚠️ 网络服务扫描失败: {e}")
        
        return services
    
    @staticmethod
    def _scan_systemd_services() -> List[Dict[str, Any]]:
        """扫描systemd服务"""
        services = []
        
        try:
            # 扫描活动的systemd服务
            rc, stdout, stderr = RealAssetScanner._run_command(
                ['systemctl', 'list-units', '--type=service', '--state=running', '--no-legend'], timeout=10
            )
            if rc == 0:
                for line in stdout.split('\n'):
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 1:
                            service_name = parts[0]
                            services.append({
                                "name": service_name,
                                "status": "running",
                                "type": "systemd_service"
                            })
        except Exception as e:
            print(f"⚠️ systemd服务扫描失败: {e}")
        
        return services
    
    @staticmethod
    def _scan_network_info() -> List[Dict[str, Any]]:
        """扫描网络接口和配置信息"""
        network_info = []
        
        try:
            interfaces = psutil.net_if_addrs()
            stats = psutil.net_io_counters(pernic=True)
            
            for interface, addrs in interfaces.items():
                interface_info = {
                    "interface": interface,
                    "addresses": [],
                    "stats": {},
                    "status": "unknown"
                }
                
                for addr in addrs:
                    address_info = {
                        "family": str(addr.family),
                        "address": addr.address
                    }
                    
                    if addr.netmask:
                        address_info["netmask"] = addr.netmask
                    if addr.broadcast:
                        address_info["broadcast"] = addr.broadcast
                    
                    interface_info["addresses"].append(address_info)
                
                if interface in stats:
                    interface_info["stats"] = {
                        "bytes_sent": stats[interface].bytes_sent,
                        "bytes_recv": stats[interface].bytes_recv,
                        "packets_sent": stats[interface].packets_sent,
                        "packets_recv": stats[interface].packets_recv
                    }
                
                # 检查接口状态
                try:
                    addrs = psutil.net_if_stats()
                    if interface in addrs:
                        interface_info["status"] = "up" if addrs[interface].isup else "down"
                except Exception:
                    pass
                
                network_info.append(interface_info)
                
        except Exception as e:
            print(f"❌ 网络信息扫描错误: {e}")
        
        return network_info
    
    @staticmethod
    def _scan_hardware_info() -> Dict[str, Any]:
        """扫描硬件信息"""
        hardware_info = {}
        
        try:
            # CPU信息
            cpu_info = {
                "physical_cores": psutil.cpu_count(logical=False),
                "logical_cores": psutil.cpu_count(logical=True),
                "max_frequency_mhz": psutil.cpu_freq().max if psutil.cpu_freq() else "Unknown",
                "current_frequency_mhz": psutil.cpu_freq().current if psutil.cpu_freq() else "Unknown"
            }
            hardware_info["cpu"] = cpu_info
            
            # 内存信息
            memory = psutil.virtual_memory()
            swap = psutil.swap_memory()
            memory_info = {
                "total_gb": round(memory.total / (1024**3), 2),
                "available_gb": round(memory.available / (1024**3), 2),
                "used_gb": round(memory.used / (1024**3), 2),
                "percent_used": memory.percent,
                "swap_total_gb": round(swap.total / (1024**3), 2),
                "swap_used_gb": round(swap.used / (1024**3), 2),
                "swap_percent_used": swap.percent
            }
            hardware_info["memory"] = memory_info
            
            # 磁盘信息（已包含在system_info中，这里提供汇总）
            disk_io = psutil.disk_io_counters()
            if disk_io:
                hardware_info["disk_io"] = {
                    "read_mb": round(disk_io.read_bytes / (1024**2), 2),
                    "write_mb": round(disk_io.write_bytes / (1024**2), 2),
                    "read_count": disk_io.read_count,
                    "write_count": disk_io.write_count
                }
                
        except Exception as e:
            print(f"⚠️ 硬件信息扫描失败: {e}")
            hardware_info["error"] = str(e)
        
        return hardware_info
    
    @staticmethod
    def _deduplicate_software(software_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """软件去重处理，并补充与 CVE Detector 对齐的规范化字段。"""
        seen = set()
        deduplicated = []
        
        for software in software_list:
            if not isinstance(software, dict):
                continue

            software = RealAssetScanner._enrich_software_entry(software)
            name = str(software.get('name', 'unknown')).lower()
            version = str(software.get('version', 'unknown')).lower()
            package_manager = str(software.get('package_manager', '')).lower()
            software_type = str(software.get('type', '')).lower()

            # 基于名称、版本、来源和类型创建唯一标识
            identifier = f"{name}-{version}-{package_manager}-{software_type}"
            
            if identifier not in seen:
                seen.add(identifier)
                deduplicated.append(software)
        
        return deduplicated

    @staticmethod
    def _generate_asset_summary(assets: Dict[str, Any]) -> Dict[str, Any]:
        """生成资产摘要，供前端和报告直接使用。"""
        software = assets.get("software", []) if isinstance(assets, dict) else []
        services = assets.get("services", []) if isinstance(assets, dict) else []
        system_info = assets.get("system_info", {}) if isinstance(assets, dict) else {}

        mapped_count = sum(1 for item in software if isinstance(item, dict) and item.get("xinchuang_package_mapped"))
        network_service_count = sum(1 for item in services if isinstance(item, dict) and item.get("type") == "network_service")

        return {
            "software_count": len(software),
            "service_count": len(services),
            "network_service_count": network_service_count,
            "xinchuang_package_mapped_count": mapped_count,
            "is_xinchuang_os": bool(system_info.get("is_xinchuang_os", False)),
            "distribution": system_info.get("distribution", "Unknown")
        }
