"""
BaseDetector 抽象基类 - 工业级重构版
功能：
1. 统一接口：强制所有检测器遵循同样的 detect 流程。
2. 自动寻址：基于文件绝对路径自动定位 rules 目录，消除路径陷阱。
3. 健壮性：内置自动检查规则库健康度。
"""

import os
import json
import logging
from abc import ABC, abstractmethod
from typing import Dict, List, Any
from datetime import datetime

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

class BaseDetector(ABC):
    """所有漏洞检测器的抽象基类"""

    def __init__(self, rules_dir: str = None):
        """
        初始化检测器，自动定位规则库目录
        """
        if rules_dir is None:
            # 自动寻址：无论子类在哪，都向上回溯寻找 rules 目录
            # 假设结构为 backend/core/rules/ 和 backend/core/detectors/
            current_dir = os.path.dirname(os.path.abspath(__file__))
            self.rules_dir = os.path.abspath(os.path.join(current_dir, "..", "rules"))
        else:
            self.rules_dir = rules_dir
        
        self.rules = self.load_rules()

    @abstractmethod
    def detect(self) -> List[Dict]:
        """执行漏洞检测 (强制子类实现)"""
        pass

    @abstractmethod
    def get_detector_name(self) -> str:
        """获取检测器名称 (强制子类实现)"""
        pass

    @abstractmethod
    def get_rule_file(self) -> str:
        """获取对应的 JSON 规则文件名 (强制子类实现)"""
        pass

    def load_rules(self) -> Dict:
        """加载并校验规则文件"""
        rule_file = self.get_rule_file()
        rule_path = os.path.join(self.rules_dir, rule_file)

        if not os.path.exists(rule_path):
            logging.error(f"Rule file not found: {rule_path}")
            return {}

        try:
            with open(rule_path, "r", encoding="utf-8") as f:
                rules_data = json.load(f)
            
            # 简单检查数据结构
            if "rules" not in rules_data:
                logging.warning(f"Warning: {rule_file} seems to be empty or missing 'rules' key.")
            
            logging.info(f"Successfully loaded {rule_file} from {self.rules_dir}")
            return rules_data
        except Exception as e:
            logging.error(f"Failed to parse {rule_file}: {e}")
            return {}

    def format_vulnerability(
        self,
        vuln_id: str,
        title: str,
        severity: str,
        category: str,
        description: str,
        affected_target: str,
        remediation: str,
        **kwargs
    ) -> Dict:
        """统一漏洞结果格式"""
        vulnerability = {
            "vuln_id": vuln_id,
            "title": title,
            "severity": severity,
            "category": category,
            "description": description,
            "affected_target": affected_target,
            "remediation": remediation,
            "detector_name": self.get_detector_name(),
            "detected_at": datetime.now().isoformat()
        }
        vulnerability.update(kwargs)
        return vulnerability
