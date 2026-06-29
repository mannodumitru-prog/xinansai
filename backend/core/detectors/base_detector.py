"""
BaseDetector 抽象基类

功能：
1. 提供统一的漏洞检测器接口
2. 自动加载规则文件
3. 提供统一漏洞结果格式
4. 规范所有检测器实现

"""

import os
import json
import logging
from datetime import datetime
from abc import ABC, abstractmethod
from typing import Dict, List, Any


# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)


class BaseDetector(ABC):
    """
    所有漏洞检测器的抽象基类
    """

    def __init__(self, rules_dir: str = "core/rules"):
        """
        初始化检测器

        Args:
            rules_dir (str): 规则文件目录
        """
        self.rules_dir = rules_dir
        self.rules = self.load_rules()

    @abstractmethod
    def detect(self) -> List[Dict]:
        """
        执行漏洞检测

        Returns:
            List[Dict]: 漏洞结果列表
        """
        pass

    @abstractmethod
    def get_detector_name(self) -> str:
        """
        获取检测器名称

        Returns:
            str: 检测器名称
        """
        pass

    @abstractmethod
    def get_rule_file(self) -> str:
        """
        获取规则文件名

        Returns:
            str: 规则文件名
        """
        pass

    def load_rules(self) -> Dict:
        """
        加载规则文件

        Returns:
            Dict: 规则内容
        """
        try:
            rule_file = self.get_rule_file()
            rule_path = os.path.join(self.rules_dir, rule_file)

            if not os.path.exists(rule_path):
                print(f"[ERROR] Rule file not found: {rule_path}")
                return {}

            with open(rule_path, "r", encoding="utf-8") as f:
                rules = json.load(f)

            logging.info(f"Rules loaded successfully: {rule_path}")
            return rules

        except Exception as e:
            print(f"[ERROR] Failed to load rules: {e}")
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
        """
        格式化漏洞结果

        Args:
            vuln_id (str): 漏洞ID
            title (str): 漏洞标题
            severity (str): 漏洞等级
            category (str): 漏洞分类
            description (str): 漏洞描述
            affected_target (str): 受影响目标
            remediation (str): 修复建议
            **kwargs: 额外字段

        Returns:
            Dict: 统一格式漏洞字典
        """
        try:
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

            # 添加额外字段
            vulnerability.update(kwargs)

            return vulnerability

        except Exception as e:
            print(f"[ERROR] Failed to format vulnerability: {e}")
            return {}


# 在文件末尾临时加测试代码
if __name__ == "__main__":
    # 测试能否被继承
    class TestDetector(BaseDetector):
        def detect(self): return []

        def get_detector_name(self): return "test"

        def get_rule_file(self): return "test_rules.json"


    t = TestDetector()
    print("✅ base_detector 可用")