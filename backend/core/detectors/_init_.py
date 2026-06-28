import pkgutil
import importlib
import os

# 自动发现当前目录下的所有 detector 子模块
package_dir = os.path.dirname(__file__)
for _, module_name, _ in pkgutil.iter_modules([package_dir]):
    # 动态导入模块 (例如: importlib.import_module('.cve_detector', package=__name__))
    importlib.import_module(f'.{module_name}', package=__name__)

# 定义一个自动导出所有检测器类的机制
from .base_detector import BaseDetector

# 自动将所有包含 "Detector" 字眼的类暴露给外部
__all__ = []
for name in dir():
    if "Detector" in name and name != "BaseDetector":
        __all__.append(name)
