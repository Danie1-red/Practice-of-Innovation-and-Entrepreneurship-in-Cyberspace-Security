#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SM2椭圆曲线数字签名算法实现包

包含以下模块:
- sm2_basic: SM2基础实现
- sm2_optimized: SM2优化实现  
- sm2_attack_poc: SM2攻击POC验证
- nakamoto_signature: 中本聪数字签名实现 (🆕)

版本: 2.1.0 - 添加中本聪数字签名
"""

__version__ = "2.1.0"
__author__ = "SM2 Project Team"

# 导入主要类和函数
from .sm2_basic import BasicSM2
from .sm2_optimized import OptimizedSM2
from .sm2_attack_poc import SM2AttackPOC
from .nakamoto_signature import NakamotoSignature

# 导出的公共接口
__all__ = [
    'BasicSM2',
    'OptimizedSM2', 
    'SM2AttackPOC',
    'NakamotoSignature',
    '__version__'
]

from .sm2_basic import SM2 as BasicSM2
from .sm2_optimized import OptimizedSM2
from .sm2_attack_poc import SM2AttackPOC

__version__ = "2.0.0"
__author__ = "Project5 Team"
__all__ = ["BasicSM2", "OptimizedSM2", "SM2AttackPOC"]
