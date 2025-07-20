#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SM2椭圆曲线数字签名算法包

本包提供了SM2算法的完整技术体系：基础实现、优化实现和攻击验证。

模块:
    sm2_basic: SM2算法基础实现
    sm2_optimized: SM2算法优化实现
    sm2_attack_poc: SM2攻击POC验证（🆕 核心模块）
"""

from .sm2_basic import SM2 as BasicSM2
from .sm2_optimized import OptimizedSM2
from .sm2_attack_poc import SM2AttackPOC

__version__ = "2.0.0"
__author__ = "Project5 Team"
__all__ = ["BasicSM2", "OptimizedSM2", "SM2AttackPOC"]
