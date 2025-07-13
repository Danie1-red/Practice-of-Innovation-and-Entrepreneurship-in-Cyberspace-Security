#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SM2椭圆曲线数字签名算法包

本包提供了SM2算法的基础实现和优化实现。

模块:
    sm2_basic: SM2算法基础实现
    sm2_optimized: SM2算法优化实现
"""

from .sm2_basic import SM2 as BasicSM2
from .sm2_optimized import OptimizedSM2

__version__ = "1.0.0"
__author__ = "Project5 Team"
__all__ = ["BasicSM2", "OptimizedSM2"]
