#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
调试SM2签名验证问题
"""

import sys
import os

# 添加src目录到路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from sm2_basic import SM2 as BasicSM2
from sm2_optimized import OptimizedSM2

def debug_verification():
    print("=== 调试SM2签名验证 ===")
    
    # 创建基础和优化版本实例
    basic_sm2 = BasicSM2()
    opt_sm2 = OptimizedSM2()
    
    # 生成相同的密钥对（使用固定种子）
    import random
    random.seed(42)
    private_key, public_key = basic_sm2.generate_keypair()
    
    print(f"私钥: {hex(private_key)}")
    print(f"公钥: ({hex(public_key.x)}, {hex(public_key.y)})")
    
    # 测试消息
    message = b"Test message"
    print(f"消息: {message}")
    
    # 基础版本签名
    print("\n--- 基础版本签名 ---")
    random.seed(42)
    signature_basic = basic_sm2.sign(message, private_key)
    print(f"基础签名: r={hex(signature_basic[0])}, s={hex(signature_basic[1])}")
    
    # 基础版本验证
    result_basic = basic_sm2.verify(message, signature_basic, public_key)
    print(f"基础版本验证: {result_basic}")
    
    # 优化版本验证同一个签名
    result_opt = opt_sm2.verify_optimized(message, signature_basic, public_key)
    print(f"优化版本验证: {result_opt}")
    
    # 检查哈希值是否相同
    print("\n--- 哈希值比较 ---")
    hash_basic = basic_sm2._hash_message(message, public_key)
    hash_opt = opt_sm2._hash_message(message, public_key)
    print(f"基础哈希: {hex(hash_basic)}")
    print(f"优化哈希: {hex(hash_opt)}")
    print(f"哈希相同: {hash_basic == hash_opt}")
    
    # 验证算法步骤
    print("\n--- 验证算法步骤 ---")
    r, s = signature_basic
    e = hash_basic
    t = (r + s) % basic_sm2.curve.n
    print(f"r = {hex(r)}")
    print(f"s = {hex(s)}")
    print(f"e = {hex(e)}")
    print(f"t = {hex(t)}")
    
    # 基础版本点运算
    point1_basic = basic_sm2.curve.point_multiply(s, basic_sm2.curve.G)
    point2_basic = basic_sm2.curve.point_multiply(t, public_key)
    point_basic = basic_sm2.curve.point_add(point1_basic, point2_basic)
    R_basic = (e + point_basic.x) % basic_sm2.curve.n
    
    print(f"基础版本 sG: ({hex(point1_basic.x)}, {hex(point1_basic.y)})")
    print(f"基础版本 tP: ({hex(point2_basic.x)}, {hex(point2_basic.y)})")
    print(f"基础版本 sG+tP: ({hex(point_basic.x)}, {hex(point_basic.y)})")
    print(f"基础版本 R: {hex(R_basic)}")
    print(f"基础版本验证: {R_basic == r}")
    
    # 优化版本点运算
    point1_opt = opt_sm2.curve.point_multiply_basic(s, opt_sm2.curve.G)
    point2_opt = opt_sm2.curve.point_multiply_basic(t, public_key)
    point_opt = opt_sm2.curve.point_add(point1_opt, point2_opt)
    R_opt = (e + point_opt.x) % opt_sm2.curve.n
    
    print(f"优化版本 sG: ({hex(point1_opt.x)}, {hex(point1_opt.y)})")
    print(f"优化版本 tP: ({hex(point2_opt.x)}, {hex(point2_opt.y)})")
    print(f"优化版本 sG+tP: ({hex(point_opt.x)}, {hex(point_opt.y)})")
    print(f"优化版本 R: {hex(R_opt)}")
    print(f"优化版本验证: {R_opt == r}")

if __name__ == "__main__":
    debug_verification()
