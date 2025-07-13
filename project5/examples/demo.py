#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SM2算法基础版本与优化版本性能对比演示
"""

import sys
import os
import time
import random

# 添加src目录到路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from sm2_basic import SM2 as BasicSM2
from sm2_optimized import OptimizedSM2

def performance_comparison():
    """基础版本与优化版本性能对比"""
    print("=" * 60)
    print("SM2算法性能对比测试")
    print("=" * 60)
    
    # 创建实例
    basic_sm2 = BasicSM2()
    opt_sm2 = OptimizedSM2()
    
    # 生成测试数据
    print("1. 生成测试数据...")
    random.seed(42)
    private_key, public_key = basic_sm2.generate_keypair()
    
    messages = [
        b"Short message",
        b"Medium length message for testing SM2 algorithm performance",
        b"This is a longer message that will be used to test the SM2 digital signature algorithm implementation. It contains more text to simulate real-world usage scenarios where messages of varying lengths need to be signed and verified."
    ]
    
    print(f"测试消息数量: {len(messages)}")
    print(f"私钥长度: {private_key.bit_length()} bits")
    print(f"公钥在曲线上: {basic_sm2.curve.is_on_curve(public_key)}")
    
    print("\n" + "=" * 60)
    print("2. 签名性能测试")
    print("=" * 60)
    
    # 签名性能对比
    basic_times = []
    opt_times = []
    signatures = []
    
    for i, message in enumerate(messages):
        print(f"\n消息 {i+1}: {len(message)} bytes")
        
        # 基础版本签名
        random.seed(42 + i)  # 确保可重现
        start_time = time.time()
        signature_basic = basic_sm2.sign(message, private_key)
        basic_time = time.time() - start_time
        basic_times.append(basic_time)
        signatures.append(signature_basic)
        
        # 优化版本签名
        random.seed(42 + i)  # 确保可重现
        start_time = time.time()
        signature_opt = opt_sm2.sign(message, private_key)
        opt_time = time.time() - start_time
        opt_times.append(opt_time)
        
        print(f"  基础版本签名时间: {basic_time:.4f}秒")
        print(f"  优化版本签名时间: {opt_time:.4f}秒")
        print(f"  性能提升: {(basic_time/opt_time):.2f}x" if opt_time > 0 else "N/A")
        print(f"  签名匹配: {'是' if signature_basic == signature_opt else '否'}")
    
    print(f"\n平均签名时间:")
    print(f"  基础版本: {sum(basic_times)/len(basic_times):.4f}秒")
    print(f"  优化版本: {sum(opt_times)/len(opt_times):.4f}秒")
    print(f"  总体提升: {(sum(basic_times)/sum(opt_times)):.2f}x")
    
    print("\n" + "=" * 60)
    print("3. 验证性能测试")
    print("=" * 60)
    
    # 验证性能对比
    basic_verify_times = []
    opt_verify_times = []
    
    for i, (message, signature) in enumerate(zip(messages, signatures)):
        print(f"\n消息 {i+1}验证:")
        
        # 基础版本验证
        start_time = time.time()
        result_basic = basic_sm2.verify(message, signature, public_key)
        basic_verify_time = time.time() - start_time
        basic_verify_times.append(basic_verify_time)
        
        # 优化版本验证
        start_time = time.time()
        result_opt = opt_sm2.verify_optimized(message, signature, public_key)
        opt_verify_time = time.time() - start_time
        opt_verify_times.append(opt_verify_time)
        
        print(f"  基础版本验证时间: {basic_verify_time:.4f}秒 (结果: {'通过' if result_basic else '失败'})")
        print(f"  优化版本验证时间: {opt_verify_time:.4f}秒 (结果: {'通过' if result_opt else '失败'})")
        print(f"  性能提升: {(basic_verify_time/opt_verify_time):.2f}x" if opt_verify_time > 0 else "N/A")
    
    print(f"\n平均验证时间:")
    print(f"  基础版本: {sum(basic_verify_times)/len(basic_verify_times):.4f}秒")
    print(f"  优化版本: {sum(opt_verify_times)/len(opt_verify_times):.4f}秒")
    print(f"  总体提升: {(sum(basic_verify_times)/sum(opt_verify_times)):.2f}x")
    
    print("\n" + "=" * 60)
    print("4. 优化技术展示")
    print("=" * 60)
    
    # NAF编码测试
    print("\nNAF编码优化:")
    test_scalars = [123, 456, 789, 0xABCDEF]
    for scalar in test_scalars:
        from sm2_optimized import NAFEncoder
        naf = NAFEncoder.naf_encode(scalar, w=4)
        hamming_weight = sum(1 for x in naf if x != 0)
        print(f"  标量 {scalar}: NAF长度={len(naf)}, 汉明重量={hamming_weight}")
    
    # 预计算表性能
    print("\n预计算表优化:")
    k = random.randint(1, opt_sm2.curve.n - 1)
    
    # 基础点乘
    start_time = time.time()
    result1 = opt_sm2.curve.point_multiply_basic(k, opt_sm2.curve.G)
    basic_mult_time = time.time() - start_time
    
    # 预计算表点乘
    start_time = time.time()
    result2 = opt_sm2.curve.point_multiply_fixed(k)
    precomp_mult_time = time.time() - start_time
    
    print(f"  基础点乘时间: {basic_mult_time:.4f}秒")
    print(f"  预计算表点乘时间: {precomp_mult_time:.4f}秒")
    print(f"  结果匹配: {'是' if result1 == result2 else '否'}")
    print(f"  性能提升: {(basic_mult_time/precomp_mult_time):.2f}x" if precomp_mult_time > 0 else "N/A")
    
    print("\n" + "=" * 60)
    print("5. 总结")
    print("=" * 60)
    print("实现的优化技术:")
    print("✓ NAF编码 - 减少点加操作次数")
    print("✓ 预计算表 - 加速固定基点乘法")
    print("✓ 窗口方法 - 优化标量乘法")
    print("✓ 模算术优化 - 使用更高效的模运算")
    print("✓ 坐标系统优化 - 支持雅可比坐标（框架）")
    
    total_basic_time = sum(basic_times) + sum(basic_verify_times)
    total_opt_time = sum(opt_times) + sum(opt_verify_times)
    
    print(f"\n总体性能提升:")
    print(f"  签名+验证总时间提升: {(total_basic_time/total_opt_time):.2f}x")
    print(f"  内存使用: 预计算表占用额外空间，换取时间性能")
    print(f"  安全性: 保持与基础实现相同的安全级别")

def main():
    """主函数"""
    try:
        performance_comparison()
    except KeyboardInterrupt:
        print("\n\n测试被用户中断")
    except Exception as e:
        print(f"\n\n测试过程中发生错误: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
