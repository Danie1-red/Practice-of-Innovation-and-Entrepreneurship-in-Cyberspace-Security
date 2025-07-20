#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SM2算法演示主程序

用法:
    python main.py basic    # 运行基础实现测试
    python main.py opt      # 运行优化实现测试  
    python main.py attack   # 运行攻击验证演示（🆕 重要功能）
    python main.py nakamoto # 运行中本聪数字签名演示（🆕 新功能）
    python main.py compare  # 运行性能对比
    python main.py all      # 运行所有测试
    python main.py help     # 显示帮助信息
"""

import sys
import os

# 添加src目录到路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

def run_basic_test():
    """运行基础实现测试"""
    print("=" * 50)
    print("运行SM2基础实现测试")
    print("=" * 50)
    from sm2_basic import test_sm2_basic
    test_sm2_basic()

def run_optimized_test():
    """运行优化实现测试"""
    print("=" * 50)
    print("运行SM2优化实现测试")
    print("=" * 50)
    from sm2_optimized import test_optimization_features, benchmark_comparison
    test_optimization_features()
    print()
    benchmark_comparison()

def run_nakamoto_signature():
    """运行中本聪数字签名演示"""
    print("=" * 50)
    print("运行中本聪数字签名演示")
    print("=" * 50)
    print("🔐 基于ECDSA-secp256k1的比特币风格数字签名")
    print("⚠️  包含签名伪造攻击演示，仅用于安全教育")
    print()
    
    try:
        from nakamoto_signature import run_nakamoto_demo, test_nakamoto_signature
        
        # 先运行测试确保实现正确
        print("--- 运行功能测试 ---")
        test_nakamoto_signature()
        
        print("\n--- 运行演示程序 ---")
        demo_result, attack_result = run_nakamoto_demo()
        
        print("\n" + "=" * 80)
        print("中本聪数字签名演示完成")
        print("=" * 80)
        print(f"✅ 签名验证: {'通过' if demo_result['verification_result'] else '失败'}")
        print(f"✅ 攻击演示: {'成功' if attack_result['attack_success'] else '失败'}")
        print("📚 学习要点:")
        print("  • ECDSA-secp256k1是比特币的核心签名算法")
        print("  • DER编码是比特币签名的标准格式")
        print("  • 随机数k重用会导致私钥泄露")
        print("  • 实际应用中必须使用安全的随机数生成")
        
    except ImportError as e:
        print(f"❌ 无法导入中本聪签名模块: {e}")
        print("请确保 nakamoto_signature.py 文件存在")
    except Exception as e:
        print(f"❌ 运行过程中发生错误: {e}")
        import traceback
        traceback.print_exc()

def run_attack_verification():
    """运行攻击验证演示"""
    print("=" * 50)
    print("运行SM2攻击验证演示")
    print("=" * 50)
    print("🆕 SM2签名算法误用攻击POC验证")
    print("⚠️  仅用于安全教育和研究目的")
    print()
    
    try:
        from sm2_attack_poc import run_all_attacks
        run_all_attacks()
    except ImportError:
        print("❌ 无法导入攻击验证模块")
        print("请确保 sm2_attack_poc.py 文件存在")

def run_comparison():
    """运行性能对比"""
    print("=" * 50)
    print("运行性能对比测试")
    print("=" * 50)
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'examples'))
    from demo import performance_comparison
    performance_comparison()

def show_help():
    """显示帮助信息"""
    print(__doc__)

def main():
    """主函数"""
    if len(sys.argv) < 2:
        show_help()
        return
    
    command = sys.argv[1].lower()
    
    try:
        if command == "basic":
            run_basic_test()
        elif command == "opt" or command == "optimized":
            run_optimized_test()
        elif command == "attack" or command == "poc":
            run_attack_verification()
        elif command == "nakamoto" or command == "bitcoin":
            run_nakamoto_signature()
        elif command == "compare" or command == "comparison":
            run_comparison()
        elif command == "all":
            run_basic_test()
            print("\n")
            run_optimized_test()
            print("\n")
            run_attack_verification()
            print("\n")
            run_nakamoto_signature()
            print("\n")
            run_comparison()
        elif command == "help" or command == "-h" or command == "--help":
            show_help()
        else:
            print(f"未知命令: {command}")
            show_help()
    except Exception as e:
        print(f"执行过程中发生错误: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
