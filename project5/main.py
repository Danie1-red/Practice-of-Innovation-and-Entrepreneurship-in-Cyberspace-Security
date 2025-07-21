#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SM2算法演示主程序

用法:
    python main.py basic         # 运行基础实现测试
    python main.py opt           # 运行优化实现测试  
    python main.py attack        # 运行攻击验证演示（🆕 重要功能）
    python main.py nakamoto      # 运行中本聪数字签名演示（🆕 新功能）
    python main.py forge_nakamoto # 🔐 完整伪造演示（8场景+高级分析+教育指南）
    python main.py compare       # 运行性能对比
    python main.py all           # 运行所有测试
    python main.py help          # 显示帮助信息

🔐 中本聪签名伪造演示功能：
    • 场景1：模拟创建"假中本聪"身份
    • 场景2：用假身份签名经典消息（8条）
    • 场景3：构造比特币风格scriptSig
    • 场景4：演示为什么这是"伪造"
    • 场景5：真实攻击的技术难点分析
    • 场景6：防护机制和检测方法
    • 场景7：统计分析和教育总结
    • 高级场景：多重身份、时间戳、关联性分析

⚠️  伪造演示仅用于密码学安全教育，严禁用于任何非法用途！
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

def run_forge_nakamoto_signature():
    """模拟伪造中本聪数字签名（仅用于学习研究）"""
    print("=" * 50)
    print("模拟伪造中本聪数字签名（仅用于学习研究）")
    print("=" * 50)
    print("⚠️  本功能仅用于密码学安全教育和研究，禁止用于任何非法用途！")
    print()
    try:
        from nakamoto_signature import NakamotoSignature, Secp256k1, ECPoint
        nakamoto = NakamotoSignature()
        # 假设我们知道一个公钥Q（比如比特币创世块公钥）
        # 这里用随机生成的密钥对模拟“中本聪公钥”
        fake_priv, fake_pub = nakamoto.generate_keypair()
        print(f"假冒中本聪公钥: (\n  x={hex(fake_pub.x)},\n  y={hex(fake_pub.y)})")
        print(f"假冒中本聪私钥(仅演示): {hex(fake_priv)}")
        # 伪造一条消息
        message = b"I am Satoshi Nakamoto."
        msg_hash = nakamoto.double_sha256(message)
        # 用假私钥对消息签名
        r, s = nakamoto.sign(msg_hash, fake_priv)
        der_sig = nakamoto.encode_der(r, s)
        print(f"伪造签名DER: {der_sig.hex()}")
        # 验证签名（应通过）
        valid = nakamoto.verify(msg_hash, (r, s), fake_pub)
        print(f"伪造签名验证: {'通过' if valid else '失败'}")
        print("\n伪造签名内容:")
        print(f"消息: {message}")
        print(f"签名: r={hex(r)}, s={hex(s)}")
        print(f"公钥: (x={hex(fake_pub.x)}, y={hex(fake_pub.y)})")
        print(f"DER签名: {der_sig.hex()}")
        print("\n⚠️  这只是模拟伪造，真实比特币网络不会承认该签名！")
    except Exception as e:
        print(f"❌ 伪造过程中发生错误: {e}")
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
        elif command == "forge_nakamoto":
            # 新增的伪造演示功能
            try:
                forge_sys_path = os.path.join(os.path.dirname(__file__), 'src')
                if forge_sys_path not in sys.path:
                    sys.path.insert(0, forge_sys_path)
                from nakamoto_forgery import main as run_forgery_main
                run_forgery_main()
            except ImportError as e:
                print(f"❌ 无法导入伪造演示模块: {e}")
                print("请确保 src/nakamoto_forgery.py 文件存在")
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
            run_forge_nakamoto_signature()
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
