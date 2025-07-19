#!/usr/bin/env python3
"""
SM2签名算法误用攻击验证测试程序
测试SM2攻击POC的有效性
"""

import sys
import os
import time
import random
import hashlib

# 添加src目录到Python路径
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from sm2_basic import SM2, SM2Curve, BigInt
from sm2_attack_poc import SM2AttackPOC


class AttackVerificationTests:
    """SM2攻击验证测试套件"""
    
    def __init__(self):
        self.sm2 = SM2()
        self.attack_poc = SM2AttackPOC()
        self.test_results = []
        
        print("=" * 80)
        print("SM2签名算法误用攻击验证测试")
        print("=" * 80)
        print(f"测试开始时间: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print()
    
    def log_test_result(self, test_name, success, details=""):
        """记录测试结果"""
        status = "✅ 成功" if success else "❌ 失败"
        result = {
            'name': test_name,
            'success': success,
            'details': details,
            'timestamp': time.strftime('%H:%M:%S')
        }
        self.test_results.append(result)
        print(f"[{result['timestamp']}] {test_name}: {status}")
        if details:
            print(f"    详情: {details}")
        print()
    
    def test_direct_poc_attacks(self):
        """直接调用POC中的攻击方法"""
        print("测试1: 直接运行POC攻击演示")
        print("-" * 40)
        
        try:
            # 调用POC中的所有攻击方法
            results = []
            
            print("\n=== 攻击1: 同一用户k重用攻击 ===")
            result1 = self.attack_poc.attack_k_reuse_same_user()
            results.append(("同一用户k重用攻击", result1))
            
            print("\n=== 攻击2: 跨用户k重用攻击 ===")
            result2 = self.attack_poc.attack_k_reuse_cross_user()
            results.append(("跨用户k重用攻击", result2))
            
            print("\n=== 攻击3: 签名延展性攻击 ===")
            result3 = self.attack_poc.attack_signature_malleability()
            results.append(("签名延展性攻击", result3))
            
            print("\n=== 攻击4: 参数校验缺失攻击 ===")
            result4 = self.attack_poc.attack_parameter_validation_bypass()
            results.append(("参数校验缺失攻击", result4))
            
            print("\n=== 攻击5: 跨算法共享(d,k)攻击 ===")
            result5 = self.attack_poc.demonstrate_cross_algorithm_attack()
            results.append(("跨算法共享攻击", result5))
            
            # 统计结果
            successful_attacks = sum(1 for _, success in results if success)
            total_attacks = len(results)
            
            details = f"成功攻击: {successful_attacks}/{total_attacks}"
            success = successful_attacks > 0
            
            self.log_test_result("POC攻击演示", success, details)
            
            # 详细结果
            for attack_name, attack_success in results:
                status = "✅" if attack_success else "❌"
                print(f"  {status} {attack_name}")
            
        except Exception as e:
            self.log_test_result("POC攻击演示", False, f"异常: {str(e)}")
    
    def test_signature_malleability_verification(self):
        """测试签名延展性验证"""
        print("测试2: 签名延展性验证")
        print("-" * 40)
        
        try:
            # 生成测试数据
            private_key = random.randint(1, self.sm2.curve.n - 1)
            public_key = self.sm2.curve.point_multiply(private_key, self.sm2.curve.G)
            message = "延展性测试消息"
            
            # 生成原始签名
            original_signature = self.sm2.sign(message.encode('utf-8'), private_key)
            
            # 使用攻击POC生成延展签名
            malleable_signature = self.attack_poc.signature_malleability_attack(original_signature)
            
            # 验证原始签名
            verify_original = self.sm2.verify(message.encode('utf-8'), original_signature, public_key)
            
            # 验证延展签名
            verify_malleable = self.sm2.verify(message.encode('utf-8'), malleable_signature, public_key)
            
            # 检查签名是否不同
            signatures_different = (original_signature != malleable_signature)
            
            print(f"原始签名: r={hex(original_signature[0])}, s={hex(original_signature[1])}")
            print(f"延展签名: r={hex(malleable_signature[0])}, s={hex(malleable_signature[1])}")
            print(f"原始签名验证: {verify_original}")
            print(f"延展签名验证: {verify_malleable}")
            print(f"签名不同: {signatures_different}")
            
            # 成功条件：原始签名有效，签名不同
            success = verify_original and signatures_different
            details = f"原始有效: {verify_original}, 延展有效: {verify_malleable}, 不同: {signatures_different}"
            
            self.log_test_result("签名延展性验证", success, details)
            
        except Exception as e:
            self.log_test_result("签名延展性验证", False, f"异常: {str(e)}")
    
    def test_random_quality_analysis(self):
        """测试随机数质量分析"""
        print("测试3: 随机数质量分析")
        print("-" * 40)
        
        try:
            # 生成正常签名
            private_key = random.randint(1, self.sm2.curve.n - 1)
            public_key = self.sm2.curve.point_multiply(private_key, self.sm2.curve.G)
            
            normal_signatures = []
            for i in range(20):
                message = f"正常消息{i}"
                signature = self.sm2.sign(message.encode('utf-8'), private_key)
                normal_signatures.append(signature)
            
            # 生成弱随机数签名
            weak_signatures = []
            base_k = random.randint(1, 1000)
            for i in range(10):
                weak_k = base_k + i  # 连续的k值
                message = f"弱随机数消息{i}"
                signature = self.sm2.sign_with_k(message, private_key, weak_k)
                weak_signatures.append(signature)
            
            # 分析随机数质量
            normal_analysis = self.attack_poc.analyze_random_quality(normal_signatures)
            weak_analysis = self.attack_poc.analyze_random_quality(weak_signatures)
            
            print(f"正常签名分析 - 重复r值: {normal_analysis['duplicate_r_count']}, 偏差: {normal_analysis['bias_score']:.4f}")
            print(f"弱随机签名分析 - 重复r值: {weak_analysis['duplicate_r_count']}, 偏差: {weak_analysis['bias_score']:.4f}")
            
            # 检测能力：弱随机数应该有更高的偏差评分
            detection_success = weak_analysis['bias_score'] > normal_analysis['bias_score']
            
            details = f"正常偏差: {normal_analysis['bias_score']:.4f}, 弱随机偏差: {weak_analysis['bias_score']:.4f}"
            
            self.log_test_result("随机数质量分析", detection_success, details)
            
        except Exception as e:
            self.log_test_result("随机数质量分析", False, f"异常: {str(e)}")
    
    def test_parameter_validation(self):
        """测试参数校验"""
        print("测试4: 参数校验")
        print("-" * 40)
        
        try:
            # 测试各种边界条件
            test_cases = [
                ("r=0", 0, 12345),
                ("s=0", 12345, 0),
                ("r=n", self.sm2.curve.n, 12345),
                ("s=n", 12345, self.sm2.curve.n),
            ]
            
            bypass_count = 0
            total_tests = len(test_cases)
            
            for test_name, r, s in test_cases:
                try:
                    result = self.attack_poc.validate_signature_parameters(r, s)
                    if result:
                        bypass_count += 1
                        print(f"  {test_name}: 校验绕过 ⚠️")
                    else:
                        print(f"  {test_name}: 正确拒绝")
                except Exception as e:
                    print(f"  {test_name}: 正确抛出异常 - {type(e).__name__}")
            
            success = bypass_count == 0
            details = f"发现 {bypass_count}/{total_tests} 个校验绕过"
            
            self.log_test_result("参数校验", success, details)
            
        except Exception as e:
            self.log_test_result("参数校验", False, f"异常: {str(e)}")
    
    def run_comprehensive_test(self):
        """运行全面的攻击验证测试"""
        print("开始执行攻击验证测试...")
        print()
        
        # 执行所有测试
        test_methods = [
            self.test_direct_poc_attacks,
            self.test_signature_malleability_verification,
            self.test_random_quality_analysis,
            self.test_parameter_validation,
        ]
        
        for test_method in test_methods:
            try:
                test_method()
            except Exception as e:
                print(f"测试方法 {test_method.__name__} 执行异常: {e}")
                print()
        
        # 输出测试总结
        self.print_test_summary()
    
    def print_test_summary(self):
        """输出测试总结"""
        print("=" * 80)
        print("测试总结")
        print("=" * 80)
        
        total_tests = len(self.test_results)
        successful_tests = sum(1 for result in self.test_results if result['success'])
        failed_tests = total_tests - successful_tests
        
        print(f"总测试数: {total_tests}")
        print(f"成功测试: {successful_tests}")
        print(f"失败测试: {failed_tests}")
        if total_tests > 0:
            print(f"成功率: {(successful_tests/total_tests)*100:.1f}%")
        print()
        
        # 详细结果
        print("详细测试结果:")
        print("-" * 80)
        for result in self.test_results:
            status = "✅" if result['success'] else "❌"
            print(f"{status} {result['name']} [{result['timestamp']}]")
            if result['details']:
                print(f"   {result['details']}")
        
        print()
        print("测试结论:")
        print("-" * 80)
        if total_tests == 0:
            print("❌ 没有执行任何测试")
        elif successful_tests == total_tests:
            print("✅ 所有攻击验证测试均成功，POC代码工作正常")
        elif successful_tests > total_tests * 0.5:
            print("⚠️  大部分攻击验证成功，但存在一些问题需要关注")
        else:
            print("❌ 多个攻击验证失败，需要检查POC实现")
        
        print(f"\n测试完成时间: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 80)


def main():
    """主函数"""
    # 创建测试实例
    tester = AttackVerificationTests()
    
    # 运行全面测试
    tester.run_comprehensive_test()


if __name__ == "__main__":
    main()
