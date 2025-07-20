#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
中本聪数字签名测试套件
验证ECDSA-secp256k1实现的正确性和安全性
"""

import sys
import os
import time

# 添加src目录到路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from nakamoto_signature import NakamotoSignature, test_nakamoto_signature

class NakamotoSignatureTests:
    """中本聪数字签名测试类"""
    
    def __init__(self):
        self.nakamoto = NakamotoSignature()
        self.test_results = []
    
    def log_test(self, test_name: str, success: bool, details: str = ""):
        """记录测试结果"""
        timestamp = time.strftime("%H:%M:%S")
        status = "✅ 成功" if success else "❌ 失败"
        self.test_results.append({
            'name': test_name,
            'success': success,
            'details': details,
            'timestamp': timestamp
        })
        print(f"[{timestamp}] {test_name}: {status}")
        if details:
            print(f"    详情: {details}")
    
    def test_secp256k1_parameters(self):
        """测试secp256k1参数"""
        try:
            from nakamoto_signature import Secp256k1, ECPoint
            
            # 验证基点在曲线上
            G = ECPoint(Secp256k1.Gx, Secp256k1.Gy)
            on_curve = G.is_on_curve()
            
            # 验证基点阶
            inf_point = self.nakamoto.scalar_mult(Secp256k1.n, G)
            correct_order = inf_point.is_infinity
            
            success = on_curve and correct_order
            details = f"基点在曲线上: {on_curve}, 基点阶正确: {correct_order}"
            
            self.log_test("secp256k1参数验证", success, details)
            return success
            
        except Exception as e:
            self.log_test("secp256k1参数验证", False, f"异常: {str(e)}")
            return False
    
    def test_key_generation(self):
        """测试密钥生成"""
        try:
            # 生成多个密钥对验证
            keys = []
            for _ in range(5):
                private_key, public_key = self.nakamoto.generate_keypair()
                
                # 验证私钥范围
                if not (1 <= private_key < self.nakamoto.curve.n):
                    raise ValueError("私钥超出范围")
                
                # 验证公钥在曲线上
                if not public_key.is_on_curve():
                    raise ValueError("公钥不在曲线上")
                
                # 验证公钥 = 私钥 * G
                expected_pubkey = self.nakamoto.scalar_mult(private_key, self.nakamoto.G)
                if not (public_key.x == expected_pubkey.x and public_key.y == expected_pubkey.y):
                    raise ValueError("公钥计算错误")
                
                keys.append((private_key, public_key))
            
            # 验证密钥唯一性
            unique_private = len(set(k[0] for k in keys)) == len(keys)
            unique_public = len(set((k[1].x, k[1].y) for k in keys)) == len(keys)
            
            success = unique_private and unique_public
            details = f"生成{len(keys)}个密钥对, 私钥唯一: {unique_private}, 公钥唯一: {unique_public}"
            
            self.log_test("密钥生成测试", success, details)
            return success
            
        except Exception as e:
            self.log_test("密钥生成测试", False, f"异常: {str(e)}")
            return False
    
    def test_signature_verification(self):
        """测试签名和验证"""
        try:
            # 生成测试数据
            private_key, public_key = self.nakamoto.generate_keypair()
            
            test_messages = [
                b"Hello Bitcoin!",
                b"The Times 03/Jan/2009 Chancellor on brink of second bailout for banks",
                b"",  # 空消息
                b"A" * 1000,  # 长消息
                bytes(range(256))  # 二进制数据
            ]
            
            all_passed = True
            verified_count = 0
            
            for i, message in enumerate(test_messages):
                msg_hash = self.nakamoto.double_sha256(message)
                
                # 签名
                signature = self.nakamoto.sign(msg_hash, private_key)
                
                # 验证正确签名
                valid = self.nakamoto.verify(msg_hash, signature, public_key)
                if not valid:
                    all_passed = False
                    continue
                
                # 验证错误消息
                wrong_hash = self.nakamoto.double_sha256(message + b"wrong")
                invalid = not self.nakamoto.verify(wrong_hash, signature, public_key)
                if not invalid:
                    all_passed = False
                    continue
                
                verified_count += 1
            
            success = all_passed and verified_count == len(test_messages)
            details = f"测试{len(test_messages)}条消息, 通过: {verified_count}"
            
            self.log_test("签名验证测试", success, details)
            return success
            
        except Exception as e:
            self.log_test("签名验证测试", False, f"异常: {str(e)}")
            return False
    
    def test_der_encoding(self):
        """测试DER编码"""
        try:
            # 生成测试签名
            private_key, public_key = self.nakamoto.generate_keypair()
            message = b"DER encoding test"
            msg_hash = self.nakamoto.double_sha256(message)
            
            r, s = self.nakamoto.sign(msg_hash, private_key)
            
            # DER编码
            der_bytes = self.nakamoto.encode_der(r, s)
            
            # 验证DER格式
            if len(der_bytes) < 6:
                raise ValueError("DER数据太短")
            
            if der_bytes[0] != 0x30:
                raise ValueError("无效的DER序列标识")
            
            # DER解码
            r_decoded, s_decoded = self.nakamoto.decode_der(der_bytes)
            
            # 验证编码解码一致性
            encoding_correct = (r == r_decoded and s == s_decoded)
            
            # 验证解码后的签名仍然有效
            verification_valid = self.nakamoto.verify(msg_hash, (r_decoded, s_decoded), public_key)
            
            success = encoding_correct and verification_valid
            details = f"编码正确: {encoding_correct}, 解码验证: {verification_valid}, DER长度: {len(der_bytes)}"
            
            self.log_test("DER编码测试", success, details)
            return success
            
        except Exception as e:
            self.log_test("DER编码测试", False, f"异常: {str(e)}")
            return False
    
    def test_bitcoin_signature_format(self):
        """测试比特币签名格式"""
        try:
            # 生成测试数据
            private_key, public_key = self.nakamoto.generate_keypair()
            message = b"Bitcoin signature format test"
            msg_hash = self.nakamoto.double_sha256(message)
            
            # 创建比特币签名
            bitcoin_sig = self.nakamoto.create_bitcoin_signature(msg_hash, private_key)
            
            # 验证格式
            if len(bitcoin_sig) < 2:
                raise ValueError("比特币签名太短")
            
            # 验证SIGHASH类型
            sighash_type = bitcoin_sig[-1]
            if sighash_type != 0x01:  # SIGHASH_ALL
                raise ValueError(f"错误的SIGHASH类型: {hex(sighash_type)}")
            
            # 验证比特币签名
            bitcoin_valid = self.nakamoto.verify_bitcoin_signature(msg_hash, bitcoin_sig, public_key)
            
            # 测试错误的签名
            wrong_sig = bitcoin_sig[:-1] + b'\xFF'  # 使用不支持的SIGHASH类型
            wrong_valid = not self.nakamoto.verify_bitcoin_signature(msg_hash, wrong_sig, public_key)
            
            success = bitcoin_valid and wrong_valid
            details = f"比特币签名验证: {bitcoin_valid}, 错误签名拒绝: {wrong_valid}, 签名长度: {len(bitcoin_sig)}"
            
            self.log_test("比特币签名格式测试", success, details)
            return success
            
        except Exception as e:
            self.log_test("比特币签名格式测试", False, f"异常: {str(e)}")
            return False
    
    def test_k_reuse_attack(self):
        """测试k重用攻击"""
        try:
            # 模拟k重用攻击
            import secrets
            from nakamoto_signature import Secp256k1
            
            # 生成受害者密钥
            victim_privkey, victim_pubkey = self.nakamoto.generate_keypair()
            
            # 使用相同k签名两个消息
            k = secrets.randbelow(Secp256k1.n - 1) + 1
            
            msg1 = b"Payment to Alice: 1 BTC"
            msg2 = b"Payment to Bob: 2 BTC"
            
            hash1 = self.nakamoto.double_sha256(msg1)
            hash2 = self.nakamoto.double_sha256(msg2)
            
            z1 = int.from_bytes(hash1, 'big')
            z2 = int.from_bytes(hash2, 'big')
            
            # 手动生成签名（模拟k重用）
            point = self.nakamoto.scalar_mult(k, self.nakamoto.G)
            r = point.x % Secp256k1.n
            
            k_inv = self.nakamoto.mod_inverse(k, Secp256k1.n)
            s1 = (k_inv * (z1 + r * victim_privkey)) % Secp256k1.n
            s2 = (k_inv * (z2 + r * victim_privkey)) % Secp256k1.n
            
            # 执行攻击：恢复私钥
            s_diff = (s1 - s2) % Secp256k1.n
            z_diff = (z1 - z2) % Secp256k1.n
            
            if s_diff == 0:
                raise ValueError("s差值为0，无法攻击")
            
            recovered_k = (z_diff * self.nakamoto.mod_inverse(s_diff, Secp256k1.n)) % Secp256k1.n
            recovered_privkey = ((s1 * recovered_k - z1) * self.nakamoto.mod_inverse(r, Secp256k1.n)) % Secp256k1.n
            
            # 验证攻击成功
            attack_success = (recovered_privkey == victim_privkey)
            k_recovery = (recovered_k == k)
            
            success = attack_success and k_recovery
            details = f"私钥恢复: {attack_success}, k值恢复: {k_recovery}"
            
            self.log_test("k重用攻击测试", success, details)
            return success
            
        except Exception as e:
            self.log_test("k重用攻击测试", False, f"异常: {str(e)}")
            return False
    
    def test_low_s_rule(self):
        """测试低S规则（BIP 66）"""
        try:
            from nakamoto_signature import Secp256k1
            
            # 生成测试数据
            private_key, public_key = self.nakamoto.generate_keypair()
            message = b"Low S rule test"
            msg_hash = self.nakamoto.double_sha256(message)
            
            # 生成多个签名，检查低S规则
            low_s_count = 0
            total_tests = 50
            
            for _ in range(total_tests):
                r, s = self.nakamoto.sign(msg_hash, private_key)
                
                # 检查s是否符合低S规则
                if s <= Secp256k1.n // 2:
                    low_s_count += 1
                
                # 验证签名
                if not self.nakamoto.verify(msg_hash, (r, s), public_key):
                    raise ValueError("生成的签名验证失败")
            
            # 所有签名都应该符合低S规则
            all_low_s = (low_s_count == total_tests)
            
            success = all_low_s
            details = f"测试{total_tests}个签名, 低S规则符合: {low_s_count}/{total_tests}"
            
            self.log_test("低S规则测试", success, details)
            return success
            
        except Exception as e:
            self.log_test("低S规则测试", False, f"异常: {str(e)}")
            return False
    
    def run_comprehensive_test(self):
        """运行综合测试"""
        print("=" * 80)
        print("中本聪数字签名综合测试")
        print("=" * 80)
        print(f"测试开始时间: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print()
        
        # 执行所有测试
        test_methods = [
            self.test_secp256k1_parameters,
            self.test_key_generation,
            self.test_signature_verification,
            self.test_der_encoding,
            self.test_bitcoin_signature_format,
            self.test_k_reuse_attack,
            self.test_low_s_rule
        ]
        
        print("开始执行测试...")
        print()
        
        for test_method in test_methods:
            test_method()
        
        # 统计结果
        total_tests = len(self.test_results)
        passed_tests = sum(1 for result in self.test_results if result['success'])
        failed_tests = total_tests - passed_tests
        success_rate = (passed_tests / total_tests) * 100 if total_tests > 0 else 0
        
        print()
        print("=" * 80)
        print("测试总结")
        print("=" * 80)
        print(f"总测试数: {total_tests}")
        print(f"成功测试: {passed_tests}")
        print(f"失败测试: {failed_tests}")
        print(f"成功率: {success_rate:.1f}%")
        
        print()
        print("详细测试结果:")
        print("-" * 80)
        for result in self.test_results:
            status = "✅" if result['success'] else "❌"
            print(f"{status} {result['name']} [{result['timestamp']}]")
            if result['details']:
                print(f"   {result['details']}")
        
        print()
        if failed_tests == 0:
            print("🎉 所有测试通过！中本聪数字签名实现正确")
        else:
            print(f"⚠️ 发现 {failed_tests} 个问题，需要修复")
        
        print(f"\n测试完成时间: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 80)
        
        return success_rate == 100.0

def main():
    """主函数"""
    print("🔐 中本聪数字签名测试套件")
    print("基于ECDSA-secp256k1的比特币风格数字签名测试")
    print()
    
    # 运行基础功能测试
    print("--- 运行基础功能测试 ---")
    try:
        test_nakamoto_signature()
    except Exception as e:
        print(f"基础测试失败: {e}")
        return
    
    print("\n--- 运行综合测试套件 ---")
    tester = NakamotoSignatureTests()
    success = tester.run_comprehensive_test()
    
    if success:
        print("\n🏆 所有测试完美通过！")
        print("📚 中本聪数字签名实现完全正确，可用于:")
        print("  • 比特币签名机制学习")
        print("  • ECDSA算法理解") 
        print("  • 密码学安全研究")
        print("  • 区块链技术教育")
    else:
        print("\n❌ 部分测试失败，需要检查实现")

if __name__ == "__main__":
    main()
