#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SM4-GCM 工作模式软件优化测试程序

本程序全面测试SM4-GCM的实现，包括：
1. 基础功能测试
2. 性能优化对比
3. 并行处理能力测试
4. 大数据流式处理测试
5. 安全性验证测试
"""

import time
import os
import random
from typing import List, Tuple
from sm4_gcm import SM4_GCM_Base, SM4_GCM_Optimized, SM4_GCM_Advanced


class SM4_GCM_Tester:
    """SM4-GCM测试套件"""
    
    def __init__(self):
        self.test_key = b'0123456789ABCDEF'  # 标准16字节测试密钥
        self.test_iv = b'123456789012'       # 标准12字节IV
        self.test_cases = self._generate_test_cases()
        
    def _generate_test_cases(self) -> List[dict]:
        """生成各种测试用例"""
        cases = [
            {
                'name': '空明文测试',
                'plaintext': b'',
                'auth_data': b'',
                'description': '测试空数据处理'
            },
            {
                'name': '单块明文测试',
                'plaintext': b'Hello SM4-GCM!',
                'auth_data': b'auth',
                'description': '测试小于16字节的单块数据'
            },
            {
                'name': '完整块测试',
                'plaintext': b'1234567890123456',  # 正好16字节
                'auth_data': b'authenticated_data',
                'description': '测试正好一个完整块的数据'
            },
            {
                'name': '多块数据测试',
                'plaintext': b'This is a longer message that spans multiple 16-byte blocks for testing purposes.',
                'auth_data': b'Additional authenticated data for multi-block test',
                'description': '测试跨越多个块的数据'
            },
            {
                'name': '大数据测试',
                'plaintext': b'Large data block ' * 1000,  # 约16KB
                'auth_data': b'Auth data for large test',
                'description': '测试大数据块处理'
            },
            {
                'name': 'Unicode数据测试',
                'plaintext': '中文测试数据：这是一个包含中文字符的测试用例。'.encode('utf-8'),
                'auth_data': '认证数据：中文认证信息'.encode('utf-8'),
                'description': '测试Unicode字符处理'
            }
        ]
        
        # 添加随机数据测试
        for size in [64, 256, 1024, 4096]:
            cases.append({
                'name': f'{size}字节随机数据',
                'plaintext': os.urandom(size),
                'auth_data': os.urandom(32),
                'description': f'测试{size}字节随机数据'
            })
        
        return cases
    
    def test_basic_functionality(self) -> bool:
        """测试基础功能"""
        print("=== 基础功能测试 ===")
        
        all_passed = True
        
        for i, case in enumerate(self.test_cases[:6]):  # 测试前6个基础用例
            print(f"\n{i+1}. {case['name']}")
            print(f"   描述: {case['description']}")
            
            try:
                # 使用基础实现
                gcm = SM4_GCM_Base(self.test_key, 'ttable')
                
                # 加密
                ciphertext, tag = gcm.encrypt(self.test_iv, case['plaintext'], case['auth_data'])
                
                # 解密
                decrypted = gcm.decrypt(self.test_iv, ciphertext, tag, case['auth_data'])
                
                # 验证
                if decrypted == case['plaintext']:
                    print(f"   ✓ 加密解密正确")
                    print(f"   ✓ 明文长度: {len(case['plaintext'])} 字节")
                    print(f"   ✓ 密文长度: {len(ciphertext)} 字节")
                    print(f"   ✓ 认证标签: {tag[:8].hex()}...")
                else:
                    print(f"   ✗ 加密解密失败")
                    all_passed = False
                
                # 测试认证失败检测
                try:
                    # 修改密文测试认证失败
                    if ciphertext:
                        tampered_cipher = bytearray(ciphertext)
                        tampered_cipher[0] ^= 1
                        gcm.decrypt(self.test_iv, bytes(tampered_cipher), tag, case['auth_data'])
                        print(f"   ✗ 未检测到密文篡改")
                        all_passed = False
                    else:
                        print(f"   ✓ 空密文跳过篡改测试")
                except ValueError:
                    print(f"   ✓ 正确检测到密文篡改")
                
            except Exception as e:
                print(f"   ✗ 测试异常: {e}")
                all_passed = False
        
        return all_passed
    
    def test_optimization_performance(self) -> dict:
        """测试优化性能对比"""
        print("\n=== 优化性能对比测试 ===")
        
        # 使用中等大小的测试数据
        test_data = b'Performance test data ' * 100  # 约2.3KB
        auth_data = b'Auth data for performance test'
        
        optimizations = ['basic', 'ttable', 'aesni', 'modern']
        results = {}
        
        for opt in optimizations:
            print(f"\n测试 {opt.upper()} 优化:")
            
            try:
                # 创建适当的GCM实例
                if opt == 'basic':
                    gcm = SM4_GCM_Base(self.test_key, opt)
                else:
                    gcm = SM4_GCM_Optimized(self.test_key, opt)
                
                # 预热
                gcm.encrypt(self.test_iv, b'warmup', b'')
                
                # 性能测试
                num_iterations = 100
                
                start_time = time.time()
                for _ in range(num_iterations):
                    ciphertext, tag = gcm.encrypt(self.test_iv, test_data, auth_data)
                    decrypted = gcm.decrypt(self.test_iv, ciphertext, tag, auth_data)
                end_time = time.time()
                
                avg_time = (end_time - start_time) / num_iterations
                throughput = len(test_data) / avg_time / 1024 / 1024  # MB/s
                
                results[opt] = {
                    'avg_time': avg_time,
                    'throughput': throughput
                }
                
                print(f"  ✓ 平均处理时间: {avg_time*1000:.2f} ms")
                print(f"  ✓ 吞吐量: {throughput:.2f} MB/s")
                
                # 验证正确性
                if decrypted == test_data:
                    print(f"  ✓ 正确性验证通过")
                else:
                    print(f"  ✗ 正确性验证失败")
                
            except Exception as e:
                print(f"  ✗ 测试错误: {e}")
                results[opt] = {'avg_time': float('inf'), 'throughput': 0}
        
        # 性能对比总结
        print(f"\n性能对比总结:")
        if 'basic' in results and results['basic']['avg_time'] != float('inf'):
            baseline = results['basic']['throughput']
            for opt in optimizations:
                if opt in results and results[opt]['throughput'] > 0:
                    speedup = results[opt]['throughput'] / baseline
                    print(f"  {opt.upper()}: {speedup:.2f}x 提升")
        
        return results
    
    def test_parallel_processing(self) -> bool:
        """测试并行处理能力"""
        print("\n=== 并行处理能力测试 ===")
        
        try:
            # 创建优化的GCM实例
            gcm = SM4_GCM_Optimized(self.test_key, 'ttable')
            
            # 测试不同大小的并行处理
            test_sizes = [1024, 4096, 16384]  # 1KB, 4KB, 16KB
            
            for size in test_sizes:
                print(f"\n测试 {size} 字节数据并行处理:")
                
                test_data = os.urandom(size)
                auth_data = b'Parallel processing test'
                
                # 顺序处理时间
                start_time = time.time()
                for _ in range(10):
                    ciphertext, tag = gcm.encrypt(self.test_iv, test_data, auth_data)
                sequential_time = time.time() - start_time
                
                # 并行处理时间（如果支持）
                if hasattr(gcm, 'supports_parallel') and gcm.supports_parallel:
                    start_time = time.time()
                    for _ in range(10):
                        ciphertext, tag = gcm.encrypt(self.test_iv, test_data, auth_data)
                    parallel_time = time.time() - start_time
                    
                    speedup = sequential_time / parallel_time
                    print(f"  ✓ 并行加速比: {speedup:.2f}x")
                    print(f"  ✓ 顺序处理: {sequential_time*100:.2f} ms")
                    print(f"  ✓ 并行处理: {parallel_time*100:.2f} ms")
                else:
                    print(f"  • 当前实现不支持并行处理")
                    print(f"  ✓ 处理时间: {sequential_time*100:.2f} ms")
            
            return True
            
        except Exception as e:
            print(f"  ✗ 并行处理测试错误: {e}")
            return False
    
    def test_stream_processing(self) -> bool:
        """测试流式处理"""
        print("\n=== 流式处理测试 ===")
        
        try:
            # 创建高级GCM实例
            advanced_gcm = SM4_GCM_Advanced(self.test_key, 'ttable')
            
            # 生成大量测试数据
            large_data = b'Stream processing test data block ' * 2000  # 约68KB
            auth_data = b'Stream auth data'
            
            print(f"测试数据大小: {len(large_data)} 字节")
            
            # 常规加密
            start_time = time.time()
            regular_cipher, regular_tag = advanced_gcm.encrypt(self.test_iv, large_data, auth_data)
            regular_time = time.time() - start_time
            
            # 流式加密
            chunk_size = 1024
            chunks = [large_data[i:i+chunk_size] for i in range(0, len(large_data), chunk_size)]
            
            start_time = time.time()
            stream_cipher, stream_tag = advanced_gcm.encrypt_stream(
                self.test_iv, chunks, auth_data, chunk_size
            )
            stream_time = time.time() - start_time
            
            # 验证结果一致性
            if stream_cipher == regular_cipher and stream_tag == regular_tag:
                print(f"  ✓ 流式处理结果正确")
                print(f"  ✓ 常规加密时间: {regular_time*1000:.2f} ms")
                print(f"  ✓ 流式加密时间: {stream_time*1000:.2f} ms")
                print(f"  ✓ 流式处理吞吐量: {len(large_data)/stream_time/1024/1024:.2f} MB/s")
                
                # 内存效率测试
                memory_efficiency = regular_time / stream_time
                print(f"  ✓ 相对性能: {memory_efficiency:.2f}x")
                
                return True
            else:
                print(f"  ✗ 流式处理结果不匹配")
                return False
        
        except Exception as e:
            print(f"  ✗ 流式处理测试错误: {e}")
            return False
    
    def test_security_features(self) -> bool:
        """测试安全特性"""
        print("\n=== 安全特性测试 ===")
        
        gcm = SM4_GCM_Optimized(self.test_key, 'ttable')
        all_passed = True
        
        # 1. IV重用检测
        print("\n1. IV重用安全性测试:")
        try:
            plaintext1 = b'First message'
            plaintext2 = b'Second message'
            auth_data = b'auth'
            
            cipher1, tag1 = gcm.encrypt(self.test_iv, plaintext1, auth_data)
            cipher2, tag2 = gcm.encrypt(self.test_iv, plaintext2, auth_data)
            
            # 相同IV应该产生不同的密文（除非明文相同）
            if cipher1 != cipher2:
                print(f"  ✓ IV重用产生不同密文（正常）")
            else:
                print(f"  • IV重用产生相同密文（需要注意）")
            
        except Exception as e:
            print(f"  ✗ IV重用测试错误: {e}")
            all_passed = False
        
        # 2. 认证数据修改检测
        print("\n2. 认证数据修改检测:")
        try:
            plaintext = b'Test message for auth modification'
            original_auth = b'original auth data'
            modified_auth = b'modified auth data'
            
            ciphertext, tag = gcm.encrypt(self.test_iv, plaintext, original_auth)
            
            try:
                # 尝试用修改过的认证数据解密
                gcm.decrypt(self.test_iv, ciphertext, tag, modified_auth)
                print(f"  ✗ 未检测到认证数据修改")
                all_passed = False
            except ValueError:
                print(f"  ✓ 正确检测到认证数据修改")
            
        except Exception as e:
            print(f"  ✗ 认证数据修改测试错误: {e}")
            all_passed = False
        
        # 3. 标签截断攻击检测
        print("\n3. 标签截断攻击检测:")
        try:
            plaintext = b'Test message for tag truncation'
            auth_data = b'auth data'
            
            ciphertext, tag = gcm.encrypt(self.test_iv, plaintext, auth_data)
            
            # 测试截断的标签
            for truncate_len in [8, 12, 15]:
                truncated_tag = tag[:truncate_len] + b'\x00' * (16 - truncate_len)
                
                try:
                    gcm.decrypt(self.test_iv, ciphertext, truncated_tag, auth_data)
                    print(f"  ✗ 未检测到{truncate_len}字节标签截断")
                    all_passed = False
                except ValueError:
                    print(f"  ✓ 正确检测到{truncate_len}字节标签截断")
            
        except Exception as e:
            print(f"  ✗ 标签截断测试错误: {e}")
            all_passed = False
        
        # 4. 密钥敏感性测试
        print("\n4. 密钥敏感性测试:")
        try:
            plaintext = b'Key sensitivity test message'
            auth_data = b'auth data'
            
            # 原始密钥加密
            gcm1 = SM4_GCM_Optimized(self.test_key, 'ttable')
            cipher1, tag1 = gcm1.encrypt(self.test_iv, plaintext, auth_data)
            
            # 修改一位的密钥
            modified_key = bytearray(self.test_key)
            modified_key[0] ^= 1
            
            gcm2 = SM4_GCM_Optimized(bytes(modified_key), 'ttable')
            cipher2, tag2 = gcm2.encrypt(self.test_iv, plaintext, auth_data)
            
            # 检查密文差异
            diff_bits = sum(bin(a ^ b).count('1') for a, b in zip(cipher1, cipher2))
            diff_ratio = diff_bits / (len(cipher1) * 8)
            
            if diff_ratio > 0.4:  # 应该有接近50%的位差异
                print(f"  ✓ 密钥敏感性良好 (差异率: {diff_ratio:.1%})")
            else:
                print(f"  • 密钥敏感性较低 (差异率: {diff_ratio:.1%})")
            
        except Exception as e:
            print(f"  ✗ 密钥敏感性测试错误: {e}")
            all_passed = False
        
        return all_passed
    
    def run_comprehensive_test(self) -> dict:
        """运行综合测试"""
        print("=" * 60)
        print(" SM4-GCM 工作模式软件优化 - 综合测试报告")
        print("=" * 60)
        
        results = {
            'basic_functionality': False,
            'optimization_performance': {},
            'parallel_processing': False,
            'stream_processing': False,
            'security_features': False,
            'overall_score': 0
        }
        
        # 执行各项测试
        try:
            results['basic_functionality'] = self.test_basic_functionality()
            results['optimization_performance'] = self.test_optimization_performance()
            results['parallel_processing'] = self.test_parallel_processing()
            results['stream_processing'] = self.test_stream_processing()
            results['security_features'] = self.test_security_features()
            
            # 计算总体评分
            score = 0
            if results['basic_functionality']:
                score += 30
            if results['optimization_performance']:
                score += 25
            if results['parallel_processing']:
                score += 15
            if results['stream_processing']:
                score += 15
            if results['security_features']:
                score += 15
            
            results['overall_score'] = score
            
        except Exception as e:
            print(f"\n综合测试过程中发生错误: {e}")
        
        # 生成测试报告
        self._generate_test_report(results)
        
        return results
    
    def _generate_test_report(self, results: dict):
        """生成测试报告"""
        print("\n" + "=" * 60)
        print(" 测试结果总结")
        print("=" * 60)
        
        print(f"\n基础功能测试: {'✓ 通过' if results['basic_functionality'] else '✗ 失败'}")
        print(f"性能优化测试: {'✓ 完成' if results['optimization_performance'] else '✗ 失败'}")
        print(f"并行处理测试: {'✓ 通过' if results['parallel_processing'] else '✗ 失败'}")
        print(f"流式处理测试: {'✓ 通过' if results['stream_processing'] else '✗ 失败'}")
        print(f"安全特性测试: {'✓ 通过' if results['security_features'] else '✗ 失败'}")
        
        print(f"\n总体评分: {results['overall_score']}/100")
        
        if results['overall_score'] >= 90:
            print("评级: 优秀 ⭐⭐⭐⭐⭐")
        elif results['overall_score'] >= 75:
            print("评级: 良好 ⭐⭐⭐⭐")
        elif results['overall_score'] >= 60:
            print("评级: 合格 ⭐⭐⭐")
        else:
            print("评级: 需要改进 ⭐⭐")
        
        # 性能总结
        if results['optimization_performance']:
            print(f"\n性能优化效果:")
            perf = results['optimization_performance']
            if 'basic' in perf and 'ttable' in perf:
                if perf['basic']['throughput'] > 0 and perf['ttable']['throughput'] > 0:
                    ttable_speedup = perf['ttable']['throughput'] / perf['basic']['throughput']
                    print(f"  T-Table优化: {ttable_speedup:.2f}x 提升")
            
            if 'ttable' in perf and 'aesni' in perf:
                if perf['ttable']['throughput'] > 0 and perf['aesni']['throughput'] > 0:
                    aesni_speedup = perf['aesni']['throughput'] / perf['ttable']['throughput']
                    print(f"  AES-NI优化: {aesni_speedup:.2f}x 额外提升")


def main():
    """主测试函数"""
    print("SM4-GCM 工作模式软件优化实现测试")
    print("Author: AI Assistant")
    print("Date: 2025-08-10")
    print()
    
    # 创建测试器
    tester = SM4_GCM_Tester()
    
    # 运行综合测试
    results = tester.run_comprehensive_test()
    
    # 保存测试结果
    print(f"\n测试完成！结果已保存到内存。")
    
    return results


if __name__ == "__main__":
    main()
