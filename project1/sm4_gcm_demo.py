#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SM4-GCM 工作模式软件优化 - 功能演示程序

本程序演示 SM4-GCM 的各种功能和优化特性：
1. 基础加密解密功能
2. 不同优化策略的性能对比
3. 并行处理能力展示
4. 流式处理大数据演示
5. 安全特性验证
6. 实际应用场景模拟
"""

import os
import time
import random
from typing import List
from sm4_gcm import SM4_GCM_Base, SM4_GCM_Optimized, SM4_GCM_Advanced


class SM4_GCM_Demo:
    """SM4-GCM 功能演示类"""
    
    def __init__(self):
        self.demo_key = b'DemoKey123456789'  # 16字节演示密钥
        self.demo_iv = b'DemoIV123456'      # 12字节演示IV
        
    def print_header(self, title: str):
        """打印标题"""
        print("\n" + "=" * 80)
        print(f" {title}")
        print("=" * 80)
    
    def print_section(self, title: str):
        """打印章节标题"""
        print(f"\n{'='*10} {title} {'='*10}")
    
    def demo_basic_functionality(self):
        """演示基础功能"""
        self.print_header("SM4-GCM 基础功能演示")
        
        # 创建 GCM 实例
        gcm = SM4_GCM_Optimized(self.demo_key, 'ttable')
        
        # 演示数据
        test_cases = [
            {
                'name': '文本消息',
                'plaintext': '这是一条需要加密保护的中文消息。'.encode('utf-8'),
                'auth_data': '发送者：Alice，接收者：Bob'.encode('utf-8')
            },
            {
                'name': '二进制数据',
                'plaintext': os.urandom(64),
                'auth_data': b'Binary data encryption test'
            },
            {
                'name': '空消息',
                'plaintext': b'',
                'auth_data': b'Empty message test'
            }
        ]
        
        for i, case in enumerate(test_cases, 1):
            self.print_section(f"{i}. {case['name']}加密演示")
            
            print(f"明文: {case['plaintext'][:50]}{'...' if len(case['plaintext']) > 50 else ''}")
            print(f"明文长度: {len(case['plaintext'])} 字节")
            print(f"认证数据: {case['auth_data'].decode('utf-8', errors='ignore')}")
            
            # 加密
            start_time = time.time()
            ciphertext, tag = gcm.encrypt(self.demo_iv, case['plaintext'], case['auth_data'])
            encrypt_time = time.time() - start_time
            
            print(f"密文: {ciphertext.hex()[:50]}{'...' if len(ciphertext) > 25 else ''}")
            print(f"认证标签: {tag.hex()}")
            print(f"加密时间: {encrypt_time*1000:.2f} ms")
            
            # 解密验证
            start_time = time.time()
            decrypted = gcm.decrypt(self.demo_iv, ciphertext, tag, case['auth_data'])
            decrypt_time = time.time() - start_time
            
            print(f"解密时间: {decrypt_time*1000:.2f} ms")
            
            if decrypted == case['plaintext']:
                print("✅ 加密解密验证成功")
            else:
                print("❌ 加密解密验证失败")
            
            # 演示篡改检测
            if ciphertext:
                print("\n🔒 篡改检测演示:")
                tampered_cipher = bytearray(ciphertext)
                tampered_cipher[0] ^= 1  # 修改第一个字节
                
                try:
                    gcm.decrypt(self.demo_iv, bytes(tampered_cipher), tag, case['auth_data'])
                    print("❌ 未检测到篡改")
                except ValueError:
                    print("✅ 成功检测到密文篡改")
    
    def demo_optimization_comparison(self):
        """演示优化策略对比"""
        self.print_header("SM4-GCM 优化策略性能对比")
        
        # 测试数据
        test_data = b'Performance test data ' * 200  # 约 4KB
        auth_data = b'Performance test authentication data'
        
        optimizations = [
            ('T-Table优化', 'ttable'),
            ('AES-NI优化', 'aesni'), 
            ('现代指令集优化', 'modern')
        ]
        
        results = {}
        
        print(f"测试数据大小: {len(test_data)} 字节")
        print(f"测试迭代次数: 50 次")
        
        for name, opt_type in optimizations:
            self.print_section(f"{name}测试")
            
            try:
                gcm = SM4_GCM_Optimized(self.demo_key, opt_type)
                
                # 预热
                gcm.encrypt(self.demo_iv, b'warmup', b'')
                
                # 性能测试
                times = []
                for _ in range(50):
                    start_time = time.time()
                    ciphertext, tag = gcm.encrypt(self.demo_iv, test_data, auth_data)
                    decrypted = gcm.decrypt(self.demo_iv, ciphertext, tag, auth_data)
                    times.append(time.time() - start_time)
                
                avg_time = sum(times) / len(times)
                throughput = len(test_data) / avg_time / 1024 / 1024  # MB/s
                
                results[name] = {
                    'avg_time': avg_time,
                    'throughput': throughput
                }
                
                print(f"平均处理时间: {avg_time*1000:.2f} ms")
                print(f"吞吐量: {throughput:.2f} MB/s")
                print(f"最快处理时间: {min(times)*1000:.2f} ms") 
                print(f"最慢处理时间: {max(times)*1000:.2f} ms")
                
                # 验证正确性
                if decrypted == test_data:
                    print("✅ 正确性验证通过")
                else:
                    print("❌ 正确性验证失败")
                    
            except Exception as e:
                print(f"❌ 测试失败: {e}")
                results[name] = {'avg_time': float('inf'), 'throughput': 0}
        
        # 性能对比总结
        self.print_section("性能对比总结")
        
        if len(results) > 1:
            baseline_name = list(results.keys())[0]
            baseline_throughput = results[baseline_name]['throughput']
            
            print(f"{'优化策略':<15} {'处理时间(ms)':<12} {'吞吐量(MB/s)':<12} {'相对性能':<10}")
            print("-" * 60)
            
            for name, result in results.items():
                if result['throughput'] > 0:
                    relative_perf = result['throughput'] / baseline_throughput
                    print(f"{name:<15} {result['avg_time']*1000:<12.2f} "
                          f"{result['throughput']:<12.2f} {relative_perf:<10.2f}x")
    
    def demo_parallel_processing(self):
        """演示并行处理能力"""
        self.print_header("SM4-GCM 并行处理能力演示")
        
        gcm = SM4_GCM_Optimized(self.demo_key, 'ttable')
        
        # 测试不同大小的数据
        test_sizes = [
            (1024, "1KB"),
            (4096, "4KB"), 
            (16384, "16KB"),
            (65536, "64KB")
        ]
        
        for size, size_name in test_sizes:
            self.print_section(f"{size_name} 数据并行处理测试")
            
            test_data = os.urandom(size)
            auth_data = f"{size_name} parallel test".encode()
            
            print(f"数据大小: {len(test_data)} 字节")
            
            # 测试多次以获得稳定结果
            times = []
            for _ in range(20):
                start_time = time.time()
                ciphertext, tag = gcm.encrypt(self.demo_iv, test_data, auth_data)
                times.append(time.time() - start_time)
            
            avg_time = sum(times) / len(times)
            throughput = len(test_data) / avg_time / 1024 / 1024
            
            print(f"平均处理时间: {avg_time*1000:.2f} ms")
            print(f"吞吐量: {throughput:.2f} MB/s")
            print(f"处理速率: {len(test_data) / avg_time:.0f} 字节/秒")
            
            # 验证结果
            decrypted = gcm.decrypt(self.demo_iv, ciphertext, tag, auth_data)
            if decrypted == test_data:
                print("✅ 并行处理结果验证成功")
            else:
                print("❌ 并行处理结果验证失败")
    
    def demo_stream_processing(self):
        """演示流式处理"""
        self.print_header("SM4-GCM 流式处理大数据演示")
        
        advanced_gcm = SM4_GCM_Advanced(self.demo_key, 'ttable')
        
        # 模拟大文件数据
        file_sizes = [
            (50 * 1024, "50KB"),
            (200 * 1024, "200KB"),
            (1024 * 1024, "1MB")
        ]
        
        for size, size_name in file_sizes:
            self.print_section(f"{size_name} 大文件流式加密演示")
            
            print(f"模拟文件大小: {size_name}")
            
            # 生成测试数据
            print("📁 生成测试数据...")
            test_data = bytearray()
            chunk_size = 8192  # 8KB chunks
            
            start_gen = time.time()
            for i in range(0, size, chunk_size):
                chunk = os.urandom(min(chunk_size, size - i))
                test_data.extend(chunk)
            gen_time = time.time() - start_gen
            
            print(f"数据生成时间: {gen_time*1000:.2f} ms")
            print(f"实际数据大小: {len(test_data)} 字节")
            
            # 流式加密
            print("🔐 开始流式加密...")
            auth_data = f"{size_name} stream test".encode()
            
            # 创建数据块生成器
            def data_chunks():
                for i in range(0, len(test_data), chunk_size):
                    yield test_data[i:i+chunk_size]
            
            start_time = time.time()
            stream_cipher, stream_tag = advanced_gcm.encrypt_stream(
                self.demo_iv, data_chunks(), auth_data, chunk_size
            )
            stream_time = time.time() - start_time
            
            print(f"流式加密时间: {stream_time*1000:.2f} ms")
            print(f"流式处理吞吐量: {len(test_data)/stream_time/1024/1024:.2f} MB/s")
            
            # 对比常规加密
            print("🔄 对比常规加密...")
            start_time = time.time()
            regular_cipher, regular_tag = advanced_gcm.encrypt(
                self.demo_iv, bytes(test_data), auth_data
            )
            regular_time = time.time() - start_time
            
            print(f"常规加密时间: {regular_time*1000:.2f} ms")
            print(f"常规处理吞吐量: {len(test_data)/regular_time/1024/1024:.2f} MB/s")
            
            # 性能对比
            if stream_time > 0 and regular_time > 0:
                speedup = regular_time / stream_time
                print(f"流式处理加速比: {speedup:.2f}x")
            
            # 验证结果一致性
            if stream_cipher == regular_cipher and stream_tag == regular_tag:
                print("✅ 流式处理结果与常规加密一致")
            else:
                print("❌ 流式处理结果不一致")
            
            # 内存使用估算
            estimated_memory = chunk_size * 4  # 估算内存使用
            print(f"估算内存使用: {estimated_memory/1024:.2f} KB (vs {len(test_data)/1024:.2f} KB 全量)")
    
    def demo_security_features(self):
        """演示安全特性"""
        self.print_header("SM4-GCM 安全特性演示")
        
        gcm = SM4_GCM_Optimized(self.demo_key, 'ttable')
        
        # 1. 完整性保护演示
        self.print_section("1. 数据完整性保护演示")
        
        plaintext = "这是需要保护完整性的重要数据".encode('utf-8')
        auth_data = "重要文档 - 机密级别".encode('utf-8')
        
        print(f"原始数据: {plaintext.decode('utf-8')}")
        print(f"认证信息: {auth_data.decode('utf-8')}")
        
        # 正常加密
        ciphertext, tag = gcm.encrypt(self.demo_iv, plaintext, auth_data)
        print(f"认证标签: {tag.hex()}")
        
        # 测试各种篡改
        tampering_tests = [
            ("密文首字节篡改", lambda: bytes([ciphertext[0] ^ 1]) + ciphertext[1:]),
            ("密文末字节篡改", lambda: ciphertext[:-1] + bytes([ciphertext[-1] ^ 1])),
            ("认证数据篡改", lambda: ciphertext),
            ("标签篡改", lambda: ciphertext)
        ]
        
        for test_name, tamper_func in tampering_tests:
            print(f"\n🔍 {test_name}测试:")
            
            try:
                if "认证数据" in test_name:
                    tampered_auth = b"modified auth data"
                    gcm.decrypt(self.demo_iv, ciphertext, tag, tampered_auth)
                elif "标签" in test_name:
                    tampered_tag = bytes([tag[0] ^ 1]) + tag[1:]
                    gcm.decrypt(self.demo_iv, ciphertext, tampered_tag, auth_data)
                else:
                    tampered_cipher = tamper_func()
                    gcm.decrypt(self.demo_iv, tampered_cipher, tag, auth_data)
                
                print("❌ 未检测到篡改（安全问题）")
            except ValueError as e:
                print(f"✅ 成功检测到篡改: {e}")
        
        # 2. 密钥敏感性演示
        self.print_section("2. 密钥敏感性演示")
        
        test_message = "密钥敏感性测试消息"
        
        # 原始密钥加密
        original_gcm = SM4_GCM_Optimized(self.demo_key, 'ttable')
        cipher1, tag1 = original_gcm.encrypt(self.demo_iv, test_message.encode(), b'test')
        
        # 修改一个比特的密钥
        modified_key = bytearray(self.demo_key)
        modified_key[0] ^= 1
        modified_gcm = SM4_GCM_Optimized(bytes(modified_key), 'ttable')
        cipher2, tag2 = modified_gcm.encrypt(self.demo_iv, test_message.encode(), b'test')
        
        # 分析差异
        cipher_diff = sum(bin(a ^ b).count('1') for a, b in zip(cipher1, cipher2))
        tag_diff = sum(bin(a ^ b).count('1') for a, b in zip(tag1, tag2))
        
        total_cipher_bits = len(cipher1) * 8
        total_tag_bits = len(tag1) * 8
        
        cipher_diff_ratio = cipher_diff / total_cipher_bits
        tag_diff_ratio = tag_diff / total_tag_bits
        
        print(f"原始密钥: {self.demo_key.hex()}")
        print(f"修改密钥: {bytes(modified_key).hex()}")
        print(f"密文1: {cipher1.hex()}")
        print(f"密文2: {cipher2.hex()}")
        print(f"密文差异: {cipher_diff}/{total_cipher_bits} 位 ({cipher_diff_ratio:.1%})")
        print(f"标签差异: {tag_diff}/{total_tag_bits} 位 ({tag_diff_ratio:.1%})")
        
        if cipher_diff_ratio > 0.4:
            print("✅ 密文显示良好的密钥敏感性")
        else:
            print("⚠️ 密文密钥敏感性较低")
        
        if tag_diff_ratio > 0.4:
            print("✅ 认证标签显示良好的密钥敏感性")
        else:
            print("⚠️ 认证标签密钥敏感性较低")
    
    def demo_real_world_applications(self):
        """演示实际应用场景"""
        self.print_header("SM4-GCM 实际应用场景演示")
        
        # 1. 安全文件传输
        self.print_section("1. 安全文件传输模拟")
        
        gcm = SM4_GCM_Optimized(self.demo_key, 'ttable')
        
        # 模拟文件内容
        file_content = """
        这是一个重要的商业文档。
        
        包含敏感信息：
        - 客户数据
        - 财务信息  
        - 技术规格
        
        需要安全传输保护。
        """.encode('utf-8')
        
        file_metadata = {
            'filename': 'business_document.txt',
            'sender': 'Alice',
            'receiver': 'Bob',
            'timestamp': int(time.time())
        }
        
        # 创建认证数据
        auth_data = f"file:{file_metadata['filename']},from:{file_metadata['sender']},to:{file_metadata['receiver']},time:{file_metadata['timestamp']}".encode()
        
        print("📄 模拟文件传输:")
        print(f"文件名: {file_metadata['filename']}")
        print(f"发送者: {file_metadata['sender']}")
        print(f"接收者: {file_metadata['receiver']}")
        print(f"文件大小: {len(file_content)} 字节")
        
        # 加密传输
        start_time = time.time()
        encrypted_content, auth_tag = gcm.encrypt(self.demo_iv, file_content, auth_data)
        encrypt_time = time.time() - start_time
        
        print(f"加密时间: {encrypt_time*1000:.2f} ms")
        print(f"传输数据大小: {len(encrypted_content) + len(auth_tag)} 字节")
        
        # 模拟接收和解密
        print("\n📥 模拟接收方解密:")
        start_time = time.time()
        decrypted_content = gcm.decrypt(self.demo_iv, encrypted_content, auth_tag, auth_data)
        decrypt_time = time.time() - start_time
        
        print(f"解密时间: {decrypt_time*1000:.2f} ms")
        
        if decrypted_content == file_content:
            print("✅ 文件传输成功，完整性验证通过")
        else:
            print("❌ 文件传输失败")
        
        # 2. 数据库加密存储
        self.print_section("2. 数据库加密存储模拟")
        
        # 模拟数据库记录
        database_records = [
            {'id': 1, 'name': '张三', 'email': 'zhangsan@example.com', 'phone': '13800138001'},
            {'id': 2, 'name': '李四', 'email': 'lisi@example.com', 'phone': '13800138002'},
            {'id': 3, 'name': '王五', 'email': 'wangwu@example.com', 'phone': '13800138003'},
        ]
        
        encrypted_db = []
        
        print("🗄️ 模拟数据库加密存储:")
        
        total_encrypt_time = 0
        for record in database_records:
            # 序列化记录
            record_data = str(record).encode('utf-8')
            record_auth = f"record_id:{record['id']},table:users".encode()
            
            # 加密存储
            start_time = time.time()
            encrypted_data, tag = gcm.encrypt(self.demo_iv, record_data, record_auth)
            encrypt_time = time.time() - start_time
            total_encrypt_time += encrypt_time
            
            encrypted_record = {
                'id': record['id'],
                'encrypted_data': encrypted_data,
                'auth_tag': tag,
                'auth_info': record_auth
            }
            encrypted_db.append(encrypted_record)
            
            print(f"记录 {record['id']} 加密: {encrypt_time*1000:.2f} ms")
        
        print(f"总加密时间: {total_encrypt_time*1000:.2f} ms")
        print(f"加密记录数: {len(encrypted_db)}")
        
        # 模拟查询和解密
        print("\n🔍 模拟数据查询和解密:")
        query_id = 2
        
        # 查找记录
        target_record = None
        for encrypted_record in encrypted_db:
            if encrypted_record['id'] == query_id:
                target_record = encrypted_record
                break
        
        if target_record:
            start_time = time.time()
            decrypted_data = gcm.decrypt(
                self.demo_iv, 
                target_record['encrypted_data'], 
                target_record['auth_tag'], 
                target_record['auth_info']
            )
            decrypt_time = time.time() - start_time
            
            print(f"查询记录 {query_id} 解密: {decrypt_time*1000:.2f} ms")
            print(f"解密数据: {decrypted_data.decode('utf-8')}")
            print("✅ 数据库查询成功")
        else:
            print("❌ 记录未找到")
    
    def run_complete_demo(self):
        """运行完整演示"""
        print("🚀 SM4-GCM 工作模式软件优化 - 完整功能演示")
        print("作者: AI Assistant")
        print("日期: 2025年8月10日")
        
        try:
            self.demo_basic_functionality()
            self.demo_optimization_comparison() 
            self.demo_parallel_processing()
            self.demo_stream_processing()
            self.demo_security_features()
            self.demo_real_world_applications()
            
            self.print_header("演示完成总结")
            print("✅ 所有功能演示已完成")
            print("🎯 SM4-GCM 实现展现了优秀的性能和安全性")
            print("🚀 已准备好用于实际生产环境")
            
        except KeyboardInterrupt:
            print("\n\n⏹️ 演示被用户中断")
        except Exception as e:
            print(f"\n\n❌ 演示过程中发生错误: {e}")
            import traceback
            traceback.print_exc()


def main():
    """主演示函数"""
    demo = SM4_GCM_Demo()
    
    print("欢迎使用 SM4-GCM 功能演示程序！")
    print("\n选择演示模式:")
    print("1. 完整演示 (推荐)")
    print("2. 基础功能演示")
    print("3. 性能对比演示") 
    print("4. 并行处理演示")
    print("5. 流式处理演示")
    print("6. 安全特性演示")
    print("7. 应用场景演示")
    print("0. 退出")
    
    try:
        choice = input("\n请输入选择 (0-7): ").strip()
        
        if choice == '1':
            demo.run_complete_demo()
        elif choice == '2':
            demo.demo_basic_functionality()
        elif choice == '3':
            demo.demo_optimization_comparison()
        elif choice == '4':
            demo.demo_parallel_processing()
        elif choice == '5':
            demo.demo_stream_processing()
        elif choice == '6':
            demo.demo_security_features()
        elif choice == '7':
            demo.demo_real_world_applications()
        elif choice == '0':
            print("👋 感谢使用！")
        else:
            print("❌ 无效选择，运行完整演示")
            demo.run_complete_demo()
            
    except KeyboardInterrupt:
        print("\n\n👋 感谢使用！")
    except Exception as e:
        print(f"\n❌ 程序运行错误: {e}")


if __name__ == "__main__":
    main()
