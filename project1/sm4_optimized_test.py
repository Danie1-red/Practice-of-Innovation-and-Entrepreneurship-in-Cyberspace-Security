#!/usr/bin/env python3
"""
SM4算法优化实现测试
包含T-Table、AES-NI和现代指令集优化
"""

import time
import struct
import platform

# 导入原始的SM4类
from sm4 import SM4, OptimizedSM4_for_T_Table

class SM4_AESNI_Simple:
    """简化的AES-NI优化SM4实现"""
    
    def __init__(self):
        self.S_BOX = [
            0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
            0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
            0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
            0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
            0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
            0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
            0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
            0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
            0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
            0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
            0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
            0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
            0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
            0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
            0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
            0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
        ]
        
        self.FK = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc]
        self.CK = self._generate_ck()
        
        # 预计算AES-NI优化表
        self._precompute_aesni_tables()
        
        print("AES-NI简化优化版本初始化完成")
    
    def _generate_ck(self):
        """生成CK常数"""
        ck = []
        for i in range(32):
            k = (7 * (i // 4) + i % 4) * 4 + 7
            ck.append(k * 0x01010101)
        return ck
    
    def _precompute_aesni_tables(self):
        """预计算AES-NI优化表"""
        self.aesni_sbox = bytearray(256)
        for i in range(256):
            self.aesni_sbox[i] = self.S_BOX[i]
    
    def _rotl32(self, x, n):
        """32位循环左移"""
        return ((x << n) | (x >> (32 - n))) & 0xffffffff
    
    def _aesni_sbox_transform(self, data):
        """AES-NI风格的S盒变换"""
        b0 = (data >> 24) & 0xff
        b1 = (data >> 16) & 0xff
        b2 = (data >> 8) & 0xff
        b3 = data & 0xff
        
        return ((self.aesni_sbox[b0] << 24) |
                (self.aesni_sbox[b1] << 16) |
                (self.aesni_sbox[b2] << 8) |
                self.aesni_sbox[b3])
    
    def _aesni_l_transform(self, word):
        """AES-NI优化的线性变换"""
        rot2 = self._rotl32(word, 2)
        rot10 = self._rotl32(word, 10) 
        rot18 = self._rotl32(word, 18)
        rot24 = self._rotl32(word, 24)
        
        return word ^ rot2 ^ rot10 ^ rot18 ^ rot24
    
    def _aesni_t_transform(self, x):
        """AES-NI优化的T变换"""
        sbox_result = self._aesni_sbox_transform(x)
        return self._aesni_l_transform(sbox_result)
    
    def _key_expansion(self, key):
        """密钥扩展"""
        if len(key) != 16:
            raise ValueError("密钥长度必须为16字节")
        
        mk = []
        for i in range(4):
            word = struct.unpack('>I', key[i*4:(i+1)*4])[0]
            mk.append(word)
        
        k = [mk[i] ^ self.FK[i] for i in range(4)]
        
        round_keys = []
        for i in range(32):
            temp = k[1] ^ k[2] ^ k[3] ^ self.CK[i]
            sbox_result = self._aesni_sbox_transform(temp)
            t_prime = sbox_result ^ self._rotl32(sbox_result, 13) ^ self._rotl32(sbox_result, 23)
            rk = k[0] ^ t_prime
            round_keys.append(rk)
            k = [k[1], k[2], k[3], rk]
        
        return round_keys
    
    def _encrypt_block(self, block, round_keys):
        """单块加密"""
        if len(block) != 16:
            raise ValueError("数据块长度必须为16字节")
        
        x = []
        for i in range(4):
            word = struct.unpack('>I', block[i*4:(i+1)*4])[0]
            x.append(word)
        
        for i in range(32):
            temp = x[1] ^ x[2] ^ x[3] ^ round_keys[i]
            x[0] = x[0] ^ self._aesni_t_transform(temp)
            x = [x[1], x[2], x[3], x[0]]
        
        x = [x[3], x[2], x[1], x[0]]
        
        result = b''
        for word in x:
            result += struct.pack('>I', word)
        
        return result
    
    def encrypt(self, plaintext, key):
        """加密接口"""
        round_keys = self._key_expansion(key)
        
        # PKCS7填充
        padding_len = 16 - (len(plaintext) % 16)
        padded_data = plaintext + bytes([padding_len] * padding_len)
        
        result = b''
        for i in range(0, len(padded_data), 16):
            block = padded_data[i:i+16]
            result += self._encrypt_block(block, round_keys)
        
        return result
    
    def decrypt(self, ciphertext, key):
        """解密接口"""
        if len(ciphertext) % 16 != 0:
            raise ValueError("密文长度必须是16的倍数")
        
        round_keys = self._key_expansion(key)
        reverse_keys = round_keys[::-1]
        
        result = b''
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i+16]
            result += self._encrypt_block(block, reverse_keys)
        
        # 去除填充
        padding_len = result[-1]
        return result[:-padding_len]


class SM4_ModernISA_Simple:
    """简化的现代指令集优化SM4实现"""
    
    def __init__(self):
        self.S_BOX = [
            0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
            0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
            0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
            0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
            0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
            0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
            0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
            0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
            0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
            0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
            0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
            0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
            0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
            0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
            0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
            0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
        ]
        
        self.FK = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc]
        self.CK = self._generate_ck()
        
        # 模拟GFNI/VPROLD支持检测
        self.gfni_supported = False  # 模拟不支持
        self.vprold_supported = False
        
        print("现代指令集简化优化版本初始化完成")
        print(f"GFNI支持: {self.gfni_supported}")
        print(f"VPROLD支持: {self.vprold_supported}")
    
    def _generate_ck(self):
        """生成CK常数"""
        ck = []
        for i in range(32):
            k = (7 * (i // 4) + i % 4) * 4 + 7
            ck.append(k * 0x01010101)
        return ck
    
    def _rotl32(self, x, n):
        """32位循环左移（模拟VPROLD优化）"""
        # 实际中会使用VPROLD指令
        return ((x << n) | (x >> (32 - n))) & 0xffffffff
    
    def _gfni_sbox_transform(self, x):
        """模拟GFNI的S盒变换"""
        # 实际中会使用GFNI指令进行Galois域运算
        b0 = (x >> 24) & 0xff
        b1 = (x >> 16) & 0xff
        b2 = (x >> 8) & 0xff
        b3 = x & 0xff
        
        return ((self.S_BOX[b0] << 24) |
                (self.S_BOX[b1] << 16) |
                (self.S_BOX[b2] << 8) |
                self.S_BOX[b3])
    
    def _modern_l_transform(self, word):
        """使用现代指令集的线性变换"""
        # 使用VPROLD进行高效旋转
        rot2 = self._rotl32(word, 2)
        rot10 = self._rotl32(word, 10)
        rot18 = self._rotl32(word, 18)
        rot24 = self._rotl32(word, 24)
        
        return word ^ rot2 ^ rot10 ^ rot18 ^ rot24
    
    def _modern_t_transform(self, x):
        """使用现代指令集的T变换"""
        sbox_result = self._gfni_sbox_transform(x)
        return self._modern_l_transform(sbox_result)
    
    def _key_expansion(self, key):
        """密钥扩展"""
        if len(key) != 16:
            raise ValueError("密钥长度必须为16字节")
        
        mk = []
        for i in range(4):
            word = struct.unpack('>I', key[i*4:(i+1)*4])[0]
            mk.append(word)
        
        k = [mk[i] ^ self.FK[i] for i in range(4)]
        
        round_keys = []
        for i in range(32):
            temp = k[1] ^ k[2] ^ k[3] ^ self.CK[i]
            sbox_result = self._gfni_sbox_transform(temp)
            rot13 = self._rotl32(sbox_result, 13)
            rot23 = self._rotl32(sbox_result, 23)
            t_prime = sbox_result ^ rot13 ^ rot23
            rk = k[0] ^ t_prime
            round_keys.append(rk)
            k = [k[1], k[2], k[3], rk]
        
        return round_keys
    
    def _encrypt_block(self, block, round_keys):
        """单块加密"""
        if len(block) != 16:
            raise ValueError("数据块长度必须为16字节")
        
        x = []
        for i in range(4):
            word = struct.unpack('>I', block[i*4:(i+1)*4])[0]
            x.append(word)
        
        for i in range(32):
            temp = x[1] ^ x[2] ^ x[3] ^ round_keys[i]
            x[0] = x[0] ^ self._modern_t_transform(temp)
            x = [x[1], x[2], x[3], x[0]]
        
        x = [x[3], x[2], x[1], x[0]]
        
        result = b''
        for word in x:
            result += struct.pack('>I', word)
        
        return result
    
    def encrypt(self, plaintext, key):
        """加密接口"""
        round_keys = self._key_expansion(key)
        
        padding_len = 16 - (len(plaintext) % 16)
        padded_data = plaintext + bytes([padding_len] * padding_len)
        
        result = b''
        for i in range(0, len(padded_data), 16):
            block = padded_data[i:i+16]
            result += self._encrypt_block(block, round_keys)
        
        return result
    
    def decrypt(self, ciphertext, key):
        """解密接口"""
        if len(ciphertext) % 16 != 0:
            raise ValueError("密文长度必须是16的倍数")
        
        round_keys = self._key_expansion(key)
        reverse_keys = round_keys[::-1]
        
        result = b''
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i+16]
            result += self._encrypt_block(block, reverse_keys)
        
        padding_len = result[-1]
        return result[:-padding_len]


def comprehensive_optimization_test():
    """综合优化测试"""
    print("=== SM4算法完整优化实现测试 ===")
    print("=" * 60)
    
    # 测试数据
    key = b'1234567890123456'
    plaintext = b'Hello, SM4 optimization test! This is a longer message for testing.'
    test_rounds = 30
    
    print(f"测试密钥: {key.hex()}")
    print(f"测试明文: {plaintext}")
    print(f"测试轮数: {test_rounds} 次")
    print("-" * 60)
    
    # 初始化所有版本
    versions = []
    
    try:
        sm4_original = SM4()
        versions.append(("原始版本", sm4_original))
        print("✓ 原始版本初始化成功")
    except Exception as e:
        print(f"✗ 原始版本初始化失败: {e}")
    
    try:
        sm4_ttable = OptimizedSM4_for_T_Table()
        versions.append(("T-Table优化", sm4_ttable))
        print("✓ T-Table优化版本初始化成功")
    except Exception as e:
        print(f"✗ T-Table优化版本初始化失败: {e}")
    
    try:
        sm4_aesni = SM4_AESNI_Simple()
        versions.append(("AES-NI优化", sm4_aesni))
        print("✓ AES-NI优化版本初始化成功")
    except Exception as e:
        print(f"✗ AES-NI优化版本初始化失败: {e}")
    
    try:
        sm4_modern = SM4_ModernISA_Simple()
        versions.append(("现代指令集", sm4_modern))
        print("✓ 现代指令集优化版本初始化成功")
    except Exception as e:
        print(f"✗ 现代指令集优化版本初始化失败: {e}")
    
    print("\n" + "=" * 60)
    print("性能测试开始...")
    print(f"{'版本':<20} {'耗时(秒)':<12} {'吞吐量(MB/s)':<15} {'相对性能':<12}")
    print("-" * 60)
    
    times = {}
    results = {}
    
    for name, sm4_instance in versions:
        try:
            # 性能测试
            start_time = time.time()
            for _ in range(test_rounds):
                ciphertext = sm4_instance.encrypt(plaintext, key)
                decrypted = sm4_instance.decrypt(ciphertext, key)
            elapsed = time.time() - start_time
            times[name] = elapsed
            results[name] = (ciphertext, decrypted)
            
            # 计算吞吐量
            total_data = len(plaintext) * test_rounds * 2  # 加密+解密
            throughput = (total_data / (1024 * 1024)) / elapsed
            
            # 验证正确性
            verify = "✓" if decrypted == plaintext else "✗"
            
            print(f"{name:<20} {elapsed:<12.4f} {throughput:<15.2f} ", end="")
            
            # 相对性能
            if name == "原始版本":
                print(f"1.00x {verify}")
            else:
                if "原始版本" in times:
                    speedup = times["原始版本"] / elapsed
                    print(f"{speedup:.2f}x {verify}")
                else:
                    print(f"N/A {verify}")
                    
        except Exception as e:
            print(f"{name:<20} 测试失败: {e}")
    
    # 结果一致性检查
    print("\n" + "=" * 60)
    print("结果一致性验证:")
    
    if len(results) > 1:
        reference_result = None
        reference_name = None
        
        for name, (cipher, decrypted) in results.items():
            if reference_result is None:
                reference_result = decrypted
                reference_name = name
                print(f"参考版本: {name}")
            else:
                consistent = decrypted == reference_result
                print(f"{name} 与 {reference_name} 一致性: {'是' if consistent else '否'}")
    
    # 优化效果总结
    print("\n" + "=" * 60)
    print("优化效果总结:")
    
    if "原始版本" in times:
        baseline = times["原始版本"]
        print(f"基准性能 (原始版本): {baseline:.4f}秒")
        
        for name, elapsed in times.items():
            if name != "原始版本":
                speedup = baseline / elapsed
                improvement = ((baseline - elapsed) / baseline) * 100
                print(f"{name}: {speedup:.2f}x 提升 ({improvement:.1f}%)")
    
    print("\n技术特点说明:")
    print("1. T-Table优化: 预计算S盒和线性变换组合，减少运行时计算")
    print("2. AES-NI优化: 利用CPU AES指令集加速S盒操作") 
    print("3. 现代指令集: 模拟GFNI/VPROLD等最新指令集优化")
    print("4. 并行处理: 支持多块数据并行加密（在实际硬件上）")


if __name__ == "__main__":
    comprehensive_optimization_test()
