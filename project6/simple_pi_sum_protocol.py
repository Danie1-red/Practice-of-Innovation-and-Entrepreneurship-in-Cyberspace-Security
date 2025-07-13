"""
DDH-based PI-Sum Protocol 的简化版本实现

这个版本使用更简单的加密方案，便于理解协议流程。
主要简化：
1. 使用简单的整数运算代替椭圆曲线
2. 使用异或运算模拟同态加密
3. 保留协议的核心逻辑和流程
"""

import hashlib
import secrets
import random
from typing import List, Tuple, Dict, Set


class SimpleHomomorphicEncryption:
    """简化的同态加密（仅用于演示协议流程）"""
    
    def __init__(self):
        self.secret_key = secrets.randbelow(2**32)
    
    def encrypt(self, plaintext: int) -> Tuple[int, int]:
        """简化加密：使用异或和随机数"""
        nonce = secrets.randbelow(2**32)
        # 简单的加密：plaintext ⊕ key ⊕ nonce
        # 实际实现中应该使用真正的同态加密
        return plaintext ^ self.secret_key ^ nonce, nonce
    
    def decrypt(self, ciphertext: Tuple[int, int]) -> int:
        """简化解密"""
        encrypted_value, nonce = ciphertext
        return encrypted_value ^ self.secret_key ^ nonce
    
    def add_encrypted(self, enc1: Tuple[int, int], enc2: Tuple[int, int]) -> Tuple[int, int]:
        """简化的同态加法"""
        # 解密后相加再加密（这不是真正的同态加密）
        val1 = self.decrypt(enc1)
        val2 = self.decrypt(enc2)
        return self.encrypt(val1 + val2)


class SimpleDDHGroup:
    """简化的 DDH 群（使用大整数模运算）"""
    
    def __init__(self):
        # 使用一个大素数作为模数
        self.p = 2**31 - 1  # 梅森素数
        self.g = 2  # 生成元
    
    def hash_to_element(self, identifier: str) -> int:
        """将标识符哈希到群元素"""
        hash_bytes = hashlib.sha256(identifier.encode()).digest()
        return int.from_bytes(hash_bytes[:4], 'big') % self.p
    
    def power(self, base: int, exponent: int) -> int:
        """计算模指数 base^exponent mod p"""
        return pow(base, exponent, self.p)


class SimpleParty1:
    """简化版参与方 P1"""
    
    def __init__(self, identifiers: List[str]):
        self.identifiers = set(identifiers)
        self.ddh_group = SimpleDDHGroup()
        self.k1 = secrets.randbelow(2**31)  # 私钥 k1
        self.encryption = None
        
    def round2_process(self, round1_data: List[Tuple[int, Tuple[int, int]]]) -> Tuple[List[Tuple[int, Tuple[int, int]]], List[int]]:
        """Round 2: 处理 P2 的数据"""
        print(f"P1 Round 2: 处理 {len(round1_data)} 个数据项")
        
        # 对每个单掩码元素应用第二次掩码
        double_masked_data = []
        for single_masked, encrypted_value in round1_data:
            # 双掩码：(H(w_j)^k2)^k1 = H(w_j)^(k1*k2)
            double_masked = self.ddh_group.power(single_masked, self.k1)
            double_masked_data.append((double_masked, encrypted_value))
        
        # 洗牌
        random.shuffle(double_masked_data)
        print(f"P1: 完成双掩码和洗牌")
        
        # 生成自己的单掩码标识符
        own_masked = []
        for identifier in self.identifiers:
            h_vi = self.ddh_group.hash_to_element(identifier)
            masked = self.ddh_group.power(h_vi, self.k1)
            own_masked.append(masked)
        
        random.shuffle(own_masked)
        print(f"P1: 生成 {len(own_masked)} 个单掩码标识符")
        
        return double_masked_data, own_masked
    
    def receive_result(self, intersection_size: int, encrypted_sum: Tuple[int, int]):
        """接收最终结果"""
        if self.encryption:
            sum_value = self.encryption.decrypt(encrypted_sum)
            print(f"\nP1 最终结果:")
            print(f"  交集大小: {intersection_size}")
            print(f"  交集值总和: {sum_value}")
            return intersection_size, sum_value
        return intersection_size, None


class SimpleParty2:
    """简化版参与方 P2"""
    
    def __init__(self, identifier_values: Dict[str, int]):
        self.identifier_values = identifier_values
        self.ddh_group = SimpleDDHGroup()
        self.k2 = secrets.randbelow(2**31)  # 私钥 k2
        self.encryption = SimpleHomomorphicEncryption()
        
    def round1_send(self) -> List[Tuple[int, Tuple[int, int]]]:
        """Round 1: 发送单掩码数据"""
        round1_data = []
        
        for identifier, value in self.identifier_values.items():
            # 单掩码：H(w_j)^k2
            h_wj = self.ddh_group.hash_to_element(identifier)
            single_masked = self.ddh_group.power(h_wj, self.k2)
            
            # 加密值
            encrypted_value = self.encryption.encrypt(value)
            
            round1_data.append((single_masked, encrypted_value))
        
        random.shuffle(round1_data)
        print(f"P2 Round 1: 发送 {len(round1_data)} 个单掩码数据")
        
        return round1_data
    
    def round3_compute(self, double_masked_p2: List[Tuple[int, Tuple[int, int]]], 
                      single_masked_p1: List[int]) -> Tuple[int, Tuple[int, int]]:
        """Round 3: 计算交集"""
        print(f"P2 Round 3: 计算交集")
        
        # 对 P1 的单掩码应用自己的掩码
        p1_double_masked = set()
        for single_masked in single_masked_p1:
            double_masked = self.ddh_group.power(single_masked, self.k2)
            p1_double_masked.add(double_masked)
        
        # 构建 P2 双掩码字典
        p2_double_masked_dict = {}
        for double_masked, encrypted_value in double_masked_p2:
            p2_double_masked_dict[double_masked] = encrypted_value
        
        # 计算交集
        intersection = p1_double_masked.intersection(set(p2_double_masked_dict.keys()))
        intersection_size = len(intersection)
        
        print(f"P2: 发现交集大小 {intersection_size}")
        
        # 同态求和
        if intersection_size > 0:
            encrypted_sum = None
            for masked_id in intersection:
                encrypted_value = p2_double_masked_dict[masked_id]
                if encrypted_sum is None:
                    encrypted_sum = encrypted_value
                else:
                    encrypted_sum = self.encryption.add_encrypted(encrypted_sum, encrypted_value)
        else:
            encrypted_sum = self.encryption.encrypt(0)
        
        return intersection_size, encrypted_sum


def run_simple_demo():
    """运行简化版协议演示"""
    
    print("=" * 50)
    print("简化版 DDH-based PI-Sum Protocol 演示")
    print("=" * 50)
    
    # 测试数据
    p1_identifiers = ["alice", "bob", "charlie", "david", "eve"]
    p2_identifier_values = {
        "bob": 100,      # 交集
        "charlie": 200,  # 交集  
        "frank": 150,    # 非交集
        "grace": 300,    # 非交集
        "david": 50      # 交集
    }
    
    print(f"P1 标识符: {p1_identifiers}")
    print(f"P2 标识符-值对: {p2_identifier_values}")
    
    # 计算真实交集用于验证
    real_intersection = set(p1_identifiers).intersection(set(p2_identifier_values.keys()))
    real_sum = sum(p2_identifier_values[uid] for uid in real_intersection)
    print(f"\n预期交集: {real_intersection}")
    print(f"预期交集大小: {len(real_intersection)}")
    print(f"预期交集值总和: {real_sum}")
    
    # 创建参与方
    party1 = SimpleParty1(p1_identifiers)
    party2 = SimpleParty2(p2_identifier_values)
    
    # P1 获取 P2 的加密器
    party1.encryption = party2.encryption
    
    print("\n协议执行:")
    
    # Round 1
    print("\nRound 1: P2 → P1")
    round1_data = party2.round1_send()
    
    # Round 2  
    print("\nRound 2: P1 → P2")
    double_masked_data, p1_masked = party1.round2_process(round1_data)
    
    # Round 3
    print("\nRound 3: P2 计算结果")
    intersection_size, encrypted_sum = party2.round3_compute(double_masked_data, p1_masked)
    
    # 最终结果
    print("\n最终结果接收:")
    final_size, final_sum = party1.receive_result(intersection_size, encrypted_sum)
    
    # 验证
    print(f"\n验证结果:")
    print(f"交集大小正确: {'✓' if final_size == len(real_intersection) else '✗'}")
    if final_sum is not None:
        print(f"交集求和正确: {'✓' if final_sum == real_sum else '✗'}")
    
    print("\n协议演示完成！")


if __name__ == "__main__":
    random.seed(42)
    run_simple_demo()
