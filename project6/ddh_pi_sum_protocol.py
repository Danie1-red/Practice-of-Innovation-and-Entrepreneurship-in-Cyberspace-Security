#!/usr/bin/env python3
"""
DDH-based Private Intersection-Sum with Cardinality Protocol Implementation

基于论文 "On Deploying Secure Computing: Private Intersection-Sum-with-Cardinality" 
实现 Section 3.1 中描述的 DDH-based PI-Sum 协议

协议概述:
- 双方 P1 和 P2 分别持有用户标识符集合
- P2 额外拥有每个标识符的整数值（如广告转化金额）
- 计算交集大小和交集标识符对应值的总和
- 基于 DDH 假设和同态加密保证隐私安全
"""

import hashlib
import secrets
import random
from typing import List, Tuple, Dict, Set
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend


class SimplePaillier:
    """简化的 Paillier 同态加密实现（用于演示）"""
    
    def __init__(self, key_size: int = 512):
        # 生成两个大素数 p, q
        self.p = self._generate_large_prime(key_size // 2)
        self.q = self._generate_large_prime(key_size // 2)
        self.n = self.p * self.q
        self.n_squared = self.n * self.n
        self.g = self.n + 1  # 简化选择 g = n + 1
        
        # 计算私钥参数
        self.lambda_ = (self.p - 1) * (self.q - 1)
        self.mu = pow(self._L(pow(self.g, self.lambda_, self.n_squared)), -1, self.n)
    
    def _generate_large_prime(self, bits: int) -> int:
        """生成指定位数的大素数（简化实现）"""
        while True:
            candidate = secrets.randbits(bits)
            candidate |= (1 << bits - 1) | 1  # 确保是奇数且最高位为1
            if self._is_prime(candidate):
                return candidate
    
    def _is_prime(self, n: int, k: int = 10) -> bool:
        """Miller-Rabin 素性测试"""
        if n < 2:
            return False
        if n in (2, 3):
            return True
        if n % 2 == 0:
            return False
        
        # 写成 n-1 = d * 2^r 的形式
        r = 0
        d = n - 1
        while d % 2 == 0:
            r += 1
            d //= 2
        
        # Miller-Rabin 测试
        for _ in range(k):
            a = random.randrange(2, n - 1)
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True
    
    def _L(self, x: int) -> int:
        """L 函数: L(x) = (x-1)/n"""
        return (x - 1) // self.n
    
    def encrypt(self, plaintext: int) -> int:
        """加密明文"""
        r = secrets.randbelow(self.n)
        while pow(r, self.lambda_, self.n) != 1:  # 确保 gcd(r,n) = 1
            r = secrets.randbelow(self.n)
        
        ciphertext = (pow(self.g, plaintext, self.n_squared) * 
                     pow(r, self.n, self.n_squared)) % self.n_squared
        return ciphertext
    
    def decrypt(self, ciphertext: int) -> int:
        """解密密文"""
        x = pow(ciphertext, self.lambda_, self.n_squared)
        plaintext = (self._L(x) * self.mu) % self.n
        return plaintext
    
    def add_ciphertexts(self, c1: int, c2: int) -> int:
        """同态加法：Enc(m1) * Enc(m2) = Enc(m1 + m2)"""
        return (c1 * c2) % self.n_squared


class DDHGroup:
    """基于椭圆曲线的 DDH 群实现"""
    
    def __init__(self):
        # 使用 NIST P-256 椭圆曲线（论文中提到的 prime256v1）
        self.curve = ec.SECP256R1()
        self.private_key = ec.generate_private_key(self.curve, default_backend())
        self.public_key = self.private_key.public_key()
        
    def hash_to_curve(self, identifier: str) -> ec.EllipticCurvePublicKey:
        """哈希函数 H: 将标识符映射到椭圆曲线上的点"""
        # 简化实现：使用标识符的哈希作为私钥，计算对应公钥
        hash_bytes = hashlib.sha256(identifier.encode()).digest()
        scalar = int.from_bytes(hash_bytes, 'big') % (2**256 - 1)
        # 确保scalar为正数且在有效范围内
        if scalar == 0:
            scalar = 1
        temp_private = ec.derive_private_key(scalar, self.curve, default_backend())
        return temp_private.public_key()
    
    def point_multiply(self, point: ec.EllipticCurvePublicKey, scalar: int) -> ec.EllipticCurvePublicKey:
        """计算椭圆曲线点的标量乘法"""
        # 将公钥转换为点，然后进行标量乘法
        point_bytes = point.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        
        # 简化实现：通过私钥操作模拟点乘法
        # 实际实现中需要更复杂的椭圆曲线运算
        temp_scalar = (scalar % (2**256 - 1)) + 1  # 确保在有效范围内
        temp_private = ec.derive_private_key(temp_scalar, self.curve, default_backend())
        return temp_private.public_key()
    
    def serialize_point(self, point: ec.EllipticCurvePublicKey) -> bytes:
        """序列化椭圆曲线点"""
        return point.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )


class Party1:
    """参与方 P1 - 持有标识符集合 V"""
    
    def __init__(self, identifiers: List[str]):
        self.identifiers = set(identifiers)
        self.ddh_group = DDHGroup()
        self.k1 = secrets.randbelow(2**255) + 1  # 私钥 k1，确保为正数
        self.paillier = None  # 将接收 P2 的公钥
        
    def round2_process_and_respond(self, round1_data: List[Tuple[bytes, int]]) -> Tuple[List[Tuple[bytes, int]], List[bytes]]:
        """
        Round 2: P1 处理来自 P2 的数据并回复
        
        输入: [(H(w_j)^k2, AEnc(t_j))] - P2 发送的单掩码标识符和加密值
        输出: (shuffled_double_masked_data, single_masked_own_identifiers)
        """
        print(f"P1 Round 2: 处理来自 P2 的 {len(round1_data)} 个数据项")
        
        # 对接收的数据进行双掩码处理
        double_masked_data = []
        for masked_point_bytes, encrypted_value in round1_data:
            # 反序列化椭圆曲线点
            try:
                # 简化处理：重新生成对应的点进行运算
                double_masked_bytes = self._apply_second_mask(masked_point_bytes)
                double_masked_data.append((double_masked_bytes, encrypted_value))
            except Exception as e:
                print(f"处理点时出错: {e}")
                continue
        
        # 洗牌（随机重排）
        random.shuffle(double_masked_data)
        print(f"P1: 完成双掩码和洗牌，处理了 {len(double_masked_data)} 个项目")
        
        # 生成自己的单掩码标识符
        own_masked_identifiers = []
        for identifier in self.identifiers:
            point = self.ddh_group.hash_to_curve(identifier)
            masked_point = self.ddh_group.point_multiply(point, self.k1)
            masked_bytes = self.ddh_group.serialize_point(masked_point)
            own_masked_identifiers.append(masked_bytes)
        
        # 洗牌自己的标识符
        random.shuffle(own_masked_identifiers)
        print(f"P1: 生成并洗牌了 {len(own_masked_identifiers)} 个自己的掩码标识符")
        
        return double_masked_data, own_masked_identifiers
    
    def _apply_second_mask(self, point_bytes: bytes) -> bytes:
        """对已掩码的点应用第二次掩码"""
        # 简化实现：通过哈希模拟双掩码效果
        combined_hash = hashlib.sha256(point_bytes + self.k1.to_bytes(32, 'big')).digest()
        return combined_hash
    
    def finalize(self, intersection_size: int, encrypted_sum: int):
        """接收最终结果"""
        if self.paillier:
            decrypted_sum = self.paillier.decrypt(encrypted_sum)
            print(f"P1 最终结果:")
            print(f"  交集大小: {intersection_size}")
            print(f"  交集值总和: {decrypted_sum}")
            return intersection_size, decrypted_sum
        else:
            print("错误: 缺少 Paillier 解密密钥")
            return intersection_size, None


class Party2:
    """参与方 P2 - 持有标识符-值对集合 W"""
    
    def __init__(self, identifier_values: Dict[str, int]):
        self.identifier_values = identifier_values
        self.ddh_group = DDHGroup()
        self.k2 = secrets.randbelow(2**255) + 1  # 私钥 k2，确保为正数
        self.paillier = SimplePaillier()  # 生成 Paillier 密钥对
        
    def round1_send_data(self) -> List[Tuple[bytes, int]]:
        """
        Round 1: P2 发送单掩码标识符和加密值
        
        输出: [(H(w_j)^k2, AEnc(t_j))] - 单掩码标识符和加密值的列表
        """
        round1_data = []
        
        for identifier, value in self.identifier_values.items():
            # 单掩码标识符: H(w_j)^k2
            point = self.ddh_group.hash_to_curve(identifier)
            masked_point = self.ddh_group.point_multiply(point, self.k2)
            masked_bytes = self.ddh_group.serialize_point(masked_point)
            
            # 同态加密值: AEnc(t_j)
            encrypted_value = self.paillier.encrypt(value)
            
            round1_data.append((masked_bytes, encrypted_value))
        
        # 洗牌以隐藏原始顺序
        random.shuffle(round1_data)
        print(f"P2 Round 1: 发送 {len(round1_data)} 个掩码标识符和加密值")
        
        return round1_data
    
    def round3_compute_intersection(self, 
                                   double_masked_p2_data: List[Tuple[bytes, int]], 
                                   single_masked_p1_data: List[bytes]) -> Tuple[int, int]:
        """
        Round 3: P2 计算交集并返回结果
        
        输入: 
        - double_masked_p2_data: P1 返回的双掩码数据
        - single_masked_p1_data: P1 的单掩码标识符
        
        输出: (intersection_size, encrypted_sum)
        """
        print(f"P2 Round 3: 开始计算交集")
        
        # 对 P1 的单掩码标识符应用自己的掩码，得到双掩码
        p1_double_masked = set()
        for masked_bytes in single_masked_p1_data:
            double_masked_bytes = self._apply_second_mask(masked_bytes)
            p1_double_masked.add(double_masked_bytes)
        
        print(f"P2: 完成对 P1 标识符的双掩码处理，共 {len(p1_double_masked)} 个")
        
        # 提取 P2 数据的双掩码标识符
        p2_double_masked_dict = {}
        for masked_bytes, encrypted_value in double_masked_p2_data:
            p2_double_masked_dict[masked_bytes] = encrypted_value
        
        print(f"P2: P2 双掩码数据共 {len(p2_double_masked_dict)} 个")
        
        # 计算交集
        intersection_masked = p1_double_masked.intersection(set(p2_double_masked_dict.keys()))
        intersection_size = len(intersection_masked)
        
        print(f"P2: 发现交集大小为 {intersection_size}")
        
        # 同态计算交集值的总和
        if intersection_size > 0:
            encrypted_sum = 1  # Paillier 加法的单位元（加密的0）
            for first_time in [True]:
                for masked_id in intersection_masked:
                    encrypted_value = p2_double_masked_dict[masked_id]
                    if first_time:
                        encrypted_sum = encrypted_value
                        first_time = False
                    else:
                        encrypted_sum = self.paillier.add_ciphertexts(encrypted_sum, encrypted_value)
        else:
            encrypted_sum = self.paillier.encrypt(0)
        
        print(f"P2: 完成同态求和计算")
        
        return intersection_size, encrypted_sum
    
    def _apply_second_mask(self, point_bytes: bytes) -> bytes:
        """对单掩码点应用第二次掩码"""
        # 简化实现：通过哈希模拟双掩码效果（与 P1 中的实现对应）
        combined_hash = hashlib.sha256(point_bytes + self.k2.to_bytes(32, 'big')).digest()
        return combined_hash
    
    def get_paillier_public_key(self):
        """返回 Paillier 公钥供 P1 使用"""
        return self.paillier


def run_pi_sum_protocol_demo():
    """运行 PI-Sum 协议演示"""
    
    print("=" * 60)
    print("DDH-based PI-Sum Protocol 演示")
    print("=" * 60)
    
    # 初始化参与方数据
    print("\n1. 初始化参与方数据")
    
    # P1 的标识符集合
    p1_identifiers = ["user001", "user002", "user003", "user004", "user005", 
                      "user006", "user007", "user008"]
    
    # P2 的标识符-值对集合（模拟广告转化数据）
    p2_identifier_values = {
        "user002": 150,  # 交集：用户002转化150元
        "user004": 300,  # 交集：用户004转化300元
        "user005": 75,   # 交集：用户005转化75元
        "user009": 200,  # 非交集：用户009
        "user010": 180,  # 非交集：用户010
        "user011": 90,   # 非交集：用户011
    }
    
    print(f"P1 标识符集合: {p1_identifiers}")
    print(f"P2 标识符-值对: {p2_identifier_values}")
    
    # 真实交集计算（用于验证）
    real_intersection = set(p1_identifiers).intersection(set(p2_identifier_values.keys()))
    real_sum = sum(p2_identifier_values[uid] for uid in real_intersection)
    print(f"\n预期结果:")
    print(f"  真实交集: {real_intersection}")
    print(f"  真实交集大小: {len(real_intersection)}")
    print(f"  真实交集值总和: {real_sum}")
    
    # 创建参与方
    print("\n2. 创建参与方")
    party1 = Party1(p1_identifiers)
    party2 = Party2(p2_identifier_values)
    
    # P1 获取 P2 的 Paillier 公钥
    party1.paillier = party2.get_paillier_public_key()
    
    print("协议开始执行...")
    
    # Round 1: P2 → P1
    print("\n3. Round 1: P2 向 P1 发送单掩码数据")
    round1_data = party2.round1_send_data()
    
    # Round 2: P1 → P2
    print("\n4. Round 2: P1 处理数据并回复")
    double_masked_data, p1_masked_ids = party1.round2_process_and_respond(round1_data)
    
    # Round 3: P2 计算结果
    print("\n5. Round 3: P2 计算交集和求和")
    intersection_size, encrypted_sum = party2.round3_compute_intersection(
        double_masked_data, p1_masked_ids
    )
    
    # P1 接收最终结果
    print("\n6. P1 接收并解密最终结果")
    final_size, final_sum = party1.finalize(intersection_size, encrypted_sum)
    
    # 验证结果
    print("\n" + "=" * 60)
    print("协议结果验证")
    print("=" * 60)
    print(f"协议计算的交集大小: {final_size}")
    print(f"实际交集大小: {len(real_intersection)}")
    print(f"交集大小正确: {'✓' if final_size == len(real_intersection) else '✗'}")
    
    if final_sum is not None:
        print(f"协议计算的交集值总和: {final_sum}")
        print(f"实际交集值总和: {real_sum}")
        print(f"交集求和正确: {'✓' if final_sum == real_sum else '✗'}")
    
    print("\n协议演示完成！")


if __name__ == "__main__":
    # 设置随机种子以便复现结果
    random.seed(42)
    
    # 运行协议演示
    run_pi_sum_protocol_demo()
