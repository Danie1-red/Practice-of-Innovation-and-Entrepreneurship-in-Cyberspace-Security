#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
中本聪数字签名实现 (Nakamoto Signature Scheme)
基于 ECDSA-secp256k1 实现比特币风格的数字签名

这个模块实现了:
1. secp256k1 椭圆曲线参数
2. ECDSA 签名和验证算法  
3. DER 编码格式
4. 比特币交易签名哈希
5. scriptSig 构造
6. 伪造签名攻击验证

⚠️ 教育用途：仅用于学习比特币签名原理和安全研究
"""

import hashlib
import secrets
import struct
from typing import Tuple, Optional

class Secp256k1:
    """secp256k1 椭圆曲线参数"""
    
    # 椭圆曲线方程: y² = x³ + 7 (mod p)
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    a = 0
    b = 7
    
    # 基点 G
    Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
    
    # 基点的阶
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    
    # 协同因子
    h = 1

class ECPoint:
    """椭圆曲线点类"""
    
    def __init__(self, x: Optional[int], y: Optional[int]):
        self.x = x
        self.y = y
        self.is_infinity = (x is None and y is None)
    
    def __eq__(self, other):
        if not isinstance(other, ECPoint):
            return False
        return self.x == other.x and self.y == other.y and self.is_infinity == other.is_infinity
    
    def __repr__(self):
        if self.is_infinity:
            return "ECPoint(∞)"
        return f"ECPoint({hex(self.x)}, {hex(self.y)})"
    
    @classmethod
    def infinity(cls):
        """无穷远点"""
        return cls(None, None)
    
    def is_on_curve(self) -> bool:
        """检查点是否在secp256k1曲线上"""
        if self.is_infinity:
            return True
        
        # y² = x³ + 7 (mod p)
        left = (self.y * self.y) % Secp256k1.p
        right = (self.x * self.x * self.x + Secp256k1.b) % Secp256k1.p
        return left == right

class NakamotoSignature:
    """中本聪数字签名实现类"""
    
    def __init__(self):
        self.curve = Secp256k1()
        self.G = ECPoint(Secp256k1.Gx, Secp256k1.Gy)
    
    def mod_inverse(self, a: int, m: int) -> int:
        """扩展欧几里得算法求模逆"""
        if a < 0:
            a = (a % m + m) % m
        
        # 扩展欧几里得算法
        g, x, _ = self._extended_gcd(a, m)
        if g != 1:
            raise ValueError("模逆不存在")
        return x % m
    
    def _extended_gcd(self, a: int, b: int) -> Tuple[int, int, int]:
        """扩展欧几里得算法"""
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = self._extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y
    
    def point_add(self, P: ECPoint, Q: ECPoint) -> ECPoint:
        """椭圆曲线点加法"""
        if P.is_infinity:
            return Q
        if Q.is_infinity:
            return P
        
        if P.x == Q.x:
            if P.y == Q.y:
                # 点倍加
                return self.point_double(P)
            else:
                # 相反的点，结果是无穷远点
                return ECPoint.infinity()
        
        # 一般情况的点加法
        slope = ((Q.y - P.y) * self.mod_inverse(Q.x - P.x, Secp256k1.p)) % Secp256k1.p
        x3 = (slope * slope - P.x - Q.x) % Secp256k1.p
        y3 = (slope * (P.x - x3) - P.y) % Secp256k1.p
        
        return ECPoint(x3, y3)
    
    def point_double(self, P: ECPoint) -> ECPoint:
        """椭圆曲线点倍加"""
        if P.is_infinity:
            return P
        
        if P.y == 0:
            return ECPoint.infinity()
        
        # 斜率计算: (3x² + a) / (2y)
        slope = ((3 * P.x * P.x + Secp256k1.a) * self.mod_inverse(2 * P.y, Secp256k1.p)) % Secp256k1.p
        x3 = (slope * slope - 2 * P.x) % Secp256k1.p
        y3 = (slope * (P.x - x3) - P.y) % Secp256k1.p
        
        return ECPoint(x3, y3)
    
    def scalar_mult(self, k: int, P: ECPoint) -> ECPoint:
        """标量乘法 k*P（双加法算法）"""
        if k == 0:
            return ECPoint.infinity()
        if k < 0:
            return self.scalar_mult(-k, ECPoint(P.x, (-P.y) % Secp256k1.p))
        
        result = ECPoint.infinity()
        addend = P
        
        while k:
            if k & 1:
                result = self.point_add(result, addend)
            addend = self.point_double(addend)
            k >>= 1
        
        return result
    
    def generate_keypair(self) -> Tuple[int, ECPoint]:
        """生成密钥对"""
        # 生成私钥 (1 <= d < n)
        private_key = secrets.randbelow(Secp256k1.n - 1) + 1
        
        # 计算公钥 Q = d*G
        public_key = self.scalar_mult(private_key, self.G)
        
        return private_key, public_key
    
    def double_sha256(self, data: bytes) -> bytes:
        """比特币使用的双重SHA256哈希"""
        return hashlib.sha256(hashlib.sha256(data).digest()).digest()
    
    def sign(self, message_hash: bytes, private_key: int) -> Tuple[int, int]:
        """ECDSA签名"""
        if len(message_hash) != 32:
            raise ValueError("消息哈希必须是32字节")
        
        # 将消息哈希转换为整数
        z = int.from_bytes(message_hash, 'big')
        
        while True:
            # 生成随机数k (1 <= k < n)
            k = secrets.randbelow(Secp256k1.n - 1) + 1
            
            # 计算点 (x1, y1) = k*G
            point = self.scalar_mult(k, self.G)
            
            # r = x1 mod n
            r = point.x % Secp256k1.n
            if r == 0:
                continue
                
            # s = k^(-1) * (z + r*d) mod n
            k_inv = self.mod_inverse(k, Secp256k1.n)
            s = (k_inv * (z + r * private_key)) % Secp256k1.n
            if s == 0:
                continue
            
            # 实施低S规则 (BIP 66)
            if s > Secp256k1.n // 2:
                s = Secp256k1.n - s
            
            return r, s
    
    def verify(self, message_hash: bytes, signature: Tuple[int, int], public_key: ECPoint) -> bool:
        """ECDSA验证"""
        if len(message_hash) != 32:
            raise ValueError("消息哈希必须是32字节")
        
        r, s = signature
        
        # 验证签名参数
        if not (1 <= r < Secp256k1.n and 1 <= s < Secp256k1.n):
            return False
        
        # 验证公钥
        if not public_key.is_on_curve():
            return False
        
        # 将消息哈希转换为整数
        z = int.from_bytes(message_hash, 'big')
        
        # 计算 w = s^(-1) mod n
        w = self.mod_inverse(s, Secp256k1.n)
        
        # 计算 u1 = z*w mod n, u2 = r*w mod n
        u1 = (z * w) % Secp256k1.n
        u2 = (r * w) % Secp256k1.n
        
        # 计算点 (x1, y1) = u1*G + u2*Q
        point1 = self.scalar_mult(u1, self.G)
        point2 = self.scalar_mult(u2, public_key)
        point = self.point_add(point1, point2)
        
        if point.is_infinity:
            return False
        
        # 验证 r ≡ x1 (mod n)
        return r == (point.x % Secp256k1.n)
    
    def encode_der(self, r: int, s: int) -> bytes:
        """将签名编码为DER格式"""
        def encode_integer(value: int) -> bytes:
            # 将整数转换为字节
            byte_length = (value.bit_length() + 7) // 8
            value_bytes = value.to_bytes(byte_length, 'big')
            
            # 如果最高位是1，需要添加0x00前缀
            if value_bytes[0] & 0x80:
                value_bytes = b'\x00' + value_bytes
            
            return b'\x02' + bytes([len(value_bytes)]) + value_bytes
        
        r_encoded = encode_integer(r)
        s_encoded = encode_integer(s)
        
        sequence = r_encoded + s_encoded
        return b'\x30' + bytes([len(sequence)]) + sequence
    
    def decode_der(self, der_bytes: bytes) -> Tuple[int, int]:
        """解码DER格式的签名"""
        if len(der_bytes) < 6:
            raise ValueError("DER数据太短")
        
        if der_bytes[0] != 0x30:
            raise ValueError("无效的DER序列标识")
        
        length = der_bytes[1]
        if length != len(der_bytes) - 2:
            raise ValueError("DER长度不匹配")
        
        pos = 2
        
        # 解码r
        if der_bytes[pos] != 0x02:
            raise ValueError("无效的r整数标识")
        pos += 1
        
        r_length = der_bytes[pos]
        pos += 1
        
        r = int.from_bytes(der_bytes[pos:pos + r_length], 'big')
        pos += r_length
        
        # 解码s
        if der_bytes[pos] != 0x02:
            raise ValueError("无效的s整数标识")
        pos += 1
        
        s_length = der_bytes[pos]
        pos += 1
        
        s = int.from_bytes(der_bytes[pos:pos + s_length], 'big')
        
        return r, s
    
    def create_bitcoin_signature(self, message_hash: bytes, private_key: int, sighash_type: int = 1) -> bytes:
        """创建比特币风格的签名（DER + SIGHASH）"""
        r, s = self.sign(message_hash, private_key)
        der_sig = self.encode_der(r, s)
        return der_sig + bytes([sighash_type])
    
    def verify_bitcoin_signature(self, message_hash: bytes, signature: bytes, public_key: ECPoint) -> bool:
        """验证比特币风格的签名"""
        if len(signature) < 2:
            return False
        
        # 分离DER签名和SIGHASH类型
        der_sig = signature[:-1]
        sighash_type = signature[-1]
        
        # 检查支持的SIGHASH类型
        supported_sighash = [0x01, 0x02, 0x03, 0x81, 0x82, 0x83]  # 常见的SIGHASH类型
        if sighash_type not in supported_sighash:
            print(f"⚠️ 不支持的SIGHASH类型: {hex(sighash_type)}")
            return False
        
        try:
            r, s = self.decode_der(der_sig)
            return self.verify(message_hash, (r, s), public_key)
        except Exception as e:
            print(f"签名解码失败: {e}")
            return False
    
    def demonstrate_nakamoto_signature(self):
        """演示中本聪数字签名的完整流程"""
        print("=" * 80)
        print("中本聪数字签名演示 (ECDSA-secp256k1)")
        print("=" * 80)
        
        # 1. 生成密钥对
        print("\n=== 1. 密钥生成 ===")
        private_key, public_key = self.generate_keypair()
        print(f"私钥 d: 0x{private_key:064x}")
        print(f"公钥 Q: ({hex(public_key.x)}, {hex(public_key.y)})")
        print(f"公钥验证: {'✅' if public_key.is_on_curve() else '❌'} 在secp256k1曲线上")
        
        # 2. 模拟比特币交易数据
        print("\n=== 2. 比特币交易构造 ===")
        transaction_data = b"Bitcoin transaction: Alice sends 1.5 BTC to Bob"
        print(f"交易数据: {transaction_data.decode()}")
        
        # 3. 计算交易哈希（double-SHA256）
        tx_hash = self.double_sha256(transaction_data)
        print(f"交易哈希: {tx_hash.hex()}")
        
        # 4. 生成数字签名
        print("\n=== 3. ECDSA签名生成 ===")
        r, s = self.sign(tx_hash, private_key)
        print(f"签名 r: 0x{r:064x}")
        print(f"签名 s: 0x{s:064x}")
        print(f"低S规则: {'✅' if s <= Secp256k1.n // 2 else '❌'} s <= n/2")
        
        # 5. DER编码
        print("\n=== 4. DER编码格式 ===")
        der_signature = self.encode_der(r, s)
        print(f"DER编码: {der_signature.hex()}")
        print(f"DER长度: {len(der_signature)} 字节")
        
        # 6. 比特币签名格式（DER + SIGHASH）
        print("\n=== 5. 比特币签名格式 ===")
        bitcoin_sig = self.create_bitcoin_signature(tx_hash, private_key)
        print(f"完整签名: {bitcoin_sig.hex()}")
        print(f"SIGHASH类型: 0x{bitcoin_sig[-1]:02x} (SIGHASH_ALL)")
        
        # 7. 签名验证
        print("\n=== 6. 签名验证 ===")
        is_valid = self.verify(tx_hash, (r, s), public_key)
        print(f"ECDSA验证: {'✅ 通过' if is_valid else '❌ 失败'}")
        
        bitcoin_valid = self.verify_bitcoin_signature(tx_hash, bitcoin_sig, public_key)
        print(f"比特币签名验证: {'✅ 通过' if bitcoin_valid else '❌ 失败'}")
        
        # 8. scriptSig构造
        print("\n=== 7. scriptSig构造 ===")
        # 公钥编码（简化，实际比特币使用压缩格式）
        pubkey_bytes = (b'\x04' + 
                       public_key.x.to_bytes(32, 'big') + 
                       public_key.y.to_bytes(32, 'big'))
        
        print(f"公钥编码: {pubkey_bytes.hex()}")
        print(f"scriptSig: <{bitcoin_sig.hex()}> <{pubkey_bytes.hex()}>")
        
        return {
            'private_key': private_key,
            'public_key': public_key,
            'transaction_hash': tx_hash,
            'signature': (r, s),
            'der_signature': der_signature,
            'bitcoin_signature': bitcoin_sig,
            'verification_result': is_valid
        }
    
    def demonstrate_signature_forgery_attack(self):
        """演示签名伪造攻击（教育目的）"""
        print("\n" + "=" * 80)
        print("中本聪签名伪造攻击演示 (教育目的)")
        print("=" * 80)
        print("⚠️ 此演示仅用于安全教育，展示密码学的重要性")
        
        # 攻击1: 弱随机数k重用攻击
        print("\n=== 攻击1: 随机数k重用攻击 ===")
        
        # 生成受害者密钥
        victim_privkey, victim_pubkey = self.generate_keypair()
        print(f"受害者私钥: 0x{victim_privkey:064x}")
        print(f"受害者公钥: ({hex(victim_pubkey.x)}, {hex(victim_pubkey.y)})")
        
        # 使用相同的k签名两个不同消息
        k = secrets.randbelow(Secp256k1.n - 1) + 1  # 相同的k
        print(f"重用的k值: 0x{k:064x}")
        
        msg1 = b"Message 1: I will pay Alice 1 BTC"
        msg2 = b"Message 2: I will pay Bob 2 BTC" 
        
        hash1 = self.double_sha256(msg1)
        hash2 = self.double_sha256(msg2)
        
        print(f"消息1: {msg1.decode()}")
        print(f"消息2: {msg2.decode()}")
        
        # 手动使用相同k进行签名（模拟错误实现）
        z1 = int.from_bytes(hash1, 'big')
        z2 = int.from_bytes(hash2, 'big')
        
        point = self.scalar_mult(k, self.G)
        r = point.x % Secp256k1.n
        
        k_inv = self.mod_inverse(k, Secp256k1.n)
        s1 = (k_inv * (z1 + r * victim_privkey)) % Secp256k1.n
        s2 = (k_inv * (z2 + r * victim_privkey)) % Secp256k1.n
        
        print(f"签名1: r={hex(r)}, s={hex(s1)}")
        print(f"签名2: r={hex(r)}, s={hex(s2)}")
        print(f"注意: 两个签名的r值相同！这是攻击线索")
        
        # 攻击：恢复私钥
        print("\n🎯 开始攻击...")
        print("根据ECDSA数学原理:")
        print("s1 = k^(-1) * (z1 + r*d) mod n")
        print("s2 = k^(-1) * (z2 + r*d) mod n")
        print("可得: k = (z1 - z2) / (s1 - s2) mod n")
        print("然后: d = (s1*k - z1) / r mod n")
        
        # 恢复k
        s_diff = (s1 - s2) % Secp256k1.n
        z_diff = (z1 - z2) % Secp256k1.n
        recovered_k = (z_diff * self.mod_inverse(s_diff, Secp256k1.n)) % Secp256k1.n
        
        # 恢复私钥
        recovered_privkey = ((s1 * recovered_k - z1) * self.mod_inverse(r, Secp256k1.n)) % Secp256k1.n
        
        print(f"\n🔓 恢复的k: 0x{recovered_k:064x}")
        print(f"🔓 恢复的私钥: 0x{recovered_privkey:064x}")
        print(f"💣 原始私钥: 0x{victim_privkey:064x}")
        
        if recovered_privkey == victim_privkey:
            print("✅ 攻击成功！私钥完全恢复")
        else:
            print("❌ 攻击失败")
        
        # 攻击2: 椭圆曲线参数攻击（理论）
        print("\n=== 攻击2: 无效曲线攻击（理论演示） ===")
        print("在实际攻击中，攻击者可能尝试:")
        print("1. 使用无效的椭圆曲线参数")
        print("2. 使用特殊构造的公钥点")
        print("3. 利用实现中的参数验证缺失")
        print("防护: 始终验证公钥在正确的曲线上")
        
        # 攻击3: 时序攻击（理论）
        print("\n=== 攻击3: 时序攻击风险 ===")
        print("侧信道攻击可能通过以下方式获取私钥信息:")
        print("1. 测量签名生成的时间")
        print("2. 分析电力消耗模式")
        print("3. 电磁辐射分析")
        print("防护: 使用常量时间算法实现")
        
        return {
            'attack_type': 'k_reuse',
            'victim_privkey': victim_privkey,
            'recovered_privkey': recovered_privkey,
            'attack_success': recovered_privkey == victim_privkey
        }

def test_nakamoto_signature():
    """测试中本聪数字签名实现"""
    print("🔐 中本聪数字签名系统测试")
    
    nakamoto = NakamotoSignature()
    
    # 基础功能测试
    print("\n--- 基础功能测试 ---")
    
    # 测试椭圆曲线点运算
    print("测试椭圆曲线点运算...")
    G = ECPoint(Secp256k1.Gx, Secp256k1.Gy)
    assert G.is_on_curve(), "基点不在曲线上"
    
    # 测试标量乘法
    point2 = nakamoto.scalar_mult(2, G)
    assert point2.is_on_curve(), "2G不在曲线上"
    
    # 测试点加法
    point3 = nakamoto.point_add(G, point2)
    point3_direct = nakamoto.scalar_mult(3, G)
    assert point3 == point3_direct, "点加法错误"
    
    print("✅ 椭圆曲线运算测试通过")
    
    # 测试ECDSA签名和验证
    print("测试ECDSA签名和验证...")
    private_key, public_key = nakamoto.generate_keypair()
    message = b"Test message for Nakamoto signature"
    msg_hash = nakamoto.double_sha256(message)
    
    signature = nakamoto.sign(msg_hash, private_key)
    is_valid = nakamoto.verify(msg_hash, signature, public_key)
    assert is_valid, "签名验证失败"
    
    print("✅ ECDSA签名验证测试通过")
    
    # 测试DER编码
    print("测试DER编码...")
    r, s = signature
    der_encoded = nakamoto.encode_der(r, s)
    r_decoded, s_decoded = nakamoto.decode_der(der_encoded)
    assert r == r_decoded and s == s_decoded, "DER编码解码失败"
    
    print("✅ DER编码测试通过")
    
    # 测试比特币签名格式
    print("测试比特币签名格式...")
    bitcoin_sig = nakamoto.create_bitcoin_signature(msg_hash, private_key)
    bitcoin_valid = nakamoto.verify_bitcoin_signature(msg_hash, bitcoin_sig, public_key)
    assert bitcoin_valid, "比特币签名验证失败"
    
    print("✅ 比特币签名格式测试通过")
    
    print("\n🎉 所有测试通过！中本聪数字签名实现正确")

def run_nakamoto_demo():
    """运行中本聪签名演示"""
    nakamoto = NakamotoSignature()
    
    # 运行签名演示
    demo_result = nakamoto.demonstrate_nakamoto_signature()
    
    # 运行攻击演示
    attack_result = nakamoto.demonstrate_signature_forgery_attack()
    
    return demo_result, attack_result

if __name__ == "__main__":
    # 运行测试
    test_nakamoto_signature()
    
    # 运行演示
    print("\n" + "=" * 100)
    print("开始中本聪数字签名完整演示")
    print("=" * 100)
    
    run_nakamoto_demo()
