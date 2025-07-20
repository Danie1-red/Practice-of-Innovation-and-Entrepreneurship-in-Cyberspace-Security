#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SM2椭圆曲线数字签名算法 - 基础实现
基于文档总结中的三层架构设计：
1. 底层大数运算
2. 中层椭圆曲线点运算  
3. 上层协议实现
"""

import random
import hashlib
from typing import Tuple, Optional

# SM2推荐参数 (256位椭圆曲线)
P = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF  # 有限域特征
A = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC  # 椭圆曲线参数a
B = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93  # 椭圆曲线参数b
N = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123  # 基点的阶
GX = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7  # 基点G的x坐标
GY = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0  # 基点G的y坐标


class BigInt:
    """256位大整数运算类"""
    
    @staticmethod
    def mod_add(a: int, b: int, p: int) -> int:
        """模加法"""
        return (a + b) % p
    
    @staticmethod
    def mod_sub(a: int, b: int, p: int) -> int:
        """模减法"""
        return (a - b) % p
    
    @staticmethod
    def mod_mul(a: int, b: int, p: int) -> int:
        """模乘法"""
        return (a * b) % p
    
    @staticmethod
    def mod_inv(a: int, p: int) -> int:
        """扩展欧几里得算法求模逆"""
        def extended_gcd(a, b):
            if a == 0:
                return b, 0, 1
            gcd, x1, y1 = extended_gcd(b % a, a)
            x = y1 - (b // a) * x1
            y = x1
            return gcd, x, y
        
        gcd, x, _ = extended_gcd(a % p, p)
        if gcd != 1:
            raise ValueError("模逆不存在")
        return (x % p + p) % p
    
    @staticmethod
    def mod_pow(base: int, exp: int, p: int) -> int:
        """快速模幂运算"""
        return pow(base, exp, p)


class Point:
    """椭圆曲线上的点"""
    
    def __init__(self, x: Optional[int] = None, y: Optional[int] = None):
        self.x = x
        self.y = y
        self.is_infinity = (x is None and y is None)
    
    def __eq__(self, other):
        if self.is_infinity and other.is_infinity:
            return True
        if self.is_infinity or other.is_infinity:
            return False
        return self.x == other.x and self.y == other.y
    
    def __str__(self):
        if self.is_infinity:
            return "Point(∞)"
        return f"Point({hex(self.x)}, {hex(self.y)})"


class SM2Curve:
    """SM2椭圆曲线运算类"""
    
    def __init__(self):
        self.p = P
        self.a = A
        self.b = B
        self.n = N
        self.G = Point(GX, GY)
    
    def is_on_curve(self, point: Point) -> bool:
        """验证点是否在曲线上"""
        if point.is_infinity:
            return True
        
        x, y = point.x, point.y
        left = BigInt.mod_mul(y, y, self.p)
        right = BigInt.mod_add(
            BigInt.mod_add(
                BigInt.mod_mul(BigInt.mod_mul(x, x, self.p), x, self.p),
                BigInt.mod_mul(self.a, x, self.p), 
                self.p
            ),
            self.b,
            self.p
        )
        return left == right
    
    def point_add(self, P1: Point, P2: Point) -> Point:
        """椭圆曲线点加运算"""
        if P1.is_infinity:
            return P2
        if P2.is_infinity:
            return P1
        
        # 相同点，执行倍点运算
        if P1 == P2:
            return self.point_double(P1)
        
        # 如果x坐标相同但y坐标不同，结果为无穷远点
        if P1.x == P2.x:
            return Point()  # 无穷远点
        
        # 一般情况的点加
        # λ = (y2 - y1) / (x2 - x1)
        numerator = BigInt.mod_sub(P2.y, P1.y, self.p)
        denominator = BigInt.mod_sub(P2.x, P1.x, self.p)
        lambda_val = BigInt.mod_mul(numerator, BigInt.mod_inv(denominator, self.p), self.p)
        
        # x3 = λ² - x1 - x2
        x3 = BigInt.mod_sub(
            BigInt.mod_sub(
                BigInt.mod_mul(lambda_val, lambda_val, self.p),
                P1.x,
                self.p
            ),
            P2.x,
            self.p
        )
        
        # y3 = λ(x1 - x3) - y1
        y3 = BigInt.mod_sub(
            BigInt.mod_mul(lambda_val, BigInt.mod_sub(P1.x, x3, self.p), self.p),
            P1.y,
            self.p
        )
        
        return Point(x3, y3)
    
    def point_double(self, P: Point) -> Point:
        """椭圆曲线倍点运算"""
        if P.is_infinity:
            return P
        
        # λ = (3x² + a) / (2y)
        numerator = BigInt.mod_add(
            BigInt.mod_mul(3, BigInt.mod_mul(P.x, P.x, self.p), self.p),
            self.a,
            self.p
        )
        denominator = BigInt.mod_mul(2, P.y, self.p)
        lambda_val = BigInt.mod_mul(numerator, BigInt.mod_inv(denominator, self.p), self.p)
        
        # x3 = λ² - 2x1
        x3 = BigInt.mod_sub(
            BigInt.mod_mul(lambda_val, lambda_val, self.p),
            BigInt.mod_mul(2, P.x, self.p),
            self.p
        )
        
        # y3 = λ(x1 - x3) - y1
        y3 = BigInt.mod_sub(
            BigInt.mod_mul(lambda_val, BigInt.mod_sub(P.x, x3, self.p), self.p),
            P.y,
            self.p
        )
        
        return Point(x3, y3)
    
    def point_multiply(self, k: int, P: Point) -> Point:
        """标量乘法：kP（二进制展开法）"""
        if k == 0:
            return Point()  # 无穷远点
        if k == 1:
            return P
        
        result = Point()  # 无穷远点
        addend = P
        
        while k > 0:
            if k & 1:  # 如果当前位为1
                result = self.point_add(result, addend)
            addend = self.point_double(addend)
            k >>= 1
        
        return result
    
    def multiply(self, k: int, P: Point) -> Point:
        """别名方法，调用point_multiply"""
        return self.point_multiply(k, P)


class SM2:
    """SM2数字签名算法"""
    
    def __init__(self):
        self.curve = SM2Curve()
    
    def generate_keypair(self) -> Tuple[int, Point]:
        """生成密钥对"""
        # 私钥：随机选择 d ∈ [1, n-1]
        d = random.randint(1, self.curve.n - 1)
        
        # 公钥：P = dG
        P = self.curve.point_multiply(d, self.curve.G)
        
        return d, P
    
    def _hash_message(self, message: bytes, public_key: Point) -> int:
        """SM3哈希函数简化实现（这里用SHA-256代替）"""
        # 实际应该使用SM3，这里简化用SHA-256
        hasher = hashlib.sha256()
        
        # 添加公钥信息
        hasher.update(public_key.x.to_bytes(32, 'big'))
        hasher.update(public_key.y.to_bytes(32, 'big'))
        
        # 添加消息
        hasher.update(message)
        
        # 返回哈希值作为整数
        return int.from_bytes(hasher.digest(), 'big') % self.curve.n
    
    def sign(self, message: bytes, private_key: int) -> Tuple[int, int]:
        """数字签名"""
        # 计算公钥
        public_key = self.curve.point_multiply(private_key, self.curve.G)
        
        # 计算消息哈希
        e = self._hash_message(message, public_key)
        
        while True:
            # 生成随机数 k ∈ [1, n-1]
            k = random.randint(1, self.curve.n - 1)
            
            # 计算点 (x1, y1) = kG
            point = self.curve.point_multiply(k, self.curve.G)
            
            # r = (e + x1) mod n
            r = (e + point.x) % self.curve.n
            if r == 0 or r + k == self.curve.n:
                continue
            
            # s = (1 + d)^(-1) * (k - r * d) mod n
            d_inv = BigInt.mod_inv(1 + private_key, self.curve.n)
            s = BigInt.mod_mul(
                d_inv,
                BigInt.mod_sub(k, BigInt.mod_mul(r, private_key, self.curve.n), self.curve.n),
                self.curve.n
            )
            
            if s != 0:
                return r, s
    
    def sign_with_k(self, message: str, private_key: int, k: int) -> Tuple[int, int]:
        """使用指定的k值进行签名（仅用于测试）"""
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        # 计算公钥
        public_key = self.curve.point_multiply(private_key, self.curve.G)
        
        # 计算消息哈希
        e = self._hash_message(message, public_key)
        
        # 计算椭圆曲线点
        point = self.curve.point_multiply(k, self.curve.G)
        x1 = point.x
        
        # 计算r
        r = (e + x1) % self.curve.n
        if r == 0 or (r + k) % self.curve.n == 0:
            raise ValueError("Invalid k value")
        
        # 计算s
        d_inv = BigInt.mod_inv(1 + private_key, self.curve.n)
        s = (d_inv * (k - r * private_key)) % self.curve.n
        if s == 0:
            raise ValueError("Invalid signature")
        
        return (r, s)
    
    def verify(self, message: bytes, signature: Tuple[int, int], public_key: Point) -> bool:
        """签名验证"""
        r, s = signature
        
        # 验证签名参数范围
        if not (1 <= r < self.curve.n and 1 <= s < self.curve.n):
            return False
        
        # 计算消息哈希
        e = self._hash_message(message, public_key)
        
        # t = (r + s) mod n
        t = (r + s) % self.curve.n
        if t == 0:
            return False
        
        # 计算点 (x1, y1) = sG + tP
        point1 = self.curve.point_multiply(s, self.curve.G)
        point2 = self.curve.point_multiply(t, public_key)
        point = self.curve.point_add(point1, point2)
        
        if point.is_infinity:
            return False
        
        # 验证 R = (e + x1) mod n
        R = (e + point.x) % self.curve.n
        return R == r


def test_sm2_basic():
    """测试SM2基础实现"""
    print("=== SM2基础实现测试 ===")
    
    # 创建SM2实例
    sm2 = SM2()
    
    # 生成密钥对
    print("1. 生成密钥对...")
    private_key, public_key = sm2.generate_keypair()
    print(f"私钥: {hex(private_key)}")
    print(f"公钥: {public_key}")
    
    # 验证公钥在曲线上
    print(f"公钥在曲线上: {sm2.curve.is_on_curve(public_key)}")
    
    # 数字签名
    message = b"Hello SM2!"
    print(f"\n2. 对消息签名: {message}")
    signature = sm2.sign(message, private_key)
    print(f"签名: r={hex(signature[0])}, s={hex(signature[1])}")
    
    # 签名验证
    print("\n3. 验证签名...")
    is_valid = sm2.verify(message, signature, public_key)
    print(f"签名验证结果: {'通过' if is_valid else '失败'}")
    
    # 测试错误消息
    print("\n4. 测试错误消息...")
    wrong_message = b"Wrong message"
    is_valid_wrong = sm2.verify(wrong_message, signature, public_key)
    print(f"错误消息验证结果: {'通过' if is_valid_wrong else '失败'}")


if __name__ == "__main__":
    test_sm2_basic()
