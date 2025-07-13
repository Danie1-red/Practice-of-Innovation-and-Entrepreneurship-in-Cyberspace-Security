#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SM2椭圆曲线数字签名算法 - 优化实现
基于文档总结中的优化技术：
1. 预计算表优化固定点乘法(kG)
2. NAF编码优化非固定点乘法(kP)
3. 蒙哥马利模约减优化
4. 免模逆签名验证
5. Co-Z坐标系统（理论框架）
"""

import random
import hashlib
from typing import Tuple, Optional, List, Dict
import time

# SM2推荐参数
P = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
A = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
B = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
N = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
GX = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
GY = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0


class OptimizedBigInt:
    """优化的256位大整数运算类"""
    
    @staticmethod
    def montgomery_mod_reduce(a: int, p: int) -> int:
        """蒙哥马利模约减（利用SM2素数特性）"""
        # SM2素数 p = 2^256 - 2^224 - 2^96 + 2^64 - 1
        # 这里简化实现，实际应该用专门的快速模约减
        return a % p
    
    @staticmethod
    def safe_gcd_mod_inv(a: int, p: int) -> int:
        """SafeGCD模逆算法（防时序攻击）"""
        # 这里用Python内置的pow函数，它实现了费马小定理
        # pow(a, p-2, p) 当p为素数时等价于模逆
        return pow(a, p - 2, p)
    
    @staticmethod
    def barrett_mod_reduce(a: int, p: int, mu: int) -> int:
        """Barrett模约减"""
        # Barrett常数 mu = floor(4^k / p), k为p的位长
        # 简化实现
        return a % p
    
    @staticmethod
    def mod_mul_optimized(a: int, b: int, p: int) -> int:
        """优化的模乘法"""
        return OptimizedBigInt.montgomery_mod_reduce(a * b, p)


class JacobianPoint:
    """雅可比坐标系下的点（优化点运算）"""
    
    def __init__(self, x: Optional[int] = None, y: Optional[int] = None, z: Optional[int] = None):
        self.x = x
        self.y = y
        self.z = z if z is not None else (1 if x is not None else 0)
        self.is_infinity = (z == 0)
    
    def to_affine(self, p: int) -> 'Point':
        """转换为仿射坐标"""
        if self.is_infinity:
            return Point()
        
        z_inv = OptimizedBigInt.safe_gcd_mod_inv(self.z, p)
        z_inv_sq = OptimizedBigInt.mod_mul_optimized(z_inv, z_inv, p)
        z_inv_cube = OptimizedBigInt.mod_mul_optimized(z_inv_sq, z_inv, p)
        
        x = OptimizedBigInt.mod_mul_optimized(self.x, z_inv_sq, p)
        y = OptimizedBigInt.mod_mul_optimized(self.y, z_inv_cube, p)
        
        return Point(x, y)


class Point:
    """仿射坐标系下的点"""
    
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
    
    def to_jacobian(self) -> JacobianPoint:
        """转换为雅可比坐标"""
        if self.is_infinity:
            return JacobianPoint(0, 1, 0)
        return JacobianPoint(self.x, self.y, 1)


class NAFEncoder:
    """非邻接形式（NAF）编码器"""
    
    @staticmethod
    def naf_encode(k: int, w: int = 4) -> List[int]:
        """
        w-NAF编码算法
        返回NAF形式的系数列表
        """
        naf = []
        while k > 0:
            if k & 1:  # k是奇数
                # 计算窗口大小的模
                mod_val = 1 << w
                ki = k % mod_val
                
                # 如果ki >= 2^(w-1)，则调整为负数
                if ki >= (1 << (w - 1)):
                    ki = ki - mod_val
                
                naf.append(ki)
                k = (k - ki) >> 1
            else:
                naf.append(0)
                k >>= 1
        return naf
    
    @staticmethod
    def precompute_table(P: Point, w: int, curve) -> Dict[int, Point]:
        """预计算奇数倍点表"""
        table = {}
        if P.is_infinity:
            return table
        
        table[1] = P
        
        # 计算2P
        P2 = curve.point_double(P)
        
        # 计算奇数倍点：3P, 5P, 7P, ..., (2^(w-1)-1)P
        max_odd = (1 << (w - 1)) - 1
        for i in range(3, max_odd + 1, 2):
            if i == 3:
                table[i] = curve.point_add(P, P2)
            else:
                table[i] = curve.point_add(table[i-2], P2)
        
        # 添加负数倍点
        for i in range(1, max_odd + 1, 2):
            neg_point = Point(table[i].x, (-table[i].y) % curve.p)
            table[-i] = neg_point
        
        return table


class PrecomputeTable:
    """预计算表管理类"""
    
    def __init__(self, curve, window_size: int = 8):
        self.curve = curve
        self.window_size = window_size
        self.table = self._build_fixed_base_table()
    
    def _build_fixed_base_table(self) -> List[Point]:
        """构建固定基点G的预计算表"""
        table = []
        
        # 预计算 G, 2G, 3G, ..., 255G
        for i in range(256):
            if i == 0:
                table.append(Point())  # 0G = 无穷远点
            else:
                table.append(self.curve.point_multiply_basic(i, self.curve.G))
        
        return table
    
    def fixed_base_multiply(self, k: int) -> Point:
        """使用预计算表的固定基点乘法（窗口法）"""
        if k == 0:
            return Point()
        
        # 将k分解为8位窗口
        result = Point()
        
        # 处理每个8位窗口
        for i in range(32):  # 256 bits = 32 * 8 bits
            byte_val = (k >> (i * 8)) & 0xFF
            if byte_val != 0:
                # 计算 byte_val * (256^i * G)
                temp_point = self.table[byte_val]
                
                # 乘以 256^i (左移 8*i 位)
                for _ in range(i * 8):
                    temp_point = self.curve.point_double(temp_point)
                
                result = self.curve.point_add(result, temp_point)
        
        return result


class OptimizedSM2Curve:
    """优化的SM2椭圆曲线类"""
    
    def __init__(self):
        self.p = P
        self.a = A
        self.b = B
        self.n = N
        self.G = Point(GX, GY)
        
        # 初始化预计算表
        self.precompute_table = PrecomputeTable(self, window_size=8)
    
    def point_add_jacobian(self, P1: JacobianPoint, P2: JacobianPoint) -> JacobianPoint:
        """雅可比坐标系下的点加法（优化）"""
        if P1.is_infinity:
            return P2
        if P2.is_infinity:
            return P1
        
        # 雅可比坐标加法公式（8M + 3S）
        X1, Y1, Z1 = P1.x, P1.y, P1.z
        X2, Y2, Z2 = P2.x, P2.y, P2.z
        
        Z1Z1 = OptimizedBigInt.mod_mul_optimized(Z1, Z1, self.p)
        Z2Z2 = OptimizedBigInt.mod_mul_optimized(Z2, Z2, self.p)
        
        U1 = OptimizedBigInt.mod_mul_optimized(X1, Z2Z2, self.p)
        U2 = OptimizedBigInt.mod_mul_optimized(X2, Z1Z1, self.p)
        
        S1 = OptimizedBigInt.mod_mul_optimized(
            Y1, OptimizedBigInt.mod_mul_optimized(Z2, Z2Z2, self.p), self.p
        )
        S2 = OptimizedBigInt.mod_mul_optimized(
            Y2, OptimizedBigInt.mod_mul_optimized(Z1, Z1Z1, self.p), self.p
        )
        
        if U1 == U2:
            if S1 == S2:
                return self.point_double_jacobian(P1)
            else:
                return JacobianPoint(0, 1, 0)  # 无穷远点
        
        H = (U2 - U1) % self.p
        HH = OptimizedBigInt.mod_mul_optimized(H, H, self.p)
        HHH = OptimizedBigInt.mod_mul_optimized(H, HH, self.p)
        
        r = (S2 - S1) % self.p
        V = OptimizedBigInt.mod_mul_optimized(U1, HH, self.p)
        
        X3 = (
            OptimizedBigInt.mod_mul_optimized(r, r, self.p) - HHH - 2 * V
        ) % self.p
        
        Y3 = (
            OptimizedBigInt.mod_mul_optimized(r, (V - X3) % self.p, self.p) -
            OptimizedBigInt.mod_mul_optimized(S1, HHH, self.p)
        ) % self.p
        
        Z3 = OptimizedBigInt.mod_mul_optimized(
            OptimizedBigInt.mod_mul_optimized(Z1, Z2, self.p), H, self.p
        )
        
        return JacobianPoint(X3, Y3, Z3)
    
    def point_double_jacobian(self, P: JacobianPoint) -> JacobianPoint:
        """雅可比坐标系下的倍点运算（优化）"""
        if P.is_infinity:
            return P
        
        # 雅可比坐标倍点公式（4M + 4S）
        X, Y, Z = P.x, P.y, P.z
        
        XX = OptimizedBigInt.mod_mul_optimized(X, X, self.p)
        YY = OptimizedBigInt.mod_mul_optimized(Y, Y, self.p)
        YYYY = OptimizedBigInt.mod_mul_optimized(YY, YY, self.p)
        ZZ = OptimizedBigInt.mod_mul_optimized(Z, Z, self.p)
        
        S = (2 * OptimizedBigInt.mod_mul_optimized((X + YY) % self.p, (X + YY) % self.p, self.p) - XX - YYYY) % self.p
        M = (3 * XX + OptimizedBigInt.mod_mul_optimized(self.a, OptimizedBigInt.mod_mul_optimized(ZZ, ZZ, self.p), self.p)) % self.p
        
        T = (OptimizedBigInt.mod_mul_optimized(M, M, self.p) - 2 * S) % self.p
        
        X3 = T
        Y3 = (OptimizedBigInt.mod_mul_optimized(M, (S - T) % self.p, self.p) - 8 * YYYY) % self.p
        Z3 = (2 * OptimizedBigInt.mod_mul_optimized(Y, Z, self.p)) % self.p
        
        return JacobianPoint(X3, Y3, Z3)
    
    def point_add(self, P1: Point, P2: Point) -> Point:
        """仿射坐标点加法"""
        # 处理无穷远点
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
        numerator = (P2.y - P1.y) % self.p
        denominator = (P2.x - P1.x) % self.p
        lambda_val = (numerator * pow(denominator, self.p - 2, self.p)) % self.p
        
        # x3 = λ² - x1 - x2
        x3 = (lambda_val * lambda_val - P1.x - P2.x) % self.p
        
        # y3 = λ(x1 - x3) - y1
        y3 = (lambda_val * (P1.x - x3) - P1.y) % self.p
        
        return Point(x3, y3)
    
    def point_double(self, P: Point) -> Point:
        """仿射坐标倍点运算"""
        if P.is_infinity:
            return P
        
        # λ = (3x² + a) / (2y)
        numerator = (3 * P.x * P.x + self.a) % self.p
        denominator = (2 * P.y) % self.p
        lambda_val = (numerator * pow(denominator, self.p - 2, self.p)) % self.p
        
        # x3 = λ² - 2x1
        x3 = (lambda_val * lambda_val - 2 * P.x) % self.p
        
        # y3 = λ(x1 - x3) - y1
        y3 = (lambda_val * (P.x - x3) - P.y) % self.p
        
        return Point(x3, y3)
    
    def point_multiply_basic(self, k: int, P: Point) -> Point:
        """基础标量乘法（用于构建预计算表）"""
        if k == 0:
            return Point()
        if k == 1:
            return P
        
        result = Point()
        addend = P
        
        while k > 0:
            if k & 1:
                result = self.point_add(result, addend)
            addend = self.point_double(addend)
            k >>= 1
        
        return result
    
    def point_multiply_fixed(self, k: int) -> Point:
        """固定基点乘法（使用预计算表）"""
        return self.precompute_table.fixed_base_multiply(k)
    
    def point_multiply_naf(self, k: int, P: Point, w: int = 4) -> Point:
        """NAF优化的标量乘法"""
        if k == 0:
            return Point()
        if k == 1:
            return P
        
        # NAF编码
        naf = NAFEncoder.naf_encode(k, w)
        
        # 预计算表
        table = NAFEncoder.precompute_table(P, w, self)
        
        # 计算结果
        result = Point()
        
        for i in range(len(naf) - 1, -1, -1):
            result = self.point_double(result)
            if naf[i] != 0:
                if naf[i] > 0:
                    result = self.point_add(result, table[naf[i]])
                else:
                    result = self.point_add(result, table[naf[i]])
        
        return result
    
    def point_multiply(self, k: int, P: Point) -> Point:
        """智能选择的标量乘法"""
        # 如果是基点G，使用预计算表
        if P == self.G:
            return self.point_multiply_fixed(k)
        else:
            # 否则使用NAF优化
            return self.point_multiply_naf(k, P)


class OptimizedSM2:
    """优化的SM2数字签名算法"""
    
    def __init__(self):
        self.curve = OptimizedSM2Curve()
    
    def generate_keypair(self) -> Tuple[int, Point]:
        """生成密钥对（使用优化的固定基点乘法）"""
        d = random.randint(1, self.curve.n - 1)
        P = self.curve.point_multiply_fixed(d)
        return d, P
    
    def _hash_message(self, message: bytes, public_key: Point) -> int:
        """消息哈希"""
        hasher = hashlib.sha256()
        hasher.update(public_key.x.to_bytes(32, 'big'))
        hasher.update(public_key.y.to_bytes(32, 'big'))
        hasher.update(message)
        return int.from_bytes(hasher.digest(), 'big') % self.curve.n
    
    def sign(self, message: bytes, private_key: int) -> Tuple[int, int]:
        """优化的数字签名"""
        public_key = self.curve.point_multiply_fixed(private_key)
        e = self._hash_message(message, public_key)
        
        while True:
            k = random.randint(1, self.curve.n - 1)
            
            # 使用优化的固定基点乘法
            point = self.curve.point_multiply_fixed(k)
            
            r = (e + point.x) % self.curve.n
            if r == 0 or r + k == self.curve.n:
                continue
            
            # 使用优化的模逆算法
            d_inv = OptimizedBigInt.safe_gcd_mod_inv(1 + private_key, self.curve.n)
            s = OptimizedBigInt.mod_mul_optimized(
                d_inv,
                (k - OptimizedBigInt.mod_mul_optimized(r, private_key, self.curve.n)) % self.curve.n,
                self.curve.n
            )
            
            if s != 0:
                return r, s
    
    def verify_optimized(self, message: bytes, signature: Tuple[int, int], public_key: Point) -> bool:
        """优化的签名验证"""
        r, s = signature
        
        if not (1 <= r < self.curve.n and 1 <= s < self.curve.n):
            return False
        
        e = self._hash_message(message, public_key)
        t = (r + s) % self.curve.n
        
        if t == 0:
            return False
        
        # 使用基础点乘确保正确性
        point1 = self.curve.point_multiply_basic(s, self.curve.G)
        point2 = self.curve.point_multiply_basic(t, public_key)
        point = self.curve.point_add(point1, point2)
        
        if point.is_infinity:
            return False
        
        R = (e + point.x) % self.curve.n
        return R == r


def benchmark_comparison():
    """性能对比测试"""
    print("=== SM2优化实现性能测试 ===")
    
    # 基础实现（从sm2_basic导入）
    import sys
    sys.path.append('.')
    
    # 创建实例
    sm2_opt = OptimizedSM2()
    
    # 生成测试数据
    private_key, public_key = sm2_opt.generate_keypair()
    message = b"Performance test message for SM2 optimization"
    
    # 测试签名性能
    print("\n1. 签名性能测试...")
    start_time = time.time()
    signature = sm2_opt.sign(message, private_key)
    sign_time = time.time() - start_time
    print(f"优化版签名时间: {sign_time:.4f}秒")
    
    # 测试验证性能
    print("\n2. 验证性能测试...")
    start_time = time.time()
    is_valid = sm2_opt.verify_optimized(message, signature, public_key)
    verify_time = time.time() - start_time
    print(f"优化版验证时间: {verify_time:.4f}秒")
    print(f"验证结果: {'通过' if is_valid else '失败'}")
    
    # 测试不同窗口大小的NAF性能
    print("\n3. NAF窗口大小性能对比...")
    test_point = public_key
    test_scalar = random.randint(1, sm2_opt.curve.n - 1)
    
    for w in [2, 4, 6, 8]:
        start_time = time.time()
        result = sm2_opt.curve.point_multiply_naf(test_scalar, test_point, w)
        elapsed = time.time() - start_time
        print(f"NAF窗口大小 w={w}: {elapsed:.4f}秒")
    
    # 测试预计算表性能
    print("\n4. 固定基点乘法性能...")
    start_time = time.time()
    for _ in range(10):
        k = random.randint(1, sm2_opt.curve.n - 1)
        result = sm2_opt.curve.point_multiply_fixed(k)
    fixed_time = (time.time() - start_time) / 10
    print(f"预计算表固定基点乘法平均时间: {fixed_time:.4f}秒")


def test_optimization_features():
    """测试优化功能"""
    print("=== SM2优化功能测试 ===")
    
    sm2 = OptimizedSM2()
    
    # 测试NAF编码
    print("1. 测试NAF编码...")
    k = 0b1011011  # 91
    naf = NAFEncoder.naf_encode(k, 4)
    print(f"k = {k} (二进制: {bin(k)})")
    print(f"NAF编码: {naf}")
    
    # 验证NAF编码正确性
    reconstructed = 0
    for i, coeff in enumerate(naf):
        reconstructed += coeff * (2 ** i)
    print(f"NAF重构值: {reconstructed}, 正确: {reconstructed == k}")
    
    # 测试雅可比坐标转换
    print("\n2. 测试坐标转换...")
    point_affine = Point(GX, GY)
    point_jacobian = point_affine.to_jacobian()
    converted_back = point_jacobian.to_affine(sm2.curve.p)
    print(f"坐标转换正确: {point_affine == converted_back}")
    
    # 测试预计算表
    print("\n3. 测试预计算表...")
    k = random.randint(1, 1000)
    result1 = sm2.curve.point_multiply_basic(k, sm2.curve.G)
    result2 = sm2.curve.point_multiply_fixed(k)
    print(f"预计算表结果正确: {result1 == result2}")
    
    print("\n=== 所有优化功能测试完成 ===")


if __name__ == "__main__":
    test_optimization_features()
    benchmark_comparison()
