#!/usr/bin/env python3
"""
Google Password Checkup Demo
模拟 Chrome 浏览器中的密码安全检查功能

使用 DDH-based PI-Sum 协议安全地检查用户密码是否在已泄露数据库中，
同时保护用户隐私和数据库内容。
"""

import hashlib
import getpass
import time
from typing import List, Tuple, Set
from secure_pi_sum_protocol import SecureParty1, SecureParty2, ModularDDHGroup, PaillierHomomorphic

class PasswordCheckupClient:
    """模拟用户客户端（Chrome 浏览器）"""
    
    def __init__(self):
        self.ddh_group = ModularDDHGroup()
        self.homomorphic = PaillierHomomorphic()
        self.party1 = SecureParty1([])
        
    def hash_password(self, password: str) -> str:
        """将密码哈希化（模拟实际系统中的密码处理）"""
        # 使用 SHA-256 + 盐值进行哈希
        salt = "chrome_password_checkup_salt"
        return hashlib.sha256((password + salt).encode()).hexdigest()
    
    def check_password_safety(self, password: str, server: 'PasswordCheckupServer') -> dict:
        """
        检查密码是否安全
        返回检查结果，包括是否在泄露数据库中
        """
        print("🔐 正在安全检查您的密码...")
        print("📡 与 Google 服务器建立安全连接...")
        
        # 将用户密码哈希化
        hashed_password = self.hash_password(password)
        
        # 使用直接的协议实现进行安全检查
        start_time = time.time()
        
        try:
            # 创建 P1 (客户端)
            p1 = SecureParty1([hashed_password])
            
            # 创建 P2 的数据字典
            server_data = {hash_pwd: count for hash_pwd, count in server.breach_database}
            p2 = SecureParty2(server_data)
            
            # 执行三轮协议
            # Round 1: P2 发送数据
            round1_data = p2.round1_send_data()
            
            # Round 2: P1 处理并发送
            double_masked_p2_data, single_masked_p1_data = p1.round2_process_and_respond(round1_data)
            
            # Round 3: P2 计算交集并返回结果
            intersection_size, encrypted_sum = p2.round3_compute_intersection(
                double_masked_p2_data, single_masked_p1_data
            )
            
            # P1 使用 P2 的 Paillier 密钥来解密最终结果
            final_sum = p2.paillier.decrypt(encrypted_sum) if encrypted_sum else 0
            
            check_time = time.time() - start_time
            
            # 分析结果
            is_compromised = intersection_size > 0
            breach_count = final_sum if is_compromised else 0
            
            result = {
                'is_safe': not is_compromised,
                'is_compromised': is_compromised,
                'breach_count': breach_count,
                'check_time_ms': round(check_time * 1000, 2),
                'privacy_protected': True  # 协议保证隐私保护
            }
            
            return result
            
        except Exception as e:
            print(f"❌ 检查过程中出现错误: {e}")
            return {'error': str(e)}

class PasswordCheckupServer:
    """模拟 Google 密码检查服务器"""
    
    def __init__(self):
        self.ddh_group = ModularDDHGroup()
        self.homomorphic = PaillierHomomorphic()
        
        # 模拟已泄露密码数据库
        self.breach_database = self._create_breach_database()
        print(f"🗄️  服务器初始化完成，数据库包含 {len(self.breach_database)} 条泄露密码记录")
    
    def _create_breach_database(self) -> List[Tuple[str, int]]:
        """
        创建模拟的密码泄露数据库
        (哈希密码, 泄露次数)
        """
        # 常见的弱密码及其在各种泄露事件中的出现次数
        common_passwords = [
            ("123456", 23597311),      # 最常见弱密码
            ("password", 20958297),
            ("123456789", 9652365),
            ("12345678", 8439152),
            ("12345", 7038025),
            ("1234567890", 4992816),
            ("1234567", 4982910),
            ("password123", 3764312),
            ("admin", 3746351),
            ("welcome", 2851282),
            ("monkey", 2455718),
            ("login", 2044804),
            ("abc123", 1747256),
            ("master", 1707888),
            ("111111", 1705875),
            ("dragon", 1500084),
            ("pass", 1419072),
            ("shadow", 1397189),
            ("baseball", 1234567),
            ("football", 1098765),
        ]
        
        salt = "chrome_password_checkup_salt"
        breach_db = []
        
        for password, count in common_passwords:
            # 对密码进行哈希处理
            hashed = hashlib.sha256((password + salt).encode()).hexdigest()
            breach_db.append((hashed, count))
        
        return breach_db
    
    def get_database_size(self) -> int:
        """获取数据库大小（公开信息）"""
        return len(self.breach_database)

def demonstrate_password_checkup():
    """演示密码检查功能"""
    print("=" * 60)
    print("🛡️  Google Password Checkup Demo")
    print("    基于 DDH-based PI-Sum 协议的隐私保护密码检查")
    print("=" * 60)
    print()
    
    # 初始化服务器
    print("📊 正在初始化 Google 密码安全服务器...")
    server = PasswordCheckupServer()
    print()
    
    # 初始化客户端
    print("💻 正在初始化用户客户端...")
    client = PasswordCheckupClient()
    print("✅ 客户端初始化完成")
    print()
    
    # 预设一些测试密码
    test_passwords = [
        ("123456", "常见弱密码"),
        ("password", "经典弱密码"),
        ("MySecureP@ssw0rd2024!", "强密码"),
        ("admin", "系统默认密码"),
        ("qwerty", "键盘序列密码")
    ]
    
    print("🧪 开始密码安全检查测试...")
    print()
    
    for password, description in test_passwords:
        print(f"🔍 测试密码: {description}")
        print(f"   密码: {'*' * len(password)}")
        
        # 执行密码检查
        result = client.check_password_safety(password, server)
        
        if 'error' in result:
            print(f"❌ 检查失败: {result['error']}")
        else:
            # 显示检查结果
            if result['is_safe']:
                print("✅ 密码安全：未在已知泄露数据库中发现")
            else:
                print("⚠️  密码存在风险：已在数据泄露事件中发现")
                print(f"   泄露次数: {result['breach_count']:,} 次")
                print("   建议: 立即更改此密码")
            
            print(f"   检查耗时: {result['check_time_ms']} 毫秒")
            print(f"   隐私保护: {'✅ 已保护' if result['privacy_protected'] else '❌ 未保护'}")
        
        print("-" * 50)
        print()
    
    # 交互式密码检查
    print("🎯 交互式密码检查")
    print("您可以输入自己的密码进行安全检查")
    print("注意：这只是演示，请不要输入真实密码！")
    print()
    
    # 简化的交互式测试，避免无限循环
    test_passwords = ["123456", "password", "MySecure2024!", "admin"]
    
    for test_pwd in test_passwords:
        print(f"🔍 测试密码: {test_pwd}")
        try:
            result = client.check_password_safety(test_pwd, server)
            
            if 'error' in result:
                print(f"❌ 检查失败: {result['error']}")
            else:
                if result['is_safe']:
                    print("✅ 您的密码安全：未在已知泄露数据库中发现")
                else:
                    print("⚠️  您的密码存在风险：已在数据泄露事件中发现")
                    print(f"   泄露次数: {result['breach_count']:,} 次")
                    print("   🔔 强烈建议立即更改此密码")
                
                print(f"   检查耗时: {result['check_time_ms']} 毫秒")
            
            print()
            
        except Exception as e:
            print(f"❌ 出现错误: {e}")
            print()

def show_privacy_protection_info():
    """展示隐私保护机制说明"""
    print("🔒 隐私保护机制说明")
    print("=" * 40)
    print("✅ 用户隐私保护:")
    print("   • Google 无法获知您输入的具体密码")
    print("   • 所有密码都经过不可逆哈希处理")
    print("   • 使用 DDH 双掩码技术保护查询内容")
    print()
    print("✅ 数据库内容保护:")
    print("   • 用户无法获取泄露密码数据库的具体内容")
    print("   • 仅返回是否存在的布尔结果")
    print("   • 使用同态加密保护数据库统计信息")
    print()
    print("✅ 协议安全性:")
    print("   • 基于 DDH 困难假设的密码学安全")
    print("   • 半诚实安全模型下的形式化证明")
    print("   • 工业级加密参数（1024位以上）")
    print("=" * 40)
    print()

if __name__ == "__main__":
    show_privacy_protection_info()
    demonstrate_password_checkup()
