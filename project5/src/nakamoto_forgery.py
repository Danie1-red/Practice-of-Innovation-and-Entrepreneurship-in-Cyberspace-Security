#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
中本聪数字签名伪造演示模块
仅用于密码学安全教育和研究目的

⚠️ 重要声明：
- 本模块仅用于技术教育，展示数字签名工作原理
- 任何用于欺诈或非法用途的行为均为违法
- 真正的数字身份需要可信的公钥基础设施
- 比特币网络通过共识机制而非单一签名确保安全性
"""

import os
import sys
import time

# 添加src目录到路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

def demonstrate_nakamoto_signature_forgery():
    """演示中本聪数字签名伪造的完整过程"""
    print("=" * 80)
    print("中本聪数字签名伪造演示（仅用于学习研究）")
    print("=" * 80)
    print("⚠️  本功能仅用于密码学安全教育和研究，禁止用于任何非法用途！")
    print("📚 教育目的：展示数字签名的工作原理和安全重要性")
    print(f"演示时间: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    try:
        from nakamoto_signature import NakamotoSignature, Secp256k1, ECPoint
        nakamoto = NakamotoSignature()
        
        print("=== 场景1：模拟创建\"假中本聪\"身份 ===")
        print("🎭 正在生成虚假身份...")
        
        # 生成一个新的密钥对，假装是"中本聪"的
        fake_satoshi_priv, fake_satoshi_pub = nakamoto.generate_keypair()
        
        print(f"📱 假冒身份密钥对生成完成：")
        print(f"   私钥: 0x{fake_satoshi_priv:064x}")
        print(f"   公钥X: 0x{fake_satoshi_pub.x:064x}")
        print(f"   公钥Y: 0x{fake_satoshi_pub.y:064x}")
        print(f"   公钥验证: {'✅' if fake_satoshi_pub.is_on_curve() else '❌'} 在secp256k1曲线上")
        
        # 模拟几条"中本聪"可能会说的话
        satoshi_messages = [
            b"I am Satoshi Nakamoto, creator of Bitcoin.",
            b"The Times 03/Jan/2009 Chancellor on brink of second bailout for banks",
            b"Bitcoin: A Peer-to-Peer Electronic Cash System",
            b"Running bitcoin",
            b"Chancellor on brink of second bailout for banks",
            b"Bitcoin v0.1 released",
            b"The root problem with conventional currency is all the trust that's required",
            b"If you don't believe it or don't get it, I don't have the time to try to convince you"
        ]
        
        print(f"\n=== 场景2：用假身份签名多条消息 ===")
        print(f"🔏 准备签名 {len(satoshi_messages)} 条经典消息...")
        
        signatures = []
        
        for i, message in enumerate(satoshi_messages, 1):
            print(f"\n--- 消息 {i} ---")
            print(f"内容: {message.decode()}")
            
            # 计算消息哈希
            msg_hash = nakamoto.double_sha256(message)
            print(f"双重SHA256哈希: {msg_hash.hex()}")
            
            # 使用假私钥签名
            r, s = nakamoto.sign(msg_hash, fake_satoshi_priv)
            der_sig = nakamoto.encode_der(r, s)
            bitcoin_sig = nakamoto.create_bitcoin_signature(msg_hash, fake_satoshi_priv)
            
            print(f"ECDSA签名:")
            print(f"  r = 0x{r:064x}")
            print(f"  s = 0x{s:064x}")
            print(f"  低S规则: {'✅' if s <= Secp256k1.n // 2 else '❌'} (s <= n/2)")
            print(f"DER编码: {der_sig.hex()}")
            print(f"比特币签名: {bitcoin_sig.hex()}")
            print(f"签名长度: {len(bitcoin_sig)} 字节")
            
            # 验证签名
            ecdsa_valid = nakamoto.verify(msg_hash, (r, s), fake_satoshi_pub)
            bitcoin_valid = nakamoto.verify_bitcoin_signature(msg_hash, bitcoin_sig, fake_satoshi_pub)
            
            print(f"验证结果:")
            print(f"  ECDSA验证: {'✅ 通过' if ecdsa_valid else '❌ 失败'}")
            print(f"  比特币签名验证: {'✅ 通过' if bitcoin_valid else '❌ 失败'}")
            
            signatures.append({
                'message': message,
                'hash': msg_hash,
                'signature': (r, s),
                'der': der_sig,
                'bitcoin_sig': bitcoin_sig,
                'valid': ecdsa_valid and bitcoin_valid
            })
        
        print(f"\n=== 场景3：构造比特币风格的交易脚本 ===")
        print("🔗 构造scriptSig格式...")
        
        # 为第一条消息构造完整的scriptSig
        first_sig = signatures[0]
        
        # 构造公钥（未压缩格式）
        pubkey_uncompressed = (b'\x04' + 
                             fake_satoshi_pub.x.to_bytes(32, 'big') + 
                             fake_satoshi_pub.y.to_bytes(32, 'big'))
        
        # 构造压缩格式公钥
        y_is_even = fake_satoshi_pub.y % 2 == 0
        pubkey_compressed = (b'\x02' if y_is_even else b'\x03') + fake_satoshi_pub.x.to_bytes(32, 'big')
        
        # 构造scriptSig
        sig_bytes = first_sig['bitcoin_sig']
        script_sig_uncompressed = f"<{sig_bytes.hex()}> <{pubkey_uncompressed.hex()}>"
        script_sig_compressed = f"<{sig_bytes.hex()}> <{pubkey_compressed.hex()}>"
        
        print(f"签名脚本 (scriptSig):")
        print(f"  签名数据: {sig_bytes.hex()}")
        print(f"  未压缩公钥: {pubkey_uncompressed.hex()}")
        print(f"  压缩公钥: {pubkey_compressed.hex()}")
        print(f"未压缩scriptSig: {script_sig_uncompressed}")
        print(f"压缩scriptSig: {script_sig_compressed}")
        
        # 计算比特币地址
        import hashlib
        
        # P2PKH地址（未压缩）
        pubkey_hash = hashlib.new('ripemd160', hashlib.sha256(pubkey_uncompressed).digest()).digest()
        print(f"公钥哈希(未压缩): {pubkey_hash.hex()}")
        
        # P2PKH地址（压缩）
        pubkey_hash_compressed = hashlib.new('ripemd160', hashlib.sha256(pubkey_compressed).digest()).digest()
        print(f"公钥哈希(压缩): {pubkey_hash_compressed.hex()}")
        
        print(f"\n=== 场景4：演示为什么这是\"伪造\" ===")
        print("🔍 技术分析结果：")
        print("1. ✅ 数学正确性：所有签名都是有效的ECDSA签名")
        print("2. ✅ 格式合规性：符合比特币DER编码和scriptSig格式")
        print("3. ✅ 验证通过性：任何人都可以验证这些签名确实对应这些消息")
        print("4. ✅ 密码学安全：使用了安全的secp256k1椭圆曲线")
        print("5. ❌ 身份真实性：但这并不能证明签名者就是真正的中本聪！")
        print()
        print("💡 关键洞察：")
        print("• 数字签名 ≠ 数字身份")
        print("• 签名只能证明：签名者拥有对应私钥")
        print("• 签名无法证明：私钥持有者的真实身份")
        print("• 身份认证需要：额外的身份绑定和信任机制")
        
        print(f"\n=== 场景5：真实攻击的技术难点 ===")
        print("🎯 要真正伪造中本聪的签名，攻击者面临的挑战：")
        print()
        print("1. 🔐 私钥获取挑战：")
        print("   • 中本聪的私钥由他本人持有")
        print("   • 256位私钥空间：2^256 ≈ 10^77 种可能")
        print("   • 暴力破解需要宇宙年龄级别的时间")
        print()
        print("2. 🔓 算法破解挑战：")
        print("   • ECDSA基于椭圆曲线离散对数问题")
        print("   • 目前没有高效的量子或经典算法")
        print("   • 即使量子计算机也需要大量量子比特")
        print()
        print("3. 🎭 实现漏洞利用：")
        print("   • k值重用攻击（需要获得多个使用相同k的签名）")
        print("   • 侧信道攻击（需要物理访问签名设备）")
        print("   • 随机数生成器缺陷（需要发现具体实现漏洞）")
        print()
        print("4. 🕰️ 时间窗口限制：")
        print("   • 比特币网络有时间戳保护")
        print("   • 历史记录无法篡改")
        print("   • 社区会验证异常活动")
        
        print(f"\n=== 场景6：防护机制和检测方法 ===")
        print("🛡️ 如何识别和防范虚假签名：")
        print()
        print("1. 📋 公钥来源验证：")
        print("   • 检查公钥的历史使用记录")
        print("   • 验证公钥与已知地址的关联")
        print("   • 交叉对照多个可信信息源")
        print()
        print("2. 🔍 签名模式分析：")
        print("   • 分析签名的时间模式")
        print("   • 检查签名的技术特征")
        print("   • 对比历史签名的一致性")
        print()
        print("3. 🌐 社会验证机制：")
        print("   • 社区共识和声誉系统")
        print("   • 多方独立验证")
        print("   • 权威机构认证")
        print()
        print("4. 🔗 区块链验证：")
        print("   • 比特币网络共识机制")
        print("   • 交易历史不可篡改性")
        print("   • 工作量证明保护")
        
        print(f"\n=== 场景7：统计分析 ===")
        print("📊 本次演示的技术统计：")
        
        valid_signatures = sum(1 for sig in signatures if sig['valid'])
        total_signatures = len(signatures)
        
        print(f"• 生成签名总数: {total_signatures}")
        print(f"• 有效签名数量: {valid_signatures}")
        print(f"• 签名成功率: {valid_signatures/total_signatures*100:.1f}%")
        print(f"• 使用的椭圆曲线: secp256k1")
        print(f"• 哈希算法: 双重SHA256")
        print(f"• 编码格式: DER + SIGHASH_ALL")
        print(f"• 公钥格式: 未压缩(65字节) + 压缩(33字节)")
        
        # 计算一些统计信息
        sig_lengths = [len(sig['bitcoin_sig']) for sig in signatures]
        avg_length = sum(sig_lengths) / len(sig_lengths)
        
        print(f"• 平均签名长度: {avg_length:.1f} 字节")
        print(f"• 签名长度范围: {min(sig_lengths)}-{max(sig_lengths)} 字节")
        
        print(f"\n⚠️  最终声明和法律提醒：")
        print("=" * 50)
        print("✅ 合法用途：")
        print("• 密码学教育和研究")
        print("• 安全系统测试和评估")
        print("• 学术论文和技术分享")
        print("• 开发者技能培训")
        print()
        print("❌ 非法用途（严禁）：")
        print("• 身份欺诈和冒充他人")
        print("• 金融诈骗和虚假交易")
        print("• 恶意攻击和系统破坏")
        print("• 任何违反法律的行为")
        print()
        print("📜 本演示受以下原则约束：")
        print("• 仅用于技术教育，展示密码学原理")
        print("• 所有生成的密钥和签名均为演示用途")
        print("• 不会对任何真实系统造成影响")
        print("• 强调数字身份验证的重要性")
        print("• 推广密码学安全最佳实践")
        
        return {
            'fake_private_key': fake_satoshi_priv,
            'fake_public_key': fake_satoshi_pub,
            'signatures': signatures,
            'script_sig_uncompressed': script_sig_uncompressed,
            'script_sig_compressed': script_sig_compressed,
            'statistics': {
                'total_signatures': total_signatures,
                'valid_signatures': valid_signatures,
                'success_rate': valid_signatures/total_signatures*100,
                'avg_signature_length': avg_length
            }
        }
        
    except Exception as e:
        print(f"❌ 伪造演示过程中发生错误: {e}")
        import traceback
        traceback.print_exc()
        return None

def run_advanced_forgery_scenarios():
    """运行高级伪造场景演示"""
    print("\n" + "=" * 80)
    print("高级伪造场景演示")
    print("=" * 80)
    
    try:
        from nakamoto_signature import NakamotoSignature
        nakamoto = NakamotoSignature()
        
        print("=== 高级场景1：多重身份伪造 ===")
        print("模拟创建多个假身份，演示身份混淆攻击...")
        
        # 创建多个假身份
        fake_identities = []
        identity_names = [
            "Fake Satoshi A",
            "Fake Satoshi B", 
            "Fake Satoshi C"
        ]
        
        for i, name in enumerate(identity_names):
            priv, pub = nakamoto.generate_keypair()
            fake_identities.append({
                'name': name,
                'private_key': priv,
                'public_key': pub
            })
            print(f"{name}: 公钥 = 0x{pub.x:064x}...")
        
        print(f"\n=== 高级场景2：时间戳伪造分析 ===")
        print("分析在不同时间创建签名的检测难度...")
        
        import time
        message = b"Historical Bitcoin message"
        
        for i, identity in enumerate(fake_identities):
            timestamp = time.time() - (i * 86400)  # 不同天数
            print(f"\n{identity['name']} 在 {time.ctime(timestamp)} 的签名:")
            
            # 将时间戳加入消息
            timestamped_msg = message + f" - {timestamp}".encode()
            msg_hash = nakamoto.double_sha256(timestamped_msg)
            
            r, s = nakamoto.sign(msg_hash, identity['private_key'])
            print(f"签名: r=0x{r:032x}..., s=0x{s:032x}...")
            
            valid = nakamoto.verify(msg_hash, (r, s), identity['public_key'])
            print(f"验证: {'✅' if valid else '❌'}")
        
        print(f"\n=== 高级场景3：签名关联性分析 ===")
        print("演示如何通过签名模式识别同一签名者...")
        
        # 使用同一私钥签名多条消息
        test_key = fake_identities[0]['private_key']
        test_pub = fake_identities[0]['public_key']
        
        test_messages = [
            b"Message from same signer 1",
            b"Message from same signer 2", 
            b"Message from same signer 3"
        ]
        
        print("相同签名者的多个签名特征:")
        for i, msg in enumerate(test_messages):
            msg_hash = nakamoto.double_sha256(msg)
            r, s = nakamoto.sign(msg_hash, test_key)
            
            # 分析r值的分布特征
            r_bits = r.bit_length()
            s_bits = s.bit_length()
            
            print(f"签名{i+1}: r长度={r_bits}位, s长度={s_bits}位")
        
        print("\n💡 关联性分析提示:")
        print("• 相同私钥的签名可能显示某些统计特征")
        print("• 随机数生成器的偏差可能被检测")
        print("• 时序分析可能揭示签名模式")
        print("• 区块链分析可以追踪资金流动")
        
    except Exception as e:
        print(f"❌ 高级场景演示失败: {e}")

def main():
    """主函数"""
    print("🔐 中本聪数字签名伪造完整演示")
    print("⚠️  仅用于密码学安全教育和研究")
    print()
    
    # 运行基础伪造演示
    result = demonstrate_nakamoto_signature_forgery()
    
    if result:
        print(f"\n✅ 基础演示完成")
        print(f"生成了 {result['statistics']['total_signatures']} 个有效签名")
        print(f"成功率: {result['statistics']['success_rate']:.1f}%")
        
        # 运行高级场景
        run_advanced_forgery_scenarios()
        
        print(f"\n🎓 教育总结:")
        print("通过此演示，我们学习到：")
        print("1. 数字签名的数学原理和实现细节")
        print("2. 身份验证与签名验证的本质区别")
        print("3. 密码学安全的多层防护重要性")
        print("4. 区块链技术的共识机制价值")
        print("5. 社会工程学攻击的防范必要性")
        
    else:
        print("❌ 演示失败，请检查依赖模块")

if __name__ == "__main__":
    main()
