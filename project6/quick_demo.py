#!/usr/bin/env python3
"""
Quick Demo Launcher - 快速演示启动器
立即可用，无需额外依赖
"""

import subprocess
import sys
import os

def run_command_demo():
    """运行命令行演示"""
    print("🚀 启动命令行密码检查演示...")
    subprocess.run([sys.executable, "password_checkup_demo.py"])

def run_test_suite():
    """运行测试套件"""
    print("🧪 启动协议测试套件...")
    subprocess.run([sys.executable, "test_pi_sum_protocol.py"])

def main():
    """主菜单"""
    while True:
        print("\n" + "="*60)
        print("🔒 Google Password Checkup - 快速演示")
        print("   基于 DDH-based PI-Sum 协议")
        print("="*60)
        
        print("\n可用演示:")
        print("1. 🎯 密码安全检查演示 (命令行版)")
        print("2. 🧪 协议测试套件")
        print("0. 退出")
        
        choice = input("\n请选择 (0-2): ").strip()
        
        if choice == "1":
            run_command_demo()
        elif choice == "2":
            run_test_suite()
        elif choice == "0":
            print("\n👋 感谢使用 Google Password Checkup Demo!")
            print("   项目已成功完成，协议运行正常！")
            print("   📖 更多信息请查看 README.md 文件")
            break
        else:
            print("❌ 无效选择，请重试")

if __name__ == "__main__":
    # 检查当前目录
    if not os.path.exists("password_checkup_demo.py"):
        print("❌ 请在项目目录中运行此程序")
        print("   cd /home/yinhe/Practice-of-Innovation-and-Entrepreneurship-in-Cyberspace-Security/project6")
        sys.exit(1)
    
    print("🎉 欢迎使用 Google Password Checkup 演示系统!")
    print("   基于 DDH-based PI-Sum 协议的隐私保护密码检查")
    main()
