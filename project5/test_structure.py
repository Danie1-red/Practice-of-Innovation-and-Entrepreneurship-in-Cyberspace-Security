#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
简单的结构验证测试
"""

import sys
import os

# 添加src目录到路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

def test_imports():
    """测试导入是否正常"""
    print("测试导入...")
    
    try:
        from sm2_basic import SM2 as BasicSM2
        print("✓ sm2_basic 导入成功")
    except ImportError as e:
        print(f"✗ sm2_basic 导入失败: {e}")
        return False
    
    try:
        from sm2_optimized import OptimizedSM2
        print("✓ sm2_optimized 导入成功")
    except ImportError as e:
        print(f"✗ sm2_optimized 导入失败: {e}")
        return False
    
    return True

def test_basic_functionality():
    """测试基本功能"""
    print("\n测试基本功能...")
    
    try:
        from sm2_basic import SM2 as BasicSM2
        from sm2_optimized import OptimizedSM2
        
        # 测试基础版本
        basic_sm2 = BasicSM2()
        private_key, public_key = basic_sm2.generate_keypair()
        message = b"Test message"
        signature = basic_sm2.sign(message, private_key)
        is_valid = basic_sm2.verify(message, signature, public_key)
        
        if is_valid:
            print("✓ 基础实现功能正常")
        else:
            print("✗ 基础实现验证失败")
            return False
        
        # 测试优化版本
        opt_sm2 = OptimizedSM2()
        is_valid_opt = opt_sm2.verify_optimized(message, signature, public_key)
        
        if is_valid_opt:
            print("✓ 优化实现功能正常")
        else:
            print("✗ 优化实现验证失败")
            return False
        
        return True
        
    except Exception as e:
        print(f"✗ 功能测试失败: {e}")
        return False

def check_file_structure():
    """检查文件结构"""
    print("检查文件结构...")
    
    expected_files = [
        'src/sm2_basic.py',
        'src/sm2_optimized.py',
        'src/__init__.py',
        'examples/demo.py',
        'tests/debug_verify.py',
        'docs/文档总结.md',
        'main.py',
        'README.md',
        '.gitignore'
    ]
    
    all_exist = True
    for file_path in expected_files:
        if os.path.exists(file_path):
            print(f"✓ {file_path}")
        else:
            print(f"✗ {file_path} 不存在")
            all_exist = False
    
    return all_exist

def main():
    """主函数"""
    print("=" * 50)
    print("SM2项目结构验证测试")
    print("=" * 50)
    
    # 检查文件结构
    structure_ok = check_file_structure()
    
    print("\n" + "=" * 50)
    
    # 测试导入
    import_ok = test_imports()
    
    # 测试功能
    if import_ok:
        function_ok = test_basic_functionality()
    else:
        function_ok = False
    
    print("\n" + "=" * 50)
    print("测试结果总结:")
    print(f"文件结构: {'✓' if structure_ok else '✗'}")
    print(f"模块导入: {'✓' if import_ok else '✗'}")
    print(f"基本功能: {'✓' if function_ok else '✗'}")
    
    if structure_ok and import_ok and function_ok:
        print("\n🎉 所有测试通过！项目结构整理成功。")
        return 0
    else:
        print("\n❌ 部分测试失败，请检查配置。")
        return 1

if __name__ == "__main__":
    exit(main())
