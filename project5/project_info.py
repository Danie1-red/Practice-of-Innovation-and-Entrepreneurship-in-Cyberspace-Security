#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
项目信息
"""

PROJECT_INFO = {
    "name": "SM2椭圆曲线数字签名算法 - 软件实现与优化",
    "version": "1.0.0",
    "description": "基于《SM2算法软件实现技术总结》文档的完整实现项目",
    "author": "Project5 Team",
    "license": "MIT",
    "keywords": ["SM2", "椭圆曲线", "数字签名", "密码学", "优化"],
    "python_requires": ">=3.6",
    "dependencies": [],  # 仅使用Python标准库
    "structure": {
        "src/": "源代码目录",
        "src/sm2_basic.py": "SM2基础实现",
        "src/sm2_optimized.py": "SM2优化实现",
        "src/__init__.py": "Python包初始化",
        "examples/": "示例程序目录",
        "examples/demo.py": "性能对比演示",
        "tests/": "测试程序目录",
        "tests/debug_verify.py": "验证调试工具",
        "docs/": "文档目录",
        "docs/文档总结.md": "技术总结文档",
        "main.py": "主程序入口",
        "test_structure.py": "结构验证测试",
        "README.md": "项目说明文档",
        ".gitignore": "Git忽略文件配置"
    }
}

def print_project_info():
    """打印项目信息"""
    print("=" * 60)
    print(f"项目: {PROJECT_INFO['name']}")
    print(f"版本: {PROJECT_INFO['version']}")
    print(f"描述: {PROJECT_INFO['description']}")
    print(f"作者: {PROJECT_INFO['author']}")
    print(f"许可: {PROJECT_INFO['license']}")
    print("=" * 60)
    
    print("\n文件结构说明:")
    for path, description in PROJECT_INFO['structure'].items():
        print(f"  {path:<25} {description}")
    
    print(f"\nPython要求: {PROJECT_INFO['python_requires']}")
    print(f"外部依赖: {'无 (仅使用标准库)' if not PROJECT_INFO['dependencies'] else ', '.join(PROJECT_INFO['dependencies'])}")

if __name__ == "__main__":
    print_project_info()
