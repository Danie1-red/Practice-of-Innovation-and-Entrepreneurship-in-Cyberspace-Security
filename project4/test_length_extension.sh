#!/bin/bash

# SM3 Length Extension Attack Test Script
# SM3 长度扩展攻击测试脚本

echo "SM3 长度扩展攻击编译和测试"
echo "====================================="

# 编译长度扩展攻击程序
echo "正在编译长度扩展攻击程序..."
gcc -Wall -Wextra -O2 -std=c99 -o length_extension_attack length_extension_attack.c

if [ $? -eq 0 ]; then
    echo "✅ 编译成功"
    echo ""
    
    echo "执行长度扩展攻击演示:"
    echo "-------------------------------------"
    ./length_extension_attack
    
    echo ""
    echo "清理编译产物..."
    # 可选：删除可执行文件
    # rm -f length_extension_attack
    
    echo "✅ 测试完成"
else
    echo "❌ 编译失败"
    exit 1
fi
