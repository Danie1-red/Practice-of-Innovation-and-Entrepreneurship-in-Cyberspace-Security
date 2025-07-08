import cv2
import numpy as np
from PIL import Image
import os
from test import ImageWatermark

def create_test_images():
    """创建测试用的图像"""
    # 创建载体图像 (蓝色背景)
    cover = np.zeros((400, 600, 3), dtype=np.uint8)
    cover[:] = (255, 100, 100)  # BGR格式，蓝色背景
    cv2.imwrite('test_images/cover.jpg', cover)
    
    # 创建水印图像 (红色方块)
    watermark = np.zeros((100, 100, 3), dtype=np.uint8)
    watermark[:] = (0, 0, 255)  # 红色
    cv2.rectangle(watermark, (10, 10), (90, 90), (255, 255, 255), 2)
    cv2.imwrite('test_images/watermark.jpg', watermark)
    
    print("测试图像已创建在 test_images/ 目录下")

def test_visible_watermark():
    """测试可见水印功能"""
    print("\n=== 测试可见水印 ===")
    watermark_tool = ImageWatermark()
    
    try:
        watermark_tool.embed_watermark(
            'test_images/cover.jpg',
            'test_images/watermark.jpg', 
            'test_images/visible_watermarked.jpg',
            alpha=0.3
        )
        print("✓ 可见水印嵌入成功")
    except Exception as e:
        print(f"✗ 可见水印嵌入失败: {e}")

def test_lsb_watermark():
    """测试LSB隐形水印功能"""
    print("\n=== 测试LSB隐形水印 ===")
    watermark_tool = ImageWatermark()
    
    test_text = "Hello World 你好世界"
    
    try:
        # 嵌入LSB水印
        watermark_tool.embed_lsb_watermark(
            'test_images/cover.jpg',
            test_text,
            'test_images/lsb_watermarked.jpg'
        )
        print("✓ LSB水印嵌入成功")
        
        # 提取LSB水印
        extracted_text = watermark_tool.extract_lsb_watermark('test_images/lsb_watermarked.jpg')
        
        if extracted_text.strip() == test_text:
            print("✓ LSB水印提取成功，文本完全匹配")
        else:
            print(f"✗ LSB水印提取结果不匹配")
            print(f"原文本: '{test_text}'")
            print(f"提取文本: '{extracted_text.strip()}'")
            
    except Exception as e:
        print(f"✗ LSB水印测试失败: {e}")

def test_watermark_detection():
    """测试水印检测功能"""
    print("\n=== 测试水印检测 ===")
    watermark_tool = ImageWatermark()
    
    try:
        # 检测可见水印
        similarity = watermark_tool.detect_watermark(
            'test_images/cover.jpg',
            'test_images/visible_watermarked.jpg'
        )
        print(f"✓ 可见水印检测完成，相似度: {similarity:.4f}")
        
        # 检测LSB水印
        similarity_lsb = watermark_tool.detect_watermark(
            'test_images/cover.jpg', 
            'test_images/lsb_watermarked.jpg'
        )
        print(f"✓ LSB水印检测完成，相似度: {similarity_lsb:.4f}")
        
    except Exception as e:
        print(f"✗ 水印检测失败: {e}")

def run_all_tests():
    """运行所有测试"""
    print("开始运行水印工具测试...")
    
    # 创建测试目录
    os.makedirs('test_images', exist_ok=True)
    
    # 创建测试图像
    create_test_images()
    
    # 运行各项测试
    test_visible_watermark()
    test_lsb_watermark() 
    test_watermark_detection()
    
    print("\n=== 测试完成 ===")
    print("生成的文件:")
    for file in os.listdir('test_images'):
        print(f"  - test_images/{file}")

if __name__ == "__main__":
    run_all_tests()