from watermark import ImageWatermark
import os
from PIL import Image

def analyze_image_properties():
    """分析原始图像的属性"""
    if os.path.exists('test.png'):
        img = Image.open('test.png')
        print(f"原始图像信息:")
        print(f"  - 模式: {img.mode}")
        print(f"  - 尺寸: {img.size}")
        print(f"  - 格式: {img.format}")
        print(f"  - 文件大小: {os.path.getsize('test.png')} bytes")

def test_improved_watermark():
    """测试改进的水印功能"""
    print("=== 改进的LSB水印测试 ===")
    
    analyze_image_properties()
    
    watermark_tool = ImageWatermark()
    test_text = "Hello World 测试水印"
    
    # 嵌入水印
    watermark_tool.embed_lsb_watermark(
        'test.png',
        test_text,
        'improved_watermarked.png'
    )
    
    # 分析结果图像
    if os.path.exists('improved_watermarked.png'):
        img = Image.open('improved_watermarked.png')
        print(f"\n水印图像信息:")
        print(f"  - 模式: {img.mode}")
        print(f"  - 尺寸: {img.size}")
        print(f"  - 文件大小: {os.path.getsize('improved_watermarked.png')} bytes")
    
    # 提取水印
    extracted = watermark_tool.extract_lsb_watermark('improved_watermarked.png')
    
    # 检测水印
    similarity = watermark_tool.detect_watermark('test.png', 'improved_watermarked.png')
    
    print(f"\n测试结果:")
    print(f"  - 文本匹配: {'✓' if extracted == test_text else '✗'}")
    print(f"  - 图像相似度: {similarity:.6f}")

if __name__ == "__main__":
    test_improved_watermark()