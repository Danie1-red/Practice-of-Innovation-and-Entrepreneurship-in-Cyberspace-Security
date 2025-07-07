import cv2
import numpy as np
from PIL import Image
import argparse

class ImageWatermark:
    def __init__(self):
        pass
    
    def embed_watermark(self, cover_image_path, watermark_image_path, output_path, alpha=0.3):
        """
        在载体图像中嵌入水印
        
        Args:
            cover_image_path: 载体图像路径
            watermark_image_path: 水印图像路径  
            output_path: 输出图像路径
            alpha: 水印透明度 (0-1)
        """
        # 读取载体图像和水印图像
        cover = cv2.imread(cover_image_path)
        watermark = cv2.imread(watermark_image_path)
        
        if cover is None or watermark is None:
            raise ValueError("无法读取图像文件")
        
        # 调整水印大小以适应载体图像
        h, w = cover.shape[:2]
        watermark = cv2.resize(watermark, (w//4, h//4))
        
        # 计算水印位置（右下角）
        wh, ww = watermark.shape[:2]
        start_h = h - wh - 10
        start_w = w - ww - 10
        
        # 创建输出图像副本
        watermarked = cover.copy()
        
        # 在指定区域嵌入水印
        roi = watermarked[start_h:start_h+wh, start_w:start_w+ww]
        watermarked[start_h:start_h+wh, start_w:start_w+ww] = cv2.addWeighted(
            roi, 1-alpha, watermark, alpha, 0
        )
        
        # 保存结果
        cv2.imwrite(output_path, watermarked)
        print(f"水印已嵌入并保存到: {output_path}")
        
        return watermarked
    
    def embed_lsb_watermark(self, cover_image_path, watermark_text, output_path):
        """
        使用LSB算法嵌入文本水印，保持图像原始格式
        
        Args:
            cover_image_path: 载体图像路径
            watermark_text: 要嵌入的文本水印
            output_path: 输出图像路径
        """
        # 读取载体图像，保持原始格式
        img = Image.open(cover_image_path)
        original_mode = img.mode
        
        # 如果是RGBA，分离透明通道
        if img.mode == 'RGBA':
            # 保存透明通道
            alpha_channel = img.split()[-1]
            # 转换为RGB进行水印处理
            img = img.convert('RGB')
        elif img.mode != 'RGB':
            img = img.convert('RGB')
            
        pixels = np.array(img)
        
        # 将文本转换为UTF-8字节，然后转换为二进制
        text_bytes = watermark_text.encode('utf-8')
        binary_text = ''.join(format(byte, '08b') for byte in text_bytes)
        binary_text += '1111111111111110'  # 结束标记
        
        # 获取图像尺寸
        height, width, channels = pixels.shape
        max_capacity = height * width * channels
        
        if len(binary_text) > max_capacity:
            raise ValueError("水印文本太长，超出图像容量")
        
        # 嵌入水印
        data_index = 0
        for i in range(height):
            for j in range(width):
                for k in range(channels):
                    if data_index < len(binary_text):
                        # 修改像素值的最低位
                        pixels[i][j][k] = (pixels[i][j][k] & 0xFE) | int(binary_text[data_index])
                        data_index += 1
                    else:
                        break
                if data_index >= len(binary_text):
                    break
            if data_index >= len(binary_text):
                break
        
        # 创建结果图像
        result_img = Image.fromarray(pixels, 'RGB')
        
        # 如果原图有透明通道，恢复它
        if original_mode == 'RGBA':
            result_img = result_img.convert('RGBA')
            # 替换透明通道
            r, g, b, _ = result_img.split()
            result_img = Image.merge('RGBA', (r, g, b, alpha_channel))
        
        # 保存时使用原图的格式参数
        original_img = Image.open(cover_image_path)
        save_kwargs = {}
        
        # PNG特定参数
        if output_path.lower().endswith('.png'):
            save_kwargs.update({
                'optimize': False,
                'compress_level': 1  # 最小压缩以保持质量
            })
        
        result_img.save(output_path, **save_kwargs)
        print(f"LSB水印已嵌入并保存到: {output_path}")
        
        return pixels

    def extract_lsb_watermark(self, watermarked_image_path):
        """
        从图像中提取LSB水印，处理各种图像格式
        
        Args:
            watermarked_image_path: 包含水印的图像路径
            
        Returns:
            提取的文本水印
        """
        # 读取含水印图像
        img = Image.open(watermarked_image_path)
        
        # 转换为RGB进行处理
        if img.mode != 'RGB':
            img = img.convert('RGB')
            
        pixels = np.array(img)
        
        # 提取LSB位
        binary_data = ""
        height, width, channels = pixels.shape
        
        for i in range(height):
            for j in range(width):
                for k in range(channels):
                    # 提取最低位
                    binary_data += str(pixels[i][j][k] & 1)
        
        # 查找结束标记
        end_marker = '1111111111111110'
        end_pos = binary_data.find(end_marker)
        if end_pos != -1:
            # 如果找到结束标记，只处理标记之前的数据
            binary_data = binary_data[:end_pos]
        
        # 将二进制转换为字节数组
        byte_data = []
        for i in range(0, len(binary_data), 8):
            byte = binary_data[i:i+8]
            if len(byte) == 8:
                byte_data.append(int(byte, 2))
        
        # 将字节数组转换为UTF-8字符串
        try:
            watermark_text = bytes(byte_data).decode('utf-8')
        except UnicodeDecodeError:
            # 如果UTF-8解码失败，尝试忽略错误字符
            watermark_text = bytes(byte_data).decode('utf-8', errors='ignore')
        
        print(f"提取的水印文本: '{watermark_text}'")
        return watermark_text
    
    def detect_watermark(self, original_path, watermarked_path):
        """
        检测LSB水印存在性，更精确的检测方法
        
        Args:
            original_path: 原始图像路径
            watermarked_path: 含水印图像路径
            
        Returns:
            相似度分数
        """
        # 使用PIL读取以保持一致性
        original_img = Image.open(original_path).convert('RGB')
        watermarked_img = Image.open(watermarked_path).convert('RGB')
        
        original = np.array(original_img)
        watermarked = np.array(watermarked_img)
        
        # 确保尺寸相同
        if original.shape != watermarked.shape:
            watermarked_img = watermarked_img.resize(original_img.size)
            watermarked = np.array(watermarked_img)
        
        # 计算LSB位的差异
        lsb_diff_count = 0
        total_pixels = original.shape[0] * original.shape[1] * original.shape[2]
        
        for i in range(original.shape[0]):
            for j in range(original.shape[1]):
                for k in range(original.shape[2]):
                    # 比较最低位是否不同
                    if (original[i][j][k] & 1) != (watermarked[i][j][k] & 1):
                        lsb_diff_count += 1
        
        # 计算相似度
        similarity = 1 - (lsb_diff_count / total_pixels)
        
        print(f"LSB位差异: {lsb_diff_count}/{total_pixels} ({lsb_diff_count/total_pixels*100:.2f}%)")
        print(f"图像相似度: {similarity:.6f}")
        
        return similarity

def main():
    watermark_tool = ImageWatermark()
    
    while True:
        print("\n=== 图片水印工具 ===")
        print("1. 嵌入可见水印")
        print("2. 嵌入隐形水印 (LSB)")
        print("3. 提取隐形水印 (LSB)")
        print("4. 检测水印")
        print("5. 退出")
        
        choice = input("请选择操作 (1-5): ").strip()
        
        try:
            if choice == '1':
                cover_path = input("请输入载体图像路径: ").strip()
                watermark_path = input("请输入水印图像路径: ").strip()
                output_path = input("请输入输出路径: ").strip()
                alpha = float(input("请输入透明度 (0-1, 默认0.3): ") or "0.3")
                
                watermark_tool.embed_watermark(cover_path, watermark_path, output_path, alpha)
                
            elif choice == '2':
                cover_path = input("请输入载体图像路径: ").strip()
                watermark_text = input("请输入要嵌入的文本: ").strip()
                output_path = input("请输入输出路径: ").strip()
                
                watermark_tool.embed_lsb_watermark(cover_path, watermark_text, output_path)
                
            elif choice == '3':
                watermarked_path = input("请输入含水印图像路径: ").strip()
                watermark_tool.extract_lsb_watermark(watermarked_path)
                
            elif choice == '4':
                original_path = input("请输入原始图像路径: ").strip()
                watermarked_path = input("请输入含水印图像路径: ").strip()
                watermark_tool.detect_watermark(original_path, watermarked_path)
                
            elif choice == '5':
                print("退出程序")
                break
                
            else:
                print("无效选择，请重新输入")
                
        except Exception as e:
            print(f"错误: {e}")

# ...existing code...
if __name__ == "__main__":
    # 检查依赖包
    try:
        import cv2
        import numpy as np
        from PIL import Image
    except ImportError as e:
        print(f"缺少依赖包: {e}")
        print("请安装: pip install opencv-python pillow numpy")
        exit(1)
    
    main()