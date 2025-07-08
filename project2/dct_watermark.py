import cv2
import numpy as np
from PIL import Image
import os

class DCTWatermark:
    def __init__(self):
        self.alpha = 15.0  # 水印强度系数
        self.block_size = 8  # DCT块大小
        
    def text_to_binary(self, text):
        """将文本转换为二进制"""
        # 修复：直接使用字节值，不需要ord()
        text_bytes = text.encode('utf-8')
        binary = ''.join(format(byte, '08b') for byte in text_bytes)
        return binary + '1111111111111110'  # 添加结束标记
    
    def binary_to_text(self, binary):
        """将二进制转换为文本"""
        # 查找结束标记
        end_marker = '1111111111111110'
        end_pos = binary.find(end_marker)
        if end_pos != -1:
            binary = binary[:end_pos]
        
        # 将二进制转换为字节数组
        byte_data = []
        for i in range(0, len(binary), 8):
            byte = binary[i:i+8]
            if len(byte) == 8:
                byte_data.append(int(byte, 2))
        
        # 将字节数组转换为UTF-8字符串
        try:
            return bytes(byte_data).decode('utf-8')
        except UnicodeDecodeError:
            return bytes(byte_data).decode('utf-8', errors='ignore')
    
    def dct2d(self, block):
        """二维DCT变换"""
        return cv2.dct(block.astype(np.float32))
    
    def idct2d(self, block):
        """二维逆DCT变换"""
        return cv2.idct(block.astype(np.float32))
    
    def get_mid_freq_positions(self):
        """获取中频系数位置（用于嵌入水印）"""
        # 选择8x8块中的中频位置，避免DC分量和高频噪声
        positions = [
            (2, 1), (1, 2), (3, 1), (2, 2), (1, 3), (4, 1), (3, 2), (2, 3)
        ]
        return positions
    
    def embed_dct_watermark(self, cover_image_path, watermark_text, output_path):
        """
        使用DCT频域嵌入水印
        
        Args:
            cover_image_path: 载体图像路径
            watermark_text: 水印文本
            output_path: 输出路径
        """
        print(f"开始嵌入DCT水印...")
        
        # 读取图像
        img = cv2.imread(cover_image_path)
        if img is None:
            raise ValueError(f"无法读取图像: {cover_image_path}")
        
        # 转换为YUV色彩空间，在Y通道嵌入水印
        yuv = cv2.cvtColor(img, cv2.COLOR_BGR2YUV)
        y_channel = yuv[:, :, 0].astype(np.float32)
        
        # 转换文本为二进制
        binary_watermark = self.text_to_binary(watermark_text)
        print(f"水印文本: '{watermark_text}'")
        print(f"水印二进制长度: {len(binary_watermark)} 位")
        
        # 获取图像尺寸
        height, width = y_channel.shape
        print(f"图像尺寸: {height} x {width}")
        
        # 计算可用的8x8块数量
        blocks_h = height // self.block_size
        blocks_w = width // self.block_size
        total_blocks = blocks_h * blocks_w
        
        # 获取中频位置
        mid_freq_pos = self.get_mid_freq_positions()
        max_capacity = total_blocks * len(mid_freq_pos)
        
        print(f"图像容量: {max_capacity} 位")
        print(f"可用块数: {total_blocks} 个")
        print(f"每块嵌入位数: {len(mid_freq_pos)} 位")
        
        if len(binary_watermark) > max_capacity:
            raise ValueError(f"水印太长！最大容量: {max_capacity} 位，当前: {len(binary_watermark)} 位")
        
        # 嵌入水印
        watermarked_y = y_channel.copy()
        bit_index = 0
        embedded_blocks = 0
        
        for i in range(0, blocks_h * self.block_size, self.block_size):
            for j in range(0, blocks_w * self.block_size, self.block_size):
                if bit_index >= len(binary_watermark):
                    break
                
                # 提取8x8块
                block = y_channel[i:i+self.block_size, j:j+self.block_size]
                
                # DCT变换
                dct_block = self.dct2d(block)
                
                # 在中频位置嵌入水印
                for pos_idx, (u, v) in enumerate(mid_freq_pos):
                    if bit_index >= len(binary_watermark):
                        break
                    
                    # 获取当前位的水印值
                    watermark_bit = int(binary_watermark[bit_index])
                    
                    # 改进的DCT系数修改方法
                    original_coeff = dct_block[u, v]
                    
                    if watermark_bit == 1:
                        # 嵌入1：增加系数幅值
                        dct_block[u, v] = original_coeff + self.alpha if original_coeff >= 0 else original_coeff - self.alpha
                    else:
                        # 嵌入0：减少系数幅值
                        if abs(original_coeff) > self.alpha:
                            dct_block[u, v] = original_coeff - self.alpha if original_coeff >= 0 else original_coeff + self.alpha
                        else:
                            dct_block[u, v] = 0
                    
                    bit_index += 1
                
                # 逆DCT变换
                watermarked_block = self.idct2d(dct_block)
                watermarked_y[i:i+self.block_size, j:j+self.block_size] = watermarked_block
                embedded_blocks += 1
            
            if bit_index >= len(binary_watermark):
                break
        
        print(f"已处理块数: {embedded_blocks}")
        print(f"已嵌入位数: {bit_index}")
        
        # 重构图像
        watermarked_yuv = yuv.copy()
        watermarked_yuv[:, :, 0] = np.clip(watermarked_y, 0, 255).astype(np.uint8)
        watermarked_img = cv2.cvtColor(watermarked_yuv, cv2.COLOR_YUV2BGR)
        
        # 保存结果
        cv2.imwrite(output_path, watermarked_img)
        print(f"DCT水印已嵌入并保存到: {output_path}")
        
        return watermarked_img
    
    def extract_dct_watermark(self, watermarked_image_path):
        """
        从DCT频域提取水印
        
        Args:
            watermarked_image_path: 含水印图像路径
            
        Returns:
            提取的水印文本
        """
        print(f"开始提取DCT水印...")
        
        # 读取图像
        img = cv2.imread(watermarked_image_path)
        if img is None:
            raise ValueError(f"无法读取图像: {watermarked_image_path}")
        
        # 转换为YUV色彩空间，提取Y通道
        yuv = cv2.cvtColor(img, cv2.COLOR_BGR2YUV)
        y_channel = yuv[:, :, 0].astype(np.float32)
        
        # 获取图像尺寸
        height, width = y_channel.shape
        blocks_h = height // self.block_size
        blocks_w = width // self.block_size
        
        # 获取中频位置
        mid_freq_pos = self.get_mid_freq_positions()
        
        # 提取水印
        extracted_bits = ""
        processed_blocks = 0
        
        for i in range(0, blocks_h * self.block_size, self.block_size):
            for j in range(0, blocks_w * self.block_size, self.block_size):
                # 提取8x8块
                block = y_channel[i:i+self.block_size, j:j+self.block_size]
                
                # DCT变换
                dct_block = self.dct2d(block)
                
                # 从中频位置提取水印
                for u, v in mid_freq_pos:
                    # 改进的提取方法：根据系数符号和幅值判断
                    coeff = dct_block[u, v]
                    
                    if abs(coeff) >= self.alpha / 2:
                        extracted_bits += "1"
                    else:
                        extracted_bits += "0"
                
                processed_blocks += 1
        
        print(f"处理块数: {processed_blocks}")
        print(f"提取位数: {len(extracted_bits)}")
        
        # 转换为文本
        extracted_text = self.binary_to_text(extracted_bits)
        print(f"提取的水印文本: '{extracted_text}'")
        
        return extracted_text
    
    def detect_watermark(self, original_path, watermarked_path):
        """
        检测水印强度和图像质量
        
        Args:
            original_path: 原始图像路径
            watermarked_path: 含水印图像路径
            
        Returns:
            相似度分数
        """
        # 读取图像
        original = cv2.imread(original_path)
        watermarked = cv2.imread(watermarked_path)
        
        if original is None or watermarked is None:
            raise ValueError("无法读取图像")
        
        # 计算PSNR (峰值信噪比)
        mse = np.mean((original.astype(np.float32) - watermarked.astype(np.float32)) ** 2)
        if mse == 0:
            psnr = float('inf')
        else:
            psnr = 20 * np.log10(255.0 / np.sqrt(mse))
        
        # 计算结构相似性 (简化版SSIM)
        original_gray = cv2.cvtColor(original, cv2.COLOR_BGR2GRAY)
        watermarked_gray = cv2.cvtColor(watermarked, cv2.COLOR_BGR2GRAY)
        
        # 计算相关系数
        correlation = np.corrcoef(original_gray.flatten(), watermarked_gray.flatten())[0, 1]
        
        print(f"PSNR: {psnr:.2f} dB")
        print(f"相关系数: {correlation:.6f}")
        
        return correlation

def main():
    """主函数 - 测试DCT水印功能"""
    print("DCT频域水印测试")
    print("=" * 40)
    
    # 检查测试图像
    test_image = 'test.png'
    if not os.path.exists(test_image):
        print(f"错误: 找不到测试图像 {test_image}")
        return
    
    # 创建DCT水印工具
    watermark_tool = DCTWatermark()
    test_text = "Hello DCT"  # 使用较短的文本进行测试
    output_image = 'dct_watermarked.png'
    
    try:
        # 嵌入水印
        print("\n1. 嵌入DCT水印...")
        watermark_tool.embed_dct_watermark(test_image, test_text, output_image)
        
        # 检测图像质量
        print("\n2. 检测图像质量...")
        watermark_tool.detect_watermark(test_image, output_image)
        
        # 提取水印
        print("\n3. 提取DCT水印...")
        extracted = watermark_tool.extract_dct_watermark(output_image)
        
        # 验证结果
        print("\n4. 验证结果...")
        success = extracted.strip() == test_text
        print(f"原始文本: '{test_text}'")
        print(f"提取文本: '{extracted.strip()}'")
        print(f"测试结果: {'✓ 成功' if success else '✗ 失败'}")
        
        if os.path.exists(output_image):
            print(f"\n生成的水印图像: {output_image}")
            
        # 显示文件大小比较
        original_size = os.path.getsize(test_image)
        watermarked_size = os.path.getsize(output_image)
        print(f"原始图像大小: {original_size} bytes")
        print(f"水印图像大小: {watermarked_size} bytes")
        
    except Exception as e:
        print(f"错误: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()