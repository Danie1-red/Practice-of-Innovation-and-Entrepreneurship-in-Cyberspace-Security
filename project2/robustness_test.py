import cv2
import numpy as np
from PIL import Image, ImageEnhance
from watermark import ImageWatermark
import os

class RobustnessTest:
    def __init__(self):
        self.watermark_tool = ImageWatermark()
        self.test_text = "Hello World 测试水印"
        self.original_image = 'test.png'
        self.watermarked_image = 'test_watermarked.png'
        
    def prepare_watermarked_image(self):
        """准备含水印的测试图像"""
        print("准备测试图像...")
        if not os.path.exists(self.original_image):
            raise FileNotFoundError(f"找不到原始图像: {self.original_image}")
            
        # 嵌入水印
        self.watermark_tool.embed_lsb_watermark(
            self.original_image,
            self.test_text,
            self.watermarked_image
        )
        print(f"水印图像已准备: {self.watermarked_image}")
    
    def test_horizontal_flip(self):
        """测试水平翻转"""
        print("\n=== 测试水平翻转 ===")
        img = Image.open(self.watermarked_image)
        flipped = img.transpose(Image.FLIP_LEFT_RIGHT)
        output_path = 'test_flipped_h.png'
        flipped.save(output_path)
        
        try:
            extracted = self.watermark_tool.extract_lsb_watermark(output_path)
            success = extracted.strip() == self.test_text
            print(f"水平翻转测试: {'✓ 通过' if success else '✗ 失败'}")
            if not success:
                print(f"  期望: '{self.test_text}'")
                print(f"  实际: '{extracted.strip()}'")
        except Exception as e:
            print(f"水平翻转测试: ✗ 异常 - {e}")
    
    def test_vertical_flip(self):
        """测试垂直翻转"""
        print("\n=== 测试垂直翻转 ===")
        img = Image.open(self.watermarked_image)
        flipped = img.transpose(Image.FLIP_TOP_BOTTOM)
        output_path = 'test_flipped_v.png'
        flipped.save(output_path)
        
        try:
            extracted = self.watermark_tool.extract_lsb_watermark(output_path)
            success = extracted.strip() == self.test_text
            print(f"垂直翻转测试: {'✓ 通过' if success else '✗ 失败'}")
            if not success:
                print(f"  期望: '{self.test_text}'")
                print(f"  实际: '{extracted.strip()}'")
        except Exception as e:
            print(f"垂直翻转测试: ✗ 异常 - {e}")
    
    def test_rotation(self):
        """测试旋转"""
        print("\n=== 测试旋转 ===")
        angles = [90, 180, 270]
        
        for angle in angles:
            img = Image.open(self.watermarked_image)
            
            if angle == 90:
                rotated = img.transpose(Image.ROTATE_90)
            elif angle == 180:
                rotated = img.transpose(Image.ROTATE_180)
            elif angle == 270:
                rotated = img.transpose(Image.ROTATE_270)
            
            output_path = f'test_rotated_{angle}.png'
            rotated.save(output_path)
            
            try:
                extracted = self.watermark_tool.extract_lsb_watermark(output_path)
                success = extracted.strip() == self.test_text
                print(f"旋转{angle}度测试: {'✓ 通过' if success else '✗ 失败'}")
                if not success:
                    print(f"  期望: '{self.test_text}'")
                    print(f"  实际: '{extracted.strip()}'")
            except Exception as e:
                print(f"旋转{angle}度测试: ✗ 异常 - {e}")
    
    def test_cropping(self):
        """测试截取/裁剪"""
        print("\n=== 测试图像裁剪 ===")
        img = Image.open(self.watermarked_image)
        width, height = img.size
        
        # 测试不同的裁剪比例
        crop_ratios = [0.9, 0.8, 0.7, 0.5]
        
        for ratio in crop_ratios:
            # 从中心裁剪
            new_width = int(width * ratio)
            new_height = int(height * ratio)
            left = (width - new_width) // 2
            top = (height - new_height) // 2
            right = left + new_width
            bottom = top + new_height
            
            cropped = img.crop((left, top, right, bottom))
            output_path = f'test_cropped_{int(ratio*100)}.png'
            cropped.save(output_path)
            
            try:
                extracted = self.watermark_tool.extract_lsb_watermark(output_path)
                success = extracted.strip() == self.test_text
                print(f"裁剪{int(ratio*100)}%测试: {'✓ 通过' if success else '✗ 失败'}")
                if not success:
                    print(f"  期望: '{self.test_text}'")
                    print(f"  实际: '{extracted.strip()}'")
            except Exception as e:
                print(f"裁剪{int(ratio*100)}%测试: ✗ 异常 - {e}")
    
    def test_contrast_adjustment(self):
        """测试对比度调整"""
        print("\n=== 测试对比度调整 ===")
        img = Image.open(self.watermarked_image)
        
        # 测试不同的对比度值
        contrast_values = [0.5, 0.8, 1.2, 1.5, 2.0]
        
        for contrast in contrast_values:
            enhancer = ImageEnhance.Contrast(img)
            enhanced = enhancer.enhance(contrast)
            output_path = f'test_contrast_{contrast}.png'
            enhanced.save(output_path)
            
            try:
                extracted = self.watermark_tool.extract_lsb_watermark(output_path)
                success = extracted.strip() == self.test_text
                print(f"对比度{contrast}测试: {'✓ 通过' if success else '✗ 失败'}")
                if not success:
                    print(f"  期望: '{self.test_text}'")
                    print(f"  实际: '{extracted.strip()}'")
            except Exception as e:
                print(f"对比度{contrast}测试: ✗ 异常 - {e}")
    
    def test_brightness_adjustment(self):
        """测试亮度调整"""
        print("\n=== 测试亮度调整 ===")
        img = Image.open(self.watermarked_image)
        
        # 测试不同的亮度值
        brightness_values = [0.5, 0.8, 1.2, 1.5]
        
        for brightness in brightness_values:
            enhancer = ImageEnhance.Brightness(img)
            enhanced = enhancer.enhance(brightness)
            output_path = f'test_brightness_{brightness}.png'
            enhanced.save(output_path)
            
            try:
                extracted = self.watermark_tool.extract_lsb_watermark(output_path)
                success = extracted.strip() == self.test_text
                print(f"亮度{brightness}测试: {'✓ 通过' if success else '✗ 失败'}")
                if not success:
                    print(f"  期望: '{self.test_text}'")
                    print(f"  实际: '{extracted.strip()}'")
            except Exception as e:
                print(f"亮度{brightness}测试: ✗ 异常 - {e}")
    
    def test_gaussian_noise(self):
        """测试高斯噪声"""
        print("\n=== 测试高斯噪声 ===")
        img = cv2.imread(self.watermarked_image)
        
        # 测试不同强度的高斯噪声
        noise_levels = [5, 10, 15, 20]
        
        for noise_level in noise_levels:
            noisy = img.copy()
            noise = np.random.normal(0, noise_level, img.shape).astype(np.uint8)
            noisy = cv2.add(noisy, noise)
            
            output_path = f'test_noise_{noise_level}.png'
            cv2.imwrite(output_path, noisy)
            
            try:
                extracted = self.watermark_tool.extract_lsb_watermark(output_path)
                success = extracted.strip() == self.test_text
                print(f"噪声强度{noise_level}测试: {'✓ 通过' if success else '✗ 失败'}")
                if not success:
                    print(f"  期望: '{self.test_text}'")
                    print(f"  实际: '{extracted.strip()}'")
            except Exception as e:
                print(f"噪声强度{noise_level}测试: ✗ 异常 - {e}")
    
    def test_gaussian_blur(self):
        """测试高斯模糊"""
        print("\n=== 测试高斯模糊 ===")
        img = cv2.imread(self.watermarked_image)
        
        # 测试不同的模糊核大小
        blur_kernels = [(3, 3), (5, 5), (7, 7), (9, 9)]
        
        for kernel in blur_kernels:
            blurred = cv2.GaussianBlur(img, kernel, 0)
            output_path = f'test_blur_{kernel[0]}x{kernel[1]}.png'
            cv2.imwrite(output_path, blurred)
            
            try:
                extracted = self.watermark_tool.extract_lsb_watermark(output_path)
                success = extracted.strip() == self.test_text
                print(f"模糊{kernel[0]}x{kernel[1]}测试: {'✓ 通过' if success else '✗ 失败'}")
                if not success:
                    print(f"  期望: '{self.test_text}'")
                    print(f"  实际: '{extracted.strip()}'")
            except Exception as e:
                print(f"模糊{kernel[0]}x{kernel[1]}测试: ✗ 异常 - {e}")
    
    def test_jpeg_compression(self):
        """测试JPEG压缩"""
        print("\n=== 测试JPEG压缩 ===")
        img = Image.open(self.watermarked_image)
        
        # 测试不同的JPEG质量
        quality_levels = [95, 85, 75, 60, 50]
        
        for quality in quality_levels:
            output_path = f'test_jpeg_q{quality}.jpg'
            img.save(output_path, 'JPEG', quality=quality)
            
            # 转换回PNG进行测试
            jpg_img = Image.open(output_path)
            png_path = f'test_jpeg_q{quality}_converted.png'
            jpg_img.save(png_path, 'PNG')
            
            try:
                extracted = self.watermark_tool.extract_lsb_watermark(png_path)
                success = extracted.strip() == self.test_text
                print(f"JPEG质量{quality}测试: {'✓ 通过' if success else '✗ 失败'}")
                if not success:
                    print(f"  期望: '{self.test_text}'")
                    print(f"  实际: '{extracted.strip()}'")
            except Exception as e:
                print(f"JPEG质量{quality}测试: ✗ 异常 - {e}")
    
    def test_scaling(self):
        """测试缩放"""
        print("\n=== 测试图像缩放 ===")
        img = Image.open(self.watermarked_image)
        original_size = img.size
        
        # 测试不同的缩放比例
        scale_factors = [0.5, 0.8, 1.2, 1.5, 2.0]
        
        for scale in scale_factors:
            new_size = (int(original_size[0] * scale), int(original_size[1] * scale))
            scaled = img.resize(new_size, Image.LANCZOS)
            
            # 如果是放大，再缩回原始大小
            if scale > 1.0:
                scaled = scaled.resize(original_size, Image.LANCZOS)
            
            output_path = f'test_scaled_{scale}.png'
            scaled.save(output_path)
            
            try:
                extracted = self.watermark_tool.extract_lsb_watermark(output_path)
                success = extracted.strip() == self.test_text
                print(f"缩放{scale}倍测试: {'✓ 通过' if success else '✗ 失败'}")
                if not success:
                    print(f"  期望: '{self.test_text}'")
                    print(f"  实际: '{extracted.strip()}'")
            except Exception as e:
                print(f"缩放{scale}倍测试: ✗ 异常 - {e}")
    
    def run_all_tests(self):
        """运行所有鲁棒性测试"""
        print("开始LSB水印鲁棒性测试...")
        print("=" * 50)
        
        # 准备测试图像
        self.prepare_watermarked_image()
        
        # 运行所有测试
        test_methods = [
            self.test_horizontal_flip,
            self.test_vertical_flip,
            self.test_rotation,
            self.test_cropping,
            self.test_contrast_adjustment,
            self.test_brightness_adjustment,
            self.test_gaussian_noise,
            self.test_gaussian_blur,
            self.test_jpeg_compression,
            self.test_scaling
        ]
        
        passed_tests = 0
        total_tests = 0
        
        for test_method in test_methods:
            try:
                test_method()
                # 这里简化统计，实际应该在每个测试方法内部统计
            except Exception as e:
                print(f"测试异常: {e}")
        
        print("\n" + "=" * 50)
        print("鲁棒性测试完成！")
        print("\n注意：LSB水印通常对以下操作不具备鲁棒性：")
        print("- 格式转换（JPEG压缩）")
        print("- 几何变换（旋转、缩放、翻转）")
        print("- 图像增强（对比度、亮度调整）")
        print("- 噪声添加")
        print("- 滤波操作")
        print("\n如需提高鲁棒性，建议使用频域水印技术（DCT、DWT等）")

def main():
    """主函数"""
    print("LSB水印鲁棒性测试工具")
    print("此测试将验证LSB水印在各种图像处理操作下的存活能力")
    
    tester = RobustnessTest()
    tester.run_all_tests()

if __name__ == "__main__":
    main()