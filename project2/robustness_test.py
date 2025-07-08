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
        
        # 统计变量
        self.total_tests = 0
        self.passed_tests = 0
        self.test_results = []
        
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
    
    def run_single_test(self, test_name, output_path):
        """运行单个测试并统计结果"""
        self.total_tests += 1
        try:
            extracted = self.watermark_tool.extract_lsb_watermark(output_path)
            success = extracted.strip() == self.test_text
            
            if success:
                self.passed_tests += 1
                print(f"{test_name}: ✓ 通过")
                self.test_results.append((test_name, "通过", extracted.strip()))
            else:
                print(f"{test_name}: ✗ 失败")
                truncated = extracted.strip()[:30] + ("..." if len(extracted.strip()) > 30 else "")
                print(f"  期望: '{self.test_text}'")
                print(f"  实际: '{truncated}'")
                self.test_results.append((test_name, "失败", truncated))
                
        except Exception as e:
            print(f"{test_name}: ✗ 异常 - {str(e)[:50]}...")
            self.test_results.append((test_name, "异常", str(e)[:30]))
    
    def test_basic_operations(self):
        """测试基本操作"""
        print("\n=== 测试基本几何变换 ===")
        
        # 水平翻转
        img = Image.open(self.watermarked_image)
        flipped = img.transpose(Image.FLIP_LEFT_RIGHT)
        flipped.save('test_flip_h.png')
        self.run_single_test("水平翻转", 'test_flip_h.png')
        
        # 垂直翻转
        flipped = img.transpose(Image.FLIP_TOP_BOTTOM)
        flipped.save('test_flip_v.png')
        self.run_single_test("垂直翻转", 'test_flip_v.png')
        
        # 180度旋转
        rotated = img.transpose(Image.ROTATE_180)
        rotated.save('test_rotate_180.png')
        self.run_single_test("旋转180度", 'test_rotate_180.png')
    
    def test_compression(self):
        """测试压缩"""
        print("\n=== 测试JPEG压缩 ===")
        img = Image.open(self.watermarked_image)
        
        # 确保是RGB模式
        if img.mode != 'RGB':
            img = img.convert('RGB')
        
        for quality in [95, 75, 50]:
            jpg_path = f'test_jpeg_q{quality}.jpg'
            img.save(jpg_path, 'JPEG', quality=quality)
            
            # 转回PNG测试
            jpg_img = Image.open(jpg_path)
            png_path = f'test_jpeg_q{quality}.png'
            jpg_img.save(png_path, 'PNG')
            
            self.run_single_test(f"JPEG质量{quality}", png_path)
    
    def test_image_enhancement(self):
        """测试图像增强"""
        print("\n=== 测试图像增强 ===")
        img = Image.open(self.watermarked_image)
        
        # 对比度调整
        for contrast in [0.5, 1.5]:
            enhancer = ImageEnhance.Contrast(img)
            enhanced = enhancer.enhance(contrast)
            output_path = f'test_contrast_{contrast}.png'
            enhanced.save(output_path)
            self.run_single_test(f"对比度{contrast}", output_path)
        
        # 亮度调整
        for brightness in [0.7, 1.3]:
            enhancer = ImageEnhance.Brightness(img)
            enhanced = enhancer.enhance(brightness)
            output_path = f'test_brightness_{brightness}.png'
            enhanced.save(output_path)
            self.run_single_test(f"亮度{brightness}", output_path)
    
    def test_noise_and_blur(self):
        """测试噪声和模糊"""
        print("\n=== 测试噪声和模糊 ===")
        img_cv = cv2.imread(self.watermarked_image)
        
        # 轻微高斯噪声
        noise = np.random.normal(0, 5, img_cv.shape).astype(np.uint8)
        noisy = cv2.add(img_cv, noise)
        cv2.imwrite('test_noise_light.png', noisy)
        self.run_single_test("轻微噪声", 'test_noise_light.png')
        
        # 轻微模糊
        blurred = cv2.GaussianBlur(img_cv, (3, 3), 0)
        cv2.imwrite('test_blur_light.png', blurred)
        self.run_single_test("轻微模糊", 'test_blur_light.png')
    
    def print_summary(self):
        """打印测试总结"""
        print("\n" + "=" * 60)
        print("LSB水印鲁棒性测试总结")
        print("=" * 60)
        print(f"总测试数: {self.total_tests}")
        print(f"通过测试: {self.passed_tests}")
        print(f"失败测试: {self.total_tests - self.passed_tests}")
        print(f"通过率: {self.passed_tests/self.total_tests*100:.1f}%")
        
        print("\n详细结果:")
        print("-" * 40)
        for test_name, result, details in self.test_results:
            status_icon = "✓" if result == "通过" else "✗"
            print(f"{status_icon} {test_name:<12} {result}")
            if result != "通过":
                print(f"    输出: {details}")
        
        print("\n" + "=" * 60)
        print("LSB水印技术特点总结:")
        print("✓ 优点:")
        print("  - 隐蔽性强，视觉上完全不可见")
        print("  - 容量大，可嵌入大量数据")
        print("  - 实现简单，计算复杂度低")
        
        print("✗ 缺点:")
        print("  - 鲁棒性极差，几乎任何处理都会破坏")
        print("  - 安全性低，容易被检测和攻击")
        print("  - 对图像格式转换敏感")
        
        print("\n适用场景:")
        print("- 完整性验证（检测图像是否被修改）")
        print("- 隐蔽通信（在严格无处理环境下）")
        print("- 脆弱水印（故意设计为易损坏的水印）")
        
        print(f"\n结论: LSB水印通过率 {self.passed_tests/self.total_tests*100:.1f}% 证明了其脆弱特性")
    
    def run_all_tests(self):
        """运行所有测试"""
        print("LSB水印鲁棒性测试")
        print("预期结果: 大部分测试失败（这是正常的）")
        print("=" * 50)
        
        self.prepare_watermarked_image()
        
        # 运行测试
        self.test_basic_operations()
        self.test_compression()
        self.test_image_enhancement() 
        self.test_noise_and_blur()
        
        # 打印总结
        self.print_summary()

def main():
    """主函数"""
    tester = RobustnessTest()
    tester.run_all_tests()

if __name__ == "__main__":
    main()