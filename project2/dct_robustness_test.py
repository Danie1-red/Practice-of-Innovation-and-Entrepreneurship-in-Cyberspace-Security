import cv2
import numpy as np
from PIL import Image, ImageEnhance
from dct_watermark import DCTWatermark
import os

class DCTRobustnessTest:
    def __init__(self):
        self.watermark_tool = DCTWatermark()
        self.test_text = "Hello DCT"  # 与原始测试保持一致
        self.original_image = 'test.png'
        self.watermarked_image = 'dct_watermarked.png'
        
        # 统计变量
        self.total_tests = 0
        self.passed_tests = 0
        self.test_results = []
        
    def prepare_watermarked_image(self):
        """准备含水印的测试图像"""
        print("准备DCT水印测试图像...")
        if not os.path.exists(self.original_image):
            raise FileNotFoundError(f"找不到原始图像: {self.original_image}")
            
        # 嵌入水印
        self.watermark_tool.embed_dct_watermark(
            self.original_image,
            self.test_text,
            self.watermarked_image
        )
        print(f"DCT水印图像已准备: {self.watermarked_image}")
    
    def run_single_test(self, test_name, output_path):
        """运行单个测试并统计结果"""
        self.total_tests += 1
        try:
            extracted = self.watermark_tool.extract_dct_watermark(output_path)
            success = extracted.strip() == self.test_text
            
            if success:
                self.passed_tests += 1
                print(f"{test_name}: ✓ 通过")
                self.test_results.append((test_name, "通过", extracted.strip()))
            else:
                print(f"{test_name}: ✗ 失败")
                truncated = extracted.strip()[:20] + ("..." if len(extracted.strip()) > 20 else "")
                print(f"  期望: '{self.test_text}'")
                print(f"  实际: '{truncated}'")
                self.test_results.append((test_name, "失败", truncated))
                
        except Exception as e:
            print(f"{test_name}: ✗ 异常 - {str(e)[:50]}...")
            self.test_results.append((test_name, "异常", str(e)[:30]))
    
    def test_geometric_transforms(self):
        """测试几何变换"""
        print("\n=== 测试几何变换 ===")
        
        # 水平翻转
        img = Image.open(self.watermarked_image)
        flipped = img.transpose(Image.FLIP_LEFT_RIGHT)
        flipped.save('dct_test_flip_h.png')
        self.run_single_test("水平翻转", 'dct_test_flip_h.png')
        
        # 垂直翻转
        flipped = img.transpose(Image.FLIP_TOP_BOTTOM)
        flipped.save('dct_test_flip_v.png')
        self.run_single_test("垂直翻转", 'dct_test_flip_v.png')
        
        # 180度旋转
        rotated = img.transpose(Image.ROTATE_180)
        rotated.save('dct_test_rotate_180.png')
        self.run_single_test("旋转180度", 'dct_test_rotate_180.png')
        
        # 90度旋转
        rotated = img.transpose(Image.ROTATE_90)
        rotated.save('dct_test_rotate_90.png')
        self.run_single_test("旋转90度", 'dct_test_rotate_90.png')
    
    def test_small_rotations(self):
        """测试小角度旋转"""
        print("\n=== 测试小角度旋转 ===")
        img_cv = cv2.imread(self.watermarked_image)
        rows, cols = img_cv.shape[:2]
        
        for angle in [1, 3, 5]:
            rotation_matrix = cv2.getRotationMatrix2D((cols/2, rows/2), angle, 1)
            rotated = cv2.warpAffine(img_cv, rotation_matrix, (cols, rows))
            output_path = f'dct_test_rotate_{angle}deg.png'
            cv2.imwrite(output_path, rotated)
            self.run_single_test(f"旋转{angle}度", output_path)
    
    def test_cropping(self):
        """测试图像裁剪"""
        print("\n=== 测试图像裁剪 ===")
        img = Image.open(self.watermarked_image)
        width, height = img.size
        
        # 测试不同的裁剪比例
        crop_ratios = [0.9, 0.8, 0.7, 0.5]
        
        for ratio in crop_ratios:
            new_width = int(width * ratio)
            new_height = int(height * ratio)
            left = (width - new_width) // 2
            top = (height - new_height) // 2
            right = left + new_width
            bottom = top + new_height
            
            cropped = img.crop((left, top, right, bottom))
            output_path = f'dct_test_cropped_{int(ratio*100)}.png'
            cropped.save(output_path)
            self.run_single_test(f"裁剪{int(ratio*100)}%", output_path)
    
    def test_scaling(self):
        """测试图像缩放"""
        print("\n=== 测试图像缩放 ===")
        img = Image.open(self.watermarked_image)
        original_size = img.size
        
        # 测试不同的缩放比例
        scale_factors = [0.5, 0.75, 1.25, 1.5]
        
        for scale in scale_factors:
            new_size = (int(original_size[0] * scale), int(original_size[1] * scale))
            scaled = img.resize(new_size, Image.LANCZOS)
            
            # 如果放大了，需要裁剪回原尺寸
            if scale > 1:
                left = (new_size[0] - original_size[0]) // 2
                top = (new_size[1] - original_size[1]) // 2
                right = left + original_size[0]
                bottom = top + original_size[1]
                scaled = scaled.crop((left, top, right, bottom))
            
            output_path = f'dct_test_scaled_{scale}.png'
            scaled.save(output_path)
            self.run_single_test(f"缩放{scale}倍", output_path)
    
    def test_jpeg_compression(self):
        """测试JPEG压缩"""
        print("\n=== 测试JPEG压缩 ===")
        img = Image.open(self.watermarked_image)
        
        # 确保RGB模式
        if img.mode != 'RGB':
            img = img.convert('RGB')
        
        # 测试不同的JPEG质量
        quality_levels = [95, 85, 75, 60, 50, 30]
        
        for quality in quality_levels:
            jpg_path = f'dct_test_jpeg_q{quality}.jpg'
            img.save(jpg_path, 'JPEG', quality=quality)
            self.run_single_test(f"JPEG质量{quality}", jpg_path)
    
    def test_brightness_contrast(self):
        """测试亮度和对比度调整"""
        print("\n=== 测试亮度对比度调整 ===")
        img = Image.open(self.watermarked_image)
        
        # 亮度调整
        brightness_values = [0.7, 0.8, 1.2, 1.3]
        for brightness in brightness_values:
            enhancer = ImageEnhance.Brightness(img)
            enhanced = enhancer.enhance(brightness)
            output_path = f'dct_test_brightness_{brightness}.png'
            enhanced.save(output_path)
            self.run_single_test(f"亮度{brightness}", output_path)
        
        # 对比度调整
        contrast_values = [0.6, 0.8, 1.2, 1.4]
        for contrast in contrast_values:
            enhancer = ImageEnhance.Contrast(img)
            enhanced = enhancer.enhance(contrast)
            output_path = f'dct_test_contrast_{contrast}.png'
            enhanced.save(output_path)
            self.run_single_test(f"对比度{contrast}", output_path)
    
    def test_color_adjustments(self):
        """测试颜色调整"""
        print("\n=== 测试颜色调整 ===")
        img = Image.open(self.watermarked_image)
        
        # 饱和度调整
        saturation_values = [0.5, 0.8, 1.2, 1.5]
        for saturation in saturation_values:
            enhancer = ImageEnhance.Color(img)
            enhanced = enhancer.enhance(saturation)
            output_path = f'dct_test_saturation_{saturation}.png'
            enhanced.save(output_path)
            self.run_single_test(f"饱和度{saturation}", output_path)
    
    def test_filtering_operations(self):
        """测试滤波操作"""
        print("\n=== 测试滤波操作 ===")
        img_cv = cv2.imread(self.watermarked_image)
        
        # 高斯模糊
        blur_kernels = [(3, 3), (5, 5), (7, 7)]
        for kernel in blur_kernels:
            blurred = cv2.GaussianBlur(img_cv, kernel, 0)
            output_path = f'dct_test_blur_{kernel[0]}x{kernel[1]}.png'
            cv2.imwrite(output_path, blurred)
            self.run_single_test(f"高斯模糊{kernel[0]}x{kernel[1]}", output_path)
        
        # 均值滤波
        mean_kernels = [3, 5, 7]
        for k in mean_kernels:
            mean_filtered = cv2.blur(img_cv, (k, k))
            output_path = f'dct_test_mean_{k}x{k}.png'
            cv2.imwrite(output_path, mean_filtered)
            self.run_single_test(f"均值滤波{k}x{k}", output_path)
        
        # 中值滤波
        median_kernels = [3, 5]
        for k in median_kernels:
            median_filtered = cv2.medianBlur(img_cv, k)
            output_path = f'dct_test_median_{k}x{k}.png'
            cv2.imwrite(output_path, median_filtered)
            self.run_single_test(f"中值滤波{k}x{k}", output_path)
    
    def test_noise_attacks(self):
        """测试噪声攻击"""
        print("\n=== 测试噪声攻击 ===")
        img_cv = cv2.imread(self.watermarked_image)
        
        # 高斯噪声
        noise_levels = [5, 10, 15, 20]
        for noise_std in noise_levels:
            noise = np.random.normal(0, noise_std, img_cv.shape).astype(np.uint8)
            noisy = cv2.add(img_cv, noise)
            output_path = f'dct_test_gaussian_noise_{noise_std}.png'
            cv2.imwrite(output_path, noisy)
            self.run_single_test(f"高斯噪声σ={noise_std}", output_path)
        
        # 椒盐噪声
        salt_pepper_ratios = [0.005, 0.01, 0.02]
        for ratio in salt_pepper_ratios:
            noisy = img_cv.copy()
            # 盐噪声
            coords = np.random.randint(0, noisy.shape[0], int(ratio * noisy.size))
            noisy.flat[coords] = 255
            # 胡椒噪声
            coords = np.random.randint(0, noisy.shape[0], int(ratio * noisy.size))
            noisy.flat[coords] = 0
            
            output_path = f'dct_test_salt_pepper_{ratio}.png'
            cv2.imwrite(output_path, noisy)
            self.run_single_test(f"椒盐噪声{ratio}", output_path)
    
    def test_translation(self):
        """测试平移变换"""
        print("\n=== 测试平移变换 ===")
        img_cv = cv2.imread(self.watermarked_image)
        rows, cols = img_cv.shape[:2]
        
        # 测试不同的平移距离
        translations = [(10, 10), (20, 20), (30, 30), (-15, 10)]
        
        for i, (tx, ty) in enumerate(translations):
            translation_matrix = np.float32([[1, 0, tx], [0, 1, ty]])
            translated = cv2.warpAffine(img_cv, translation_matrix, (cols, rows))
            output_path = f'dct_test_translate_{i+1}.png'
            cv2.imwrite(output_path, translated)
            self.run_single_test(f"平移({tx},{ty})", output_path)
    
    def test_histogram_equalization(self):
        """测试直方图均衡化"""
        print("\n=== 测试直方图均衡化 ===")
        img_cv = cv2.imread(self.watermarked_image)
        
        # 全局直方图均衡化
        yuv = cv2.cvtColor(img_cv, cv2.COLOR_BGR2YUV)
        yuv[:,:,0] = cv2.equalizeHist(yuv[:,:,0])
        equalized = cv2.cvtColor(yuv, cv2.COLOR_YUV2BGR)
        output_path = 'dct_test_hist_eq.png'
        cv2.imwrite(output_path, equalized)
        self.run_single_test("直方图均衡化", output_path)
        
        # CLAHE (限制对比度自适应直方图均衡化)
        clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8,8))
        yuv = cv2.cvtColor(img_cv, cv2.COLOR_BGR2YUV)
        yuv[:,:,0] = clahe.apply(yuv[:,:,0])
        clahe_result = cv2.cvtColor(yuv, cv2.COLOR_YUV2BGR)
        output_path = 'dct_test_clahe.png'
        cv2.imwrite(output_path, clahe_result)
        self.run_single_test("CLAHE", output_path)
    
    def print_summary(self):
        """打印测试总结"""
        print("\n" + "=" * 70)
        print("DCT频域水印鲁棒性测试总结")
        print("=" * 70)
        print(f"总测试数: {self.total_tests}")
        print(f"通过测试: {self.passed_tests}")
        print(f"失败测试: {self.total_tests - self.passed_tests}")
        print(f"通过率: {self.passed_tests/self.total_tests*100:.1f}%")
        
        print("\n详细结果:")
        print("-" * 50)
        
        # 按类别分组显示结果
        categories = {
            "几何变换": ["水平翻转", "垂直翻转", "旋转"],
            "JPEG压缩": ["JPEG"],
            "图像增强": ["亮度", "对比度", "饱和度"],
            "滤波操作": ["模糊", "滤波"],
            "噪声攻击": ["噪声"],
            "其他操作": ["裁剪", "缩放", "平移", "直方图", "CLAHE"]
        }
        
        for category, keywords in categories.items():
            print(f"\n{category}:")
            category_tests = [r for r in self.test_results if any(kw in r[0] for kw in keywords)]
            if category_tests:
                passed = sum(1 for r in category_tests if r[1] == "通过")
                total = len(category_tests)
                print(f"  通过率: {passed}/{total} ({passed/total*100:.1f}%)")
                for test_name, result, details in category_tests:
                    status_icon = "✓" if result == "通过" else "✗"
                    print(f"  {status_icon} {test_name:<15} {result}")
        
        print("\n" + "=" * 70)
        print("DCT频域水印技术特点分析:")
        
        # 计算各类攻击的通过率
        compression_passed = sum(1 for r in self.test_results if "JPEG" in r[0] and r[1] == "通过")
        compression_total = sum(1 for r in self.test_results if "JPEG" in r[0])
        
        enhancement_passed = sum(1 for r in self.test_results if any(x in r[0] for x in ["亮度", "对比度", "饱和度"]) and r[1] == "通过")
        enhancement_total = sum(1 for r in self.test_results if any(x in r[0] for x in ["亮度", "对比度", "饱和度"]))
        
        geometric_passed = sum(1 for r in self.test_results if any(x in r[0] for x in ["翻转", "旋转", "裁剪", "缩放", "平移"]) and r[1] == "通过")
        geometric_total = sum(1 for r in self.test_results if any(x in r[0] for x in ["翻转", "旋转", "裁剪", "缩放", "平移"]))
        
        print("✓ 优势攻击类型:")
        if compression_total > 0:
            print(f"  - JPEG压缩抗性: {compression_passed/compression_total*100:.1f}% ({compression_passed}/{compression_total})")
        if enhancement_total > 0:
            print(f"  - 图像增强抗性: {enhancement_passed/enhancement_total*100:.1f}% ({enhancement_passed}/{enhancement_total})")
        
        print("\n✗ 弱势攻击类型:")
        if geometric_total > 0:
            print(f"  - 几何变换抗性: {geometric_passed/geometric_total*100:.1f}% ({geometric_passed}/{geometric_total})")
        
        print("\nDCT水印适用场景:")
        if self.passed_tests/self.total_tests > 0.6:
            print("- 数字版权保护 (对常见处理有较好抗性)")
            print("- 内容认证 (可检测恶意篡改)")
        if compression_total > 0 and compression_passed/compression_total > 0.7:
            print("- 网络传输水印 (抗JPEG压缩)")
        
        print(f"\n总体评价: DCT水印通过率 {self.passed_tests/self.total_tests*100:.1f}%")
        if self.passed_tests/self.total_tests > 0.5:
            print("相比LSB水印有显著改善，适合实际应用！")
        else:
            print("仍需要进一步优化算法参数。")
    
    def run_all_tests(self):
        """运行所有鲁棒性测试"""
        print("DCT频域水印鲁棒性测试")
        print("预期结果: 相比LSB应有明显改善")
        print("=" * 60)
        
        # 准备测试图像
        self.prepare_watermarked_image()
        
        # 运行各类测试
        test_methods = [
            self.test_geometric_transforms,
            self.test_small_rotations,
            self.test_cropping,
            self.test_scaling,
            self.test_jpeg_compression,
            self.test_brightness_contrast,
            self.test_color_adjustments,
            self.test_filtering_operations,
            self.test_noise_attacks,
            self.test_translation,
            self.test_histogram_equalization
        ]
        
        for test_method in test_methods:
            try:
                test_method()
            except Exception as e:
                print(f"测试方法 {test_method.__name__} 异常: {e}")
        
        # 打印总结
        self.print_summary()

def main():
    """主函数"""
    print("DCT频域水印鲁棒性测试工具")
    print("此测试将验证DCT水印在各种图像处理操作下的存活能力")
    print("预期DCT水印相比LSB水印应有显著改善")
    
    tester = DCTRobustnessTest()
    tester.run_all_tests()

if __name__ == "__main__":
    main()