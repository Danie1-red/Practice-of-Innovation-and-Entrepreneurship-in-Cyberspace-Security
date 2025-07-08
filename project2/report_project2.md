# 数字图像水印技术对比研究报告

## 摘要

本报告对LSB（最低有效位）水印和DCT（离散余弦变换）频域水印两种数字图像水印技术进行了全面的对比研究。通过实验验证，LSB水印在基础功能上表现良好但鲁棒性极差（通过率约0-10%），而DCT频域水印在保持良好视觉质量的同时显著提升了鲁棒性（通过率达53.7%），证明了频域水印技术在实际应用中的优势。

## 1. 引言

### 1.1 研究背景
随着数字媒体技术的快速发展，数字版权保护和内容认证成为重要需求。数字水印技术作为一种有效的版权保护手段，能够在不明显影响原始内容质量的前提下嵌入标识信息。

### 1.2 研究目标
- 实现并对比LSB空域水印和DCT频域水印算法
- 评估两种算法在不同攻击场景下的鲁棒性
- 分析各自的优缺点和适用场景

## 2. 理论基础

### 2.1 LSB水印技术

#### 原理
LSB（Least Significant Bit）水印技术通过修改图像像素的最低有效位来嵌入水印信息。由于人眼对亮度的细微变化不敏感，修改最低位通常不会造成可见的图像质量损失。

#### 算法步骤
1. **文本编码**：将水印文本转换为二进制序列
2. **像素遍历**：按顺序遍历图像像素
3. **位替换**：用水印位替换像素的最低有效位
4. **结束标记**：添加特定的二进制序列作为水印结束标记

#### 技术特点
- **优点**：实现简单，计算复杂度低，视觉隐蔽性强
- **缺点**：鲁棒性极差，任何图像处理都可能破坏水印

### 2.2 DCT频域水印技术

#### 原理
DCT水印技术在频域中嵌入水印信息。通过将图像分割为8×8像素块，对每个块进行DCT变换，然后在中频系数中嵌入水印位。

#### 算法步骤
1. **色彩空间转换**：将图像从RGB转换为YUV，在Y（亮度）通道操作
2. **块分割**：将图像分割为8×8像素块
3. **DCT变换**：对每个块进行二维DCT变换
4. **系数修改**：在选定的中频位置修改DCT系数
5. **逆变换**：进行逆DCT变换重构图像

#### 技术特点
- **优点**：对JPEG压缩和常见图像处理具有良好鲁棒性
- **缺点**：计算复杂度较高，对几何变换敏感

## 3. 实验设计与实现

### 3.1 实验环境
- **编程语言**：Python 3.x
- **主要库**：OpenCV, PIL, NumPy
- **测试图像**：620×1439像素PNG格式图像
- **水印内容**："Hello DCT"（与LSB测试保持一致）

### 3.2 LSB水印实现

```python
class ImageWatermark:
    def embed_lsb_watermark(self, cover_image_path, watermark_text, output_path):
        # 读取图像并转换为RGB
        img = Image.open(cover_image_path).convert('RGB')
        pixels = list(img.getdata())
        
        # 文本转二进制
        binary_watermark = self.text_to_binary(watermark_text)
        
        # 嵌入水印到像素LSB
        for i, bit in enumerate(binary_watermark):
            if i < len(pixels):
                r, g, b = pixels[i]
                # 修改红色通道的LSB
                pixels[i] = ((r & 0xFE) | int(bit), g, b)
        
        # 保存结果
        watermarked_img = Image.new('RGB', img.size)
        watermarked_img.putdata(pixels)
        watermarked_img.save(output_path)