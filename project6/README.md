# DDH-based PI-Sum Protocol Implementation

基于论文 "On Deploying Secure Computing: Private Intersection-Sum-with-Cardinality" Section 3.1 的协议实现。

## 项目结构

```

project6/
├── README.md                    # 项目说明文档
├── ddh_pi_sum_protocol.py      # 椭圆曲线版本（有实现问题）
├── simple_pi_sum_protocol.py   # 简化版协议实现（便于理解）
├── secure_pi_sum_protocol.py   # 完整安全版本（推荐）
├── test_pi_sum_protocol.py     # 协议测试套件
├── 协议原理.md                 # 协议原理详细解析
└── 论文总结.md                 # 论文核心内容总结
```

## 协议概述

### 问题定义

**Private Intersection-Sum with Cardinality (PI-Sum-C)**：

- 两方 P₁ 和 P₂ 分别持有用户标识符集合
- P₂ 额外拥有每个标识符的整数值（如广告转化金额）
- 目标：安全计算交集大小和交集标识符对应值的总和
- 隐私要求：除结果外不泄露任何其他信息

### 协议特点

1. **基于 DDH 假设**：使用经典的判定性 Diffie-Hellman 困难假设
2. **通信高效**：优化批处理场景下的通信开销
3. **半诚实安全**：参与者遵守协议但可能窃听
4. **工业可部署**：Google 实际业务中的应用案例

## 协议流程

### 三轮交互协议

#### 输入与初始化

- **P₁**：标识符集合 V = {v₁, ..., v\_{m₁}}
- **P₂**：标识符-值对集合 W = {(w₁, t₁), ..., (w*{m₂}, t*{m₂})}
- **公共参数**：
  - DDH 困难群 G（如椭圆曲线 prime256v1）
  - 同态加密方案（如 Paillier）
  - 随机预言机 H: U → G

#### Round 1 (P₂ → P₁)

P₂ 计算并发送：

- **单掩码标识符**：H(wⱼ)^{k₂}（用私钥 k₂ 掩码）
- **加密值**：AEnc(tⱼ)（同态加密值 tⱼ）
- **乱序发送**：{(H(wⱼ)^{k₂}, AEnc(tⱼ))}（随机排列）

#### Round 2 (P₁ → P₂)

P₁ 处理并发送：

- **双掩码**：计算 (H(wⱼ)^{k₂})^{k₁} = H(wⱼ)^{k₁k₂}
- **洗牌**：随机重排双掩码数据和对应加密值
- **自身掩码**：发送 {H(vᵢ)^{k₁}}（P₁ 标识符的单掩码）

#### Round 3 (P₂ → P₁)

P₂ 计算并发送：

- **双掩码 P₁ 数据**：计算 (H(vᵢ)^{k₁})^{k₂} = H(vᵢ)^{k₁k₂}
- **求交集**：匹配双掩码集合，找到交集位置
- **同态求和**：计算 AEnc(∑\_{j∈J} tⱼ)
- **返回结果**：交集大小 |J| 和加密的交集和

#### 输出

- **P₁**：解密得到交集大小和交集值总和
- **P₂**：仅获知交集大小

## 关键隐私保护机制

### 1. 双掩码 (Double Masking)

- 标识符通过 H(·)^{k₁k₂} 转换为伪随机值
- 双方必须合作才能还原，类似共享密钥 OPRF
- 确保单方无法关联输入与输出

### 2. 洗牌 (Shuffling)

- P₁ 在 Round 2 重排数据顺序
- 切断掩码标识符与加密值的关联
- 防止 P₂ 通过位置推断哪些值被求和

### 3. 同态加密 (Homomorphic Aggregation)

- P₂ 仅处理加密值，无法窥探明文
- P₁ 仅解密最终和，不获知单个值
- 支持槽位打包优化，减少通信量

## 安全性分析

- **半诚实安全**：模拟证明各方视图仅依赖输入和输出
- **DDH 困难假设**：标识符掩码的安全性基于 DDH 假设
- **同态加密安全性**：值的隐私基于同态加密方案的安全性

## 效率特点

- **通信主导**：对 10⁵ 元素成本仅 0.084 美分（Paillier 优化）
- **批处理友好**：适合非实时场景
- **工业部署**：Google 每日 1000 次协议执行的实际应用

## 实现说明

### secure_pi_sum_protocol.py（推荐）

完整且安全的协议实现，包含：

- 基于 1024 位安全素数的 DDH 群
- 完整的 Paillier 同态加密实现
- 严格遵循论文协议流程
- Miller-Rabin 素性测试
- 工业级安全参数

### simple_pi_sum_protocol.py

简化版实现，特点：

- 使用整数模运算代替椭圆曲线
- 简化的"同态"加密（仅演示流程）
- 保留协议核心逻辑
- 便于理解协议原理

### ddh_pi_sum_protocol.py

椭圆曲线版本实现（存在技术问题）：

- 尝试使用椭圆曲线实现 DDH 群
- 有 cryptography 库兼容性问题
- 仅供学习参考

### test_pi_sum_protocol.py

全面的测试套件，覆盖：

- 空交集、完全交集、部分交集场景
- 大规模数据处理能力
- 边界条件和特殊值处理
- 协议正确性验证

## 运行示例

```bash
# 运行安全版本协议（推荐）
python secure_pi_sum_protocol.py

# 运行简化版协议
python simple_pi_sum_protocol.py

# 运行完整测试套件
python test_pi_sum_protocol.py
```

## 依赖库

```bash
pip install cryptography
```

## 扩展应用

协议支持以下扩展：

- **阈值过滤**：交集大小低于阈值可中止协议
- **多值统计**：计算交集的均值、方差等
- **分段统计**：按地区等维度分组计算
- **差分隐私**：添加噪声保护隐私

## 参考文献

Mihaela Ion et al. "On Deploying Secure Computing: Private Intersection-Sum-with-Cardinality." Proceedings of the IEEE Symposium on Security and Privacy (SP), 2020.

---

本实现仅用于学术研究和教学目的，实际部署需要更严格的安全审计和性能优化。
