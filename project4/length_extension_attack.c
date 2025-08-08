/*
 * SM3 Length Extension Attack Implementation
 * SM3 长度扩展攻击验证与演示
 *
 * 长度扩展攻击原理：
 * 对于基于Merkle-Damgård结构的哈希函数（如SM3），攻击者在已知
 * H(secret||message) 和 message 长度的情况下，可以计算出
 * H(secret||message||padding||additional_message) 而无需知道 secret
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

// SM3 基本常数定义
#define SM3_BLOCK_SIZE 64  // 512 bits
#define SM3_DIGEST_SIZE 32 // 256 bits

// SM3 初始值
#define SM3_H0 0x7380166F
#define SM3_H1 0x4914B2B9
#define SM3_H2 0x172442D7
#define SM3_H3 0xDA8A0600
#define SM3_H4 0xA96F30BC
#define SM3_H5 0x163138AA
#define SM3_H6 0xE38DEE4D
#define SM3_H7 0xB0FB0E4E

// T 常数
#define T_0_15 0x79cc4519
#define T_16_63 0x7a879d8a

// 基础运算宏
#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

// P0 和 P1 置换函数
#define P0(x) ((x) ^ ROTL32((x), 9) ^ ROTL32((x), 17))
#define P1(x) ((x) ^ ROTL32((x), 15) ^ ROTL32((x), 23))

// FF 和 GG 布尔函数
#define FF_0_15(x, y, z) ((x) ^ (y) ^ (z))
#define FF_16_63(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define GG_0_15(x, y, z) ((x) ^ (y) ^ (z))
#define GG_16_63(x, y, z) (((x) & (y)) | (~(x) & (z)))

// SM3 上下文结构
typedef struct
{
    uint32_t state[8];      // 256位哈希状态
    uint8_t buffer[64];     // 512位输入缓冲区
    uint64_t total_length;  // 累计输入长度（位）
    uint32_t buffer_length; // 当前缓冲区长度
} sm3_context_t;

// 字节序转换 - 大端序
static uint32_t bytes_to_u32_be(const uint8_t *bytes)
{
    return (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
}

static void u32_to_bytes_be(uint32_t value, uint8_t *bytes)
{
    bytes[0] = (value >> 24) & 0xFF;
    bytes[1] = (value >> 16) & 0xFF;
    bytes[2] = (value >> 8) & 0xFF;
    bytes[3] = value & 0xFF;
}

// SM3 压缩函数
static void sm3_compress(sm3_context_t *ctx, const uint8_t *block)
{
    uint32_t W[68];
    uint32_t W1[64];

    // 消息字加载
    for (int i = 0; i < 16; i++)
    {
        W[i] = bytes_to_u32_be(block + i * 4);
    }

    // 消息扩展
    for (int j = 16; j < 68; j++)
    {
        uint32_t temp = W[j - 16] ^ W[j - 9] ^ ROTL32(W[j - 3], 15);
        W[j] = P1(temp) ^ ROTL32(W[j - 13], 7) ^ W[j - 6];
    }

    // 生成W'数组
    for (int j = 0; j < 64; j++)
    {
        W1[j] = W[j] ^ W[j + 4];
    }

    // 压缩函数迭代
    uint32_t A = ctx->state[0], B = ctx->state[1], C = ctx->state[2], D = ctx->state[3];
    uint32_t E = ctx->state[4], F = ctx->state[5], G = ctx->state[6], H = ctx->state[7];

    // 64轮压缩
    for (int j = 0; j < 64; j++)
    {
        uint32_t T = (j < 16) ? T_0_15 : T_16_63;
        T = ROTL32(T, j % 32);

        uint32_t SS1 = ROTL32(ROTL32(A, 12) + E + T, 7);
        uint32_t SS2 = SS1 ^ ROTL32(A, 12);

        uint32_t TT1, TT2;
        if (j < 16)
        {
            TT1 = FF_0_15(A, B, C) + D + SS2 + W1[j];
            TT2 = GG_0_15(E, F, G) + H + SS1 + W[j];
        }
        else
        {
            TT1 = FF_16_63(A, B, C) + D + SS2 + W1[j];
            TT2 = GG_16_63(E, F, G) + H + SS1 + W[j];
        }

        D = C;
        C = ROTL32(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = ROTL32(F, 19);
        F = E;
        E = P0(TT2);
    }

    // 更新状态
    ctx->state[0] ^= A;
    ctx->state[1] ^= B;
    ctx->state[2] ^= C;
    ctx->state[3] ^= D;
    ctx->state[4] ^= E;
    ctx->state[5] ^= F;
    ctx->state[6] ^= G;
    ctx->state[7] ^= H;
}

// SM3 初始化
void sm3_init(sm3_context_t *ctx)
{
    ctx->state[0] = SM3_H0;
    ctx->state[1] = SM3_H1;
    ctx->state[2] = SM3_H2;
    ctx->state[3] = SM3_H3;
    ctx->state[4] = SM3_H4;
    ctx->state[5] = SM3_H5;
    ctx->state[6] = SM3_H6;
    ctx->state[7] = SM3_H7;

    ctx->total_length = 0;
    ctx->buffer_length = 0;
    memset(ctx->buffer, 0, 64);
}

// SM3 更新
void sm3_update(sm3_context_t *ctx, const uint8_t *data, uint64_t len)
{
    ctx->total_length += len * 8; // 转换为位数

    while (len > 0)
    {
        uint32_t chunk_size = 64 - ctx->buffer_length;
        if (chunk_size > len)
            chunk_size = len;

        memcpy(ctx->buffer + ctx->buffer_length, data, chunk_size);
        ctx->buffer_length += chunk_size;
        data += chunk_size;
        len -= chunk_size;

        if (ctx->buffer_length == 64)
        {
            sm3_compress(ctx, ctx->buffer);
            ctx->buffer_length = 0;
        }
    }
}

// SM3 最终化
void sm3_final(sm3_context_t *ctx, uint8_t *digest)
{
    // 添加填充
    ctx->buffer[ctx->buffer_length] = 0x80;
    ctx->buffer_length++;

    // 如果空间不足，先处理一个块
    if (ctx->buffer_length > 56)
    {
        while (ctx->buffer_length < 64)
        {
            ctx->buffer[ctx->buffer_length] = 0x00;
            ctx->buffer_length++;
        }
        sm3_compress(ctx, ctx->buffer);
        ctx->buffer_length = 0;
    }

    // 填充到56字节
    while (ctx->buffer_length < 56)
    {
        ctx->buffer[ctx->buffer_length] = 0x00;
        ctx->buffer_length++;
    }

    // 添加长度（大端序，64位）
    uint64_t bit_length = ctx->total_length;
    for (int i = 7; i >= 0; i--)
    {
        ctx->buffer[56 + i] = bit_length & 0xFF;
        bit_length >>= 8;
    }

    sm3_compress(ctx, ctx->buffer);

    // 输出哈希值（大端序）
    for (int i = 0; i < 8; i++)
    {
        u32_to_bytes_be(ctx->state[i], digest + i * 4);
    }
}

// 一次性哈希计算
void sm3_hash(const uint8_t *data, uint64_t len, uint8_t *digest)
{
    sm3_context_t ctx;
    sm3_init(&ctx);
    sm3_update(&ctx, data, len);
    sm3_final(&ctx, digest);
}

// 计算SM3填充
uint64_t sm3_calculate_padding_length(uint64_t original_length)
{
    // 原始长度（字节）
    uint64_t bit_length = original_length * 8;

    // 计算需要的填充：使得 (bit_length + 1 + padding_bits) % 512 = 448
    uint64_t after_bit = bit_length + 1; // 添加0x80标记
    uint64_t remainder = after_bit % 512;
    uint64_t padding_bits;

    if (remainder <= 448)
    {
        padding_bits = 448 - remainder;
    }
    else
    {
        padding_bits = 512 + 448 - remainder;
    }

    // 总填充长度：填充位 + 长度字段(64位)
    return (1 + padding_bits + 64) / 8; // 转换为字节
}

// 生成SM3填充数据
void sm3_generate_padding(uint64_t original_length, uint8_t *padding, uint64_t *padding_len)
{
    uint64_t bit_length = original_length * 8;

    // 计算填充长度
    *padding_len = sm3_calculate_padding_length(original_length);

    // 生成填充
    padding[0] = 0x80; // 第一个字节是0x80
    uint64_t idx = 1;

    // 计算零填充长度
    uint64_t after_bit = bit_length + 8; // 0x80占8位
    uint64_t remainder = after_bit % 512;
    uint64_t zero_padding_bits;

    if (remainder <= 448)
    {
        zero_padding_bits = 448 - remainder;
    }
    else
    {
        zero_padding_bits = 512 + 448 - remainder;
    }

    // 添加零填充
    uint64_t zero_bytes = zero_padding_bits / 8;
    memset(padding + idx, 0, zero_bytes);
    idx += zero_bytes;

    // 添加原始长度（64位大端序）
    for (int i = 7; i >= 0; i--)
    {
        padding[idx + i] = bit_length & 0xFF;
        bit_length >>= 8;
    }
}

// 从已知哈希值构造攻击上下文
void sm3_length_extension_init(sm3_context_t *ctx, const uint8_t *known_hash,
                               uint64_t known_message_length)
{
    // 从已知哈希值设置状态
    for (int i = 0; i < 8; i++)
    {
        ctx->state[i] = bytes_to_u32_be(known_hash + i * 4);
    }

    // 计算已处理的总长度（包括secret + message + padding）
    uint64_t original_bit_length = known_message_length * 8;
    uint64_t padding_length = sm3_calculate_padding_length(known_message_length);
    ctx->total_length = original_bit_length + padding_length * 8;

    ctx->buffer_length = 0;
    memset(ctx->buffer, 0, 64);
}

// 打印十六进制数据
void print_hex(const char *label, const uint8_t *data, int len)
{
    printf("%s: ", label);
    for (int i = 0; i < len; i++)
    {
        printf("%02x", data[i]);
    }
    printf("\n");
}

// 演示长度扩展攻击
void demonstrate_length_extension_attack()
{
    printf("=== SM3 长度扩展攻击演示 ===\n\n");

    // 1. 模拟场景设置
    const char *secret = "my_secret_key";
    const char *original_message = "transfer 100 yuan to alice";
    const char *additional_message = " and 999 yuan to mallory";

    printf("1. 攻击场景设置:\n");
    printf("   Secret: \"%s\" (攻击者未知)\n", secret);
    printf("   Original message: \"%s\"\n", original_message);
    printf("   Additional message: \"%s\" (攻击者想要添加)\n", additional_message);
    printf("\n");

    // 2. 计算原始认证标签 H(secret||message)
    uint64_t combined_length = strlen(secret) + strlen(original_message);
    uint8_t *combined = malloc(combined_length);
    memcpy(combined, secret, strlen(secret));
    memcpy(combined + strlen(secret), original_message, strlen(original_message));

    uint8_t original_hash[SM3_DIGEST_SIZE];
    sm3_hash(combined, combined_length, original_hash);

    print_hex("2. 原始认证标签 H(secret||message)", original_hash, SM3_DIGEST_SIZE);
    printf("\n");

    // 3. 攻击者已知信息
    printf("3. 攻击者已知信息:\n");
    printf("   - 原始消息: \"%s\"\n", original_message);
    printf("   - 原始消息长度: %zu bytes\n", strlen(original_message));
    printf("   - 认证标签: ");
    for (int i = 0; i < SM3_DIGEST_SIZE; i++)
    {
        printf("%02x", original_hash[i]);
    }
    printf("\n");
    printf("   - Secret长度: %zu bytes (通过某种方式获得，如配置泄漏)\n", strlen(secret));
    printf("\n");

    // 4. 构造长度扩展攻击
    printf("4. 构造长度扩展攻击:\n");

    // 生成填充
    uint8_t padding[128];
    uint64_t padding_length;
    sm3_generate_padding(combined_length, padding, &padding_length);

    printf("   - 原始消息填充长度: %llu bytes\n", (unsigned long long)padding_length);
    print_hex("   - 填充数据", padding, padding_length);

    // 从已知哈希值开始构造新的哈希
    sm3_context_t attack_ctx;
    sm3_length_extension_init(&attack_ctx, original_hash, combined_length);

    // 添加攻击者的消息
    sm3_update(&attack_ctx, (const uint8_t *)additional_message, strlen(additional_message));

    uint8_t forged_hash[SM3_DIGEST_SIZE];
    sm3_final(&attack_ctx, forged_hash);

    print_hex("   - 伪造的认证标签", forged_hash, SM3_DIGEST_SIZE);
    printf("\n");

    // 5. 验证攻击是否成功
    printf("5. 验证攻击结果:\n");

    // 构造完整的伪造消息
    uint64_t forged_message_length = combined_length + padding_length + strlen(additional_message);
    uint8_t *forged_message = malloc(forged_message_length);

    // 组装: secret || original_message || padding || additional_message
    uint64_t offset = 0;
    memcpy(forged_message + offset, secret, strlen(secret));
    offset += strlen(secret);
    memcpy(forged_message + offset, original_message, strlen(original_message));
    offset += strlen(original_message);
    memcpy(forged_message + offset, padding, padding_length);
    offset += padding_length;
    memcpy(forged_message + offset, additional_message, strlen(additional_message));

    // 重新计算哈希验证
    uint8_t verification_hash[SM3_DIGEST_SIZE];
    sm3_hash(forged_message, forged_message_length, verification_hash);

    print_hex("   - 重新计算的哈希", verification_hash, SM3_DIGEST_SIZE);

    // 检查是否匹配
    int attack_successful = memcmp(forged_hash, verification_hash, SM3_DIGEST_SIZE) == 0;
    printf("   - 攻击结果: %s\n", attack_successful ? "✅ 成功" : "❌ 失败");

    if (attack_successful)
    {
        printf("\n✅ 长度扩展攻击成功！\n");
        printf("攻击者在不知道secret的情况下，成功伪造了包含额外消息的认证标签。\n");

        // 显示伪造的完整消息（不包含secret部分）
        printf("\n伪造的消息结构:\n");
        printf("Secret部分: [HIDDEN] (%zu bytes)\n", strlen(secret));
        printf("原始消息: \"%s\"\n", original_message);
        printf("填充数据: ");
        for (uint64_t i = 0; i < padding_length; i++)
        {
            printf("%02x ", padding[i]);
        }
        printf("(%llu bytes)\n", (unsigned long long)padding_length);
        printf("恶意添加: \"%s\"\n", additional_message);
        printf("总长度: %llu bytes\n", (unsigned long long)forged_message_length);
    }

    // 清理内存
    free(combined);
    free(forged_message);

    printf("\n=== 攻击分析 ===\n");
    printf("1. 攻击原理: SM3采用Merkle-Damgård结构，哈希状态只依赖于前面的输入\n");
    printf("2. 攻击条件: 已知H(secret||message)、message长度、secret长度\n");
    printf("3. 攻击结果: 可伪造H(secret||message||padding||additional_message)\n");
    printf("4. 防护措施: 使用HMAC、基于海绵结构的哈希函数(如SHA-3)等\n");
}

// 测试不同场景的长度扩展攻击
void test_various_scenarios()
{
    printf("\n=== 不同场景测试 ===\n\n");

    struct
    {
        const char *secret;
        const char *message;
        const char *additional;
    } test_cases[] = {
        {"key", "hello", "world"},
        {"secret123", "login=admin", "&role=superuser"},
        {"0123456789abcdef", "amount=100", "&recipient=attacker"},
        {"x", "", "malicious_payload"},
    };

    for (int i = 0; i < sizeof(test_cases) / sizeof(test_cases[0]); i++)
    {
        printf("测试案例 %d:\n", i + 1);
        printf("Secret: \"%s\", Message: \"%s\", Additional: \"%s\"\n",
               test_cases[i].secret, test_cases[i].message, test_cases[i].additional);

        // 计算原始哈希
        uint64_t combined_len = strlen(test_cases[i].secret) + strlen(test_cases[i].message);
        uint8_t *combined = malloc(combined_len);
        memcpy(combined, test_cases[i].secret, strlen(test_cases[i].secret));
        memcpy(combined + strlen(test_cases[i].secret), test_cases[i].message, strlen(test_cases[i].message));

        uint8_t original_hash[SM3_DIGEST_SIZE];
        sm3_hash(combined, combined_len, original_hash);

        // 执行长度扩展攻击
        sm3_context_t attack_ctx;
        sm3_length_extension_init(&attack_ctx, original_hash, combined_len);
        sm3_update(&attack_ctx, (const uint8_t *)test_cases[i].additional, strlen(test_cases[i].additional));

        uint8_t forged_hash[SM3_DIGEST_SIZE];
        sm3_final(&attack_ctx, forged_hash);

        // 验证
        uint8_t padding[128];
        uint64_t padding_len;
        sm3_generate_padding(combined_len, padding, &padding_len);

        uint64_t total_len = combined_len + padding_len + strlen(test_cases[i].additional);
        uint8_t *full_message = malloc(total_len);
        uint64_t offset = 0;
        memcpy(full_message + offset, combined, combined_len);
        offset += combined_len;
        memcpy(full_message + offset, padding, padding_len);
        offset += padding_len;
        memcpy(full_message + offset, test_cases[i].additional, strlen(test_cases[i].additional));

        uint8_t verify_hash[SM3_DIGEST_SIZE];
        sm3_hash(full_message, total_len, verify_hash);

        int success = memcmp(forged_hash, verify_hash, SM3_DIGEST_SIZE) == 0;
        printf("结果: %s\n\n", success ? "✅ 成功" : "❌ 失败");

        free(combined);
        free(full_message);
    }
}

int main()
{
    printf("SM3 长度扩展攻击验证程序\n");
    printf("========================================\n\n");

    // 主要演示
    demonstrate_length_extension_attack();

    // 多场景测试
    test_various_scenarios();

    printf("程序执行完成。\n");
    return 0;
}
