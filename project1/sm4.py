class SM4:
    """SM4对称加密算法实现"""
    
    # S盒
    S_BOX = [
        0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
        0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
        0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
        0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
        0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
        0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
        0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
        0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
        0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
        0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
        0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
        0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
        0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
        0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
        0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
        0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
    ]
    
    # 固定参数FK
    FK = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc]
    
    # 固定参数CK
    CK = [
        0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
        0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
        0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
        0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
        0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
        0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
        0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
        0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
    ]
    
    def __init__(self):
        self.round_keys = []
    
    def _s_box(self, byte_val):
        """S盒变换"""
        return self.S_BOX[byte_val]
    
    def _tau(self, word):
        """非线性变换τ"""
        a = (word >> 24) & 0xff
        b = (word >> 16) & 0xff
        c = (word >> 8) & 0xff
        d = word & 0xff
        
        return (self._s_box(a) << 24) | (self._s_box(b) << 16) | (self._s_box(c) << 8) | self._s_box(d)
    
    def _rotl(self, value, shift):
        """循环左移"""
        return ((value << shift) | (value >> (32 - shift))) & 0xffffffff
    
    def _l(self, word):
        """线性变换L"""
        return word ^ self._rotl(word, 2) ^ self._rotl(word, 10) ^ self._rotl(word, 18) ^ self._rotl(word, 24)
    
    def _l_prime(self, word):
        """线性变换L'（用于密钥扩展）"""
        return word ^ self._rotl(word, 13) ^ self._rotl(word, 23)
    
    def _t(self, word):
        """合成置换T"""
        return self._l(self._tau(word))
    
    def _t_prime(self, word):
        """合成置换T'（用于密钥扩展）"""
        return self._l_prime(self._tau(word))
    
    def _key_expansion(self, key):
        """密钥扩展算法"""
        if len(key) != 16:
            raise ValueError("密钥长度必须为16字节")
        
        # 将密钥转换为4个32位字
        mk = []
        for i in range(4):
            word = (key[i*4] << 24) | (key[i*4+1] << 16) | (key[i*4+2] << 8) | key[i*4+3]
            mk.append(word)
        
        # 生成中间密钥K
        k = [mk[i] ^ self.FK[i] for i in range(4)]
        
        # 生成轮密钥
        self.round_keys = []
        for i in range(32):
            rk = k[0] ^ self._t_prime(k[1] ^ k[2] ^ k[3] ^ self.CK[i])
            self.round_keys.append(rk)
            k = k[1:] + [rk]
    
    def _round_function(self, x0, x1, x2, x3, rk):
        """轮函数F"""
        return x0 ^ self._t(x1 ^ x2 ^ x3 ^ rk)
    
    def _bytes_to_words(self, data):
        """将字节数组转换为32位字数组"""
        words = []
        for i in range(0, len(data), 4):
            word = (data[i] << 24) | (data[i+1] << 16) | (data[i+2] << 8) | data[i+3]
            words.append(word)
        return words
    
    def _words_to_bytes(self, words):
        """将32位字数组转换为字节数组"""
        data = []
        for word in words:
            data.extend([
                (word >> 24) & 0xff,
                (word >> 16) & 0xff,
                (word >> 8) & 0xff,
                word & 0xff
            ])
        return bytes(data)
    
    def encrypt_block(self, plaintext):
        """加密单个16字节数据块"""
        if len(plaintext) != 16:
            raise ValueError("数据块长度必须为16字节")
        
        # 转换为32位字
        x = self._bytes_to_words(plaintext)
        
        # 32轮加密
        for i in range(32):
            x[0], x[1], x[2], x[3] = x[1], x[2], x[3], self._round_function(x[0], x[1], x[2], x[3], self.round_keys[i])
        
        # 反序变换
        result = [x[3], x[2], x[1], x[0]]
        return self._words_to_bytes(result)
    
    def decrypt_block(self, ciphertext):
        """解密单个16字节数据块"""
        if len(ciphertext) != 16:
            raise ValueError("数据块长度必须为16字节")
        
        # 转换为32位字
        x = self._bytes_to_words(ciphertext)
        
        # 32轮解密（使用逆序轮密钥）
        for i in range(32):
            x[0], x[1], x[2], x[3] = x[1], x[2], x[3], self._round_function(x[0], x[1], x[2], x[3], self.round_keys[31-i])
        
        # 反序变换
        result = [x[3], x[2], x[1], x[0]]
        return self._words_to_bytes(result)
    
    def encrypt(self, plaintext, key):
        """加密（自动处理PKCS7填充）"""
        self._key_expansion(key)
        
        # PKCS7填充
        padding_len = 16 - (len(plaintext) % 16)
        padded_data = plaintext + bytes([padding_len] * padding_len)
        
        result = b''
        for i in range(0, len(padded_data), 16):
            block = padded_data[i:i+16]
            result += self.encrypt_block(block)
        
        return result
    
    def decrypt(self, ciphertext, key):
        """解密（自动去除PKCS7填充）"""
        if len(ciphertext) % 16 != 0:
            raise ValueError("密文长度必须是16的倍数")
        
        self._key_expansion(key)
        
        result = b''
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i+16]
            result += self.decrypt_block(block)
        
        # 去除PKCS7填充
        padding_len = result[-1]
        return result[:-padding_len]

class OptimizedSM4_for_T_Table:
    def __init__(self):
        # 原始S盒
        self.S_BOX = [
            0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
            0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
            0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
            0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
            0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
            0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
            0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
            0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
            0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
            0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
            0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
            0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
            0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
            0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
            0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
            0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
        ]
        
        # 预计算T表 - 这是关键优化
        self._precompute_tables()
        
        # FK常数
        self.FK = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc]
        
        # CK常数
        self.CK = self._generate_ck()

    def _precompute_tables(self):
        """预计算T表，将S盒变换和线性变换L合并"""
        self.T0 = [0] * 256
        self.T1 = [0] * 256
        self.T2 = [0] * 256
        self.T3 = [0] * 256
        
        for i in range(256):
            s = self.S_BOX[i]
            # 计算L变换：L(B) = B ⊕ (B<<<2) ⊕ (B<<<10) ⊕ (B<<<18) ⊕ (B<<<24)
            t = s ^ self._rotl32(s, 2) ^ self._rotl32(s, 10) ^ self._rotl32(s, 18) ^ self._rotl32(s, 24)
            
            # 预计算不同字节位置的T表
            self.T0[i] = t & 0xffffffff
            self.T1[i] = self._rotl32(t, 8) & 0xffffffff
            self.T2[i] = self._rotl32(t, 16) & 0xffffffff
            self.T3[i] = self._rotl32(t, 24) & 0xffffffff

    def _generate_ck(self):
        """生成CK常数"""
        ck = []
        for i in range(32):
            k = (7 * (i // 4) + i % 4) * 4 + 7
            ck.append(k * 0x01010101)
        return ck

    def _rotl32(self, x, n):
        """32位循环左移"""
        return ((x << n) | (x >> (32 - n))) & 0xffffffff

    def _bytes_to_uint32(self, data):
        """字节数组转32位整数"""
        return (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3]

    def _uint32_to_bytes(self, x):
        """32位整数转字节数组"""
        return [(x >> 24) & 0xff, (x >> 16) & 0xff, (x >> 8) & 0xff, x & 0xff]

    def _optimized_t_transform(self, x):
        """优化的T变换，使用预计算的T表"""
        b0 = (x >> 24) & 0xff
        b1 = (x >> 16) & 0xff
        b2 = (x >> 8) & 0xff
        b3 = x & 0xff
        
        # 使用T表进行快速查表
        return (self.T0[b0] ^ self.T1[b1] ^ self.T2[b2] ^ self.T3[b3]) & 0xffffffff

    def _key_schedule_transform(self, x):
        """密钥扩展中的T'变换"""
        # S盒变换
        b0 = self.S_BOX[(x >> 24) & 0xff]
        b1 = self.S_BOX[(x >> 16) & 0xff]
        b2 = self.S_BOX[(x >> 8) & 0xff]
        b3 = self.S_BOX[x & 0xff]
        
        s_result = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
        
        # L'变换：L'(B) = B ⊕ (B<<<13) ⊕ (B<<<23)
        return (s_result ^ self._rotl32(s_result, 13) ^ self._rotl32(s_result, 23)) & 0xffffffff

    def _expand_key(self, key):
        """密钥扩展算法"""
        if len(key) != 16:
            raise ValueError("密钥长度必须为16字节")
        
        # 将密钥分为4个32位字
        mk = []
        for i in range(4):
            mk.append(self._bytes_to_uint32(key[i*4:(i+1)*4]))
        
        # 计算K0, K1, K2, K3
        k = [0] * 36
        for i in range(4):
            k[i] = mk[i] ^ self.FK[i]
        
        # 生成轮密钥
        rk = []
        for i in range(32):
            k[i+4] = k[i] ^ self._key_schedule_transform(k[i+1] ^ k[i+2] ^ k[i+3] ^ self.CK[i])
            rk.append(k[i+4])
        
        return rk

    def _encrypt_block(self, plaintext, round_keys):
        """单块加密"""
        if len(plaintext) != 16:
            raise ValueError("明文块长度必须为16字节")
        
        # 将明文分为4个32位字
        x = []
        for i in range(4):
            x.append(self._bytes_to_uint32(plaintext[i*4:(i+1)*4]))
        
        # 32轮迭代
        for i in range(32):
            # 使用优化的T变换
            temp = x[1] ^ x[2] ^ x[3] ^ round_keys[i]
            x[0] = x[0] ^ self._optimized_t_transform(temp)
            # 轮换
            x[0], x[1], x[2], x[3] = x[1], x[2], x[3], x[0]
        
        # 反序变换
        x[0], x[1], x[2], x[3] = x[3], x[2], x[1], x[0]
        
        # 转换为字节
        result = []
        for i in range(4):
            result.extend(self._uint32_to_bytes(x[i]))
        
        return bytes(result)

    def _decrypt_block(self, ciphertext, round_keys):
        """单块解密"""
        if len(ciphertext) != 16:
            raise ValueError("密文块长度必须为16字节")
        
        # 解密使用逆序的轮密钥
        reverse_keys = round_keys[::-1]
        return self._encrypt_block(ciphertext, reverse_keys)

    def _pkcs7_pad(self, data):
        """PKCS7填充"""
        pad_len = 16 - (len(data) % 16)
        return data + bytes([pad_len] * pad_len)

    def _pkcs7_unpad(self, data):
        """PKCS7去填充"""
        if len(data) == 0:
            raise ValueError("数据为空")
        pad_len = data[-1]
        if pad_len > 16 or pad_len == 0:
            raise ValueError("填充格式错误")
        return data[:-pad_len]

    def encrypt(self, plaintext, key, mode='ECB'):
        """加密接口"""
        round_keys = self._expand_key(key)
        padded_plaintext = self._pkcs7_pad(plaintext)
        
        result = b''
        for i in range(0, len(padded_plaintext), 16):
            block = padded_plaintext[i:i+16]
            encrypted_block = self._encrypt_block(block, round_keys)
            result += encrypted_block
        
        return result

    def decrypt(self, ciphertext, key, mode='ECB'):
        """解密接口"""
        if len(ciphertext) % 16 != 0:
            raise ValueError("密文长度必须是16的倍数")
        
        round_keys = self._expand_key(key)
        
        result = b''
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i+16]
            decrypted_block = self._decrypt_block(block, round_keys)
            result += decrypted_block
        
        return self._pkcs7_unpad(result)




# 使用示例
if __name__ == "__main__":
    # 创建SM4实例
    #sm4 = SM4()
    sm4 = OptimizedSM4_for_T_Table()
    
    # 测试密钥和明文
    key = b'1234567890abcdef'  # 16字节密钥
    plaintext = b'Hello, SM4 Algorithm!'
    
    print(f"原文: {plaintext}")
    print(f"密钥: {key}")
    
    # 加密
    ciphertext = sm4.encrypt(plaintext, key)
    print(f"密文: {ciphertext.hex()}")
    
    # 解密
    decrypted = sm4.decrypt(ciphertext, key)
    print(f"解密: {decrypted}")
    
    # 验证
    print(f"验证成功: {plaintext == decrypted}")
