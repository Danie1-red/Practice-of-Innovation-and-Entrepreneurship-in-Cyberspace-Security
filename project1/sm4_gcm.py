# SM4-GCM 工作模式软件优化实现

import struct
import time
from typing import List, Tuple, Optional
from sm4 import OptimizedSM4_for_T_Table, SM4_AESNI_Optimized, SM4_ModernISA_Optimized


class SM4_GCM_Base:
    """SM4-GCM基础实现类"""
    
    def __init__(self, key: bytes, use_optimization='ttable'):
        """
        初始化SM4-GCM
        
        Args:
            key: 16字节密钥
            use_optimization: 优化方式 ('basic', 'ttable', 'aesni', 'modern')
        """
        if len(key) != 16:
            raise ValueError("密钥长度必须为16字节")
        
        self.key = key
        
        # 根据优化方式选择SM4实现
        if use_optimization == 'ttable':
            self.sm4 = OptimizedSM4_for_T_Table()
        elif use_optimization == 'aesni':
            self.sm4 = SM4_AESNI_Optimized()
        elif use_optimization == 'modern':
            self.sm4 = SM4_ModernISA_Optimized()
        else:
            from sm4 import SM4
            self.sm4 = SM4()
        
        # GCM参数
        self.block_size = 16
        self.tag_size = 16
        
        # 预计算GF(2^128)乘法表
        self._precompute_galois_tables()
    
    def _sm4_encrypt_block(self, block: bytes) -> bytes:
        """统一的SM4块加密接口"""
        if hasattr(self.sm4, 'encrypt_block'):
            # 某些实现可能有专门的块加密方法
            return self.sm4.encrypt_block(block)
        elif hasattr(self.sm4, 'encrypt'):
            # 使用标准加密方法
            return self.sm4.encrypt(block, self.key)[:16]  # 只取一个块
        else:
            raise NotImplementedError("SM4实现缺少加密方法")
    
    def _precompute_galois_tables(self):
        """预计算GF(2^128)域上的乘法表用于加速GHASH"""
        # GF(2^128)的不可约多项式: x^128 + x^7 + x^2 + x + 1
        self.reduction_table = [0] * 256
        
        for i in range(256):
            v = i
            for _ in range(8):
                if v & 1:
                    v = (v >> 1) ^ 0xE1000000000000000000000000000000
                else:
                    v >>= 1
            self.reduction_table[i] = v
    
    def _ghash_gfmul(self, x: int, y: int) -> int:
        """
        GF(2^128)域上的乘法运算
        
        Args:
            x, y: 128位整数
            
        Returns:
            x * y mod (x^128 + x^7 + x^2 + x + 1)
        """
        result = 0
        
        for i in range(128):
            if y & (1 << i):
                result ^= x << i
        
        # 模约简
        for i in range(127, -1, -1):
            if result & (1 << (128 + i)):
                result ^= (0x87 << i)  # x^128 + x^7 + x^2 + x + 1的表示
        
        return result & ((1 << 128) - 1)
    
    def _ghash_optimized_gfmul(self, x_bytes: bytes, y_bytes: bytes) -> bytes:
        """
        优化的GF(2^128)乘法，使用查表法
        
        Args:
            x_bytes, y_bytes: 16字节输入
            
        Returns:
            16字节乘法结果
        """
        x = int.from_bytes(x_bytes, 'big')
        y = int.from_bytes(y_bytes, 'big')
        
        # 分解为8位组件进行查表计算
        result = 0
        
        for i in range(16):
            byte_val = (y >> (8 * (15 - i))) & 0xFF
            if byte_val:
                shifted_x = x << (8 * i)
                # 使用预计算的约简表
                for j in range(8):
                    if byte_val & (1 << j):
                        result ^= shifted_x << j
        
        # 约简结果到128位
        for i in range(255, 127, -1):
            if result & (1 << i):
                result ^= (0x87 << (i - 128))
        
        return (result & ((1 << 128) - 1)).to_bytes(16, 'big')
    
    def _ghash(self, auth_data: bytes, ciphertext: bytes, h: bytes) -> bytes:
        """
        GHASH认证函数
        
        Args:
            auth_data: 附加认证数据
            ciphertext: 密文数据
            h: Hash子密钥 (E_k(0^128))
            
        Returns:
            16字节认证标签
        """
        # 填充数据到16字节边界
        auth_len = len(auth_data)
        cipher_len = len(ciphertext)
        
        # 填充auth_data
        if auth_len % 16:
            auth_data += b'\x00' * (16 - (auth_len % 16))
        
        # 填充ciphertext
        if cipher_len % 16:
            ciphertext += b'\x00' * (16 - (cipher_len % 16))
        
        # 连接数据
        data = auth_data + ciphertext
        
        # 添加长度信息
        len_block = struct.pack('>QQ', auth_len * 8, cipher_len * 8)
        data += len_block
        
        # GHASH计算
        y = b'\x00' * 16
        
        for i in range(0, len(data), 16):
            block = data[i:i+16]
            y = bytes(a ^ b for a, b in zip(y, block))
            y = self._ghash_optimized_gfmul(y, h)
        
        return y
    
    def _gctr(self, icb: bytes, plaintext: bytes) -> bytes:
        """
        GCTR加密函数 (Counter Mode)
        
        Args:
            icb: 初始计数器块
            plaintext: 明文
            
        Returns:
            密文
        """
        if not plaintext:
            return b''
        
        ciphertext = bytearray()
        counter = int.from_bytes(icb, 'big')
        
        for i in range(0, len(plaintext), 16):
            # 生成计数器块
            counter_block = (counter + i // 16).to_bytes(16, 'big')
            
            # 加密计数器块
            encrypted_counter = self._sm4_encrypt_block(counter_block)
            
            # 与明文异或
            chunk = plaintext[i:i+16]
            for j in range(len(chunk)):
                ciphertext.append(chunk[j] ^ encrypted_counter[j])
        
        return bytes(ciphertext)
    
    def encrypt(self, iv: bytes, plaintext: bytes, auth_data: bytes = b'') -> Tuple[bytes, bytes]:
        """
        SM4-GCM加密
        
        Args:
            iv: 初始化向量 (12字节推荐)
            plaintext: 明文
            auth_data: 附加认证数据
            
        Returns:
            (密文, 认证标签)
        """
        if len(iv) != 12:
            raise ValueError("推荐使用12字节IV")
        
        # 生成Hash子密钥
        h = self._sm4_encrypt_block(b'\x00' * 16)
        
        # 构造初始计数器
        icb = iv + b'\x00\x00\x00\x01'
        
        # GCTR加密
        ciphertext = self._gctr(icb, plaintext)
        
        # 计算认证标签
        s = self._ghash(auth_data, ciphertext, h)
        
        # 计算最终标签
        tag_icb = iv + b'\x00\x00\x00\x01'
        tag_mask = self._sm4_encrypt_block(tag_icb)
        tag = bytes(a ^ b for a, b in zip(s, tag_mask))
        
        return ciphertext, tag
    
    def decrypt(self, iv: bytes, ciphertext: bytes, tag: bytes, auth_data: bytes = b'') -> bytes:
        """
        SM4-GCM解密
        
        Args:
            iv: 初始化向量
            ciphertext: 密文
            tag: 认证标签
            auth_data: 附加认证数据
            
        Returns:
            明文
            
        Raises:
            ValueError: 认证失败
        """
        if len(iv) != 12:
            raise ValueError("推荐使用12字节IV")
        
        # 生成Hash子密钥
        h = self._sm4_encrypt_block(b'\x00' * 16)
        
        # 验证认证标签
        s = self._ghash(auth_data, ciphertext, h)
        tag_icb = iv + b'\x00\x00\x00\x01'
        tag_mask = self._sm4_encrypt_block(tag_icb)
        expected_tag = bytes(a ^ b for a, b in zip(s, tag_mask))
        
        if tag != expected_tag:
            raise ValueError("认证标签验证失败")
        
        # GCTR解密 (与加密相同)
        icb = iv + b'\x00\x00\x00\x01'
        plaintext = self._gctr(icb, ciphertext)
        
        return plaintext


class SM4_GCM_Optimized(SM4_GCM_Base):
    """优化的SM4-GCM实现"""
    
    def __init__(self, key: bytes, use_optimization='ttable'):
        super().__init__(key, use_optimization)
        
        # 预计算优化表
        self._precompute_ghash_tables()
        
        # 支持的优化特性
        self.supports_parallel = True
        self.supports_aesni_gcm = hasattr(self.sm4, 'aesni_supported')
    
    def _precompute_ghash_tables(self):
        """预计算GHASH优化表"""
        # 预计算H的幂次
        h_zero = self._sm4_encrypt_block(b'\x00' * 16)
        
        self.h_powers = [b'\x00' * 16]  # H^0 = 0
        self.h_powers.append(h_zero)    # H^1
        
        # 预计算H^2, H^3, ..., H^8用于并行处理
        for i in range(2, 9):
            hi = self._ghash_optimized_gfmul(self.h_powers[i-1], h_zero)
            self.h_powers.append(hi)
        
        # 为查表优化预计算更多值
        self.ghash_table = {}
        for i in range(256):
            key_bytes = i.to_bytes(1, 'big') + b'\x00' * 15
            self.ghash_table[i] = self._ghash_optimized_gfmul(key_bytes, h_zero)
    
    def _parallel_ghash(self, data_blocks: List[bytes], h: bytes) -> bytes:
        """
        并行GHASH计算
        
        Args:
            data_blocks: 16字节块列表
            h: Hash子密钥
            
        Returns:
            GHASH结果
        """
        if len(data_blocks) <= 4:
            # 数据量较小，使用标准方法
            return self._sequential_ghash(data_blocks, h)
        
        # 并行处理多个块
        num_blocks = len(data_blocks)
        y = b'\x00' * 16
        
        # 每次处理8个块以充分利用预计算的幂次
        for i in range(0, num_blocks, 8):
            batch = data_blocks[i:i+8]
            batch_result = b'\x00' * 16
            
            # 并行计算这批块的贡献
            for j, block in enumerate(batch):
                if j < len(self.h_powers) - 1:
                    contribution = self._ghash_optimized_gfmul(block, self.h_powers[len(batch)-j])
                    batch_result = bytes(a ^ b for a, b in zip(batch_result, contribution))
            
            y = bytes(a ^ b for a, b in zip(y, batch_result))
            if i + 8 < num_blocks:
                y = self._ghash_optimized_gfmul(y, self.h_powers[min(8, num_blocks - i - 8)])
        
        return y
    
    def _sequential_ghash(self, data_blocks: List[bytes], h: bytes) -> bytes:
        """标准顺序GHASH计算"""
        y = b'\x00' * 16
        
        for block in data_blocks:
            y = bytes(a ^ b for a, b in zip(y, block))
            y = self._ghash_optimized_gfmul(y, h)
        
        return y
    
    def _optimized_gctr(self, icb: bytes, plaintext: bytes) -> bytes:
        """
        优化的GCTR函数，支持并行加密
        
        Args:
            icb: 初始计数器块
            plaintext: 明文
            
        Returns:
            密文
        """
        if not plaintext:
            return b''
        
        # 计算需要的块数
        num_blocks = (len(plaintext) + 15) // 16
        counter_base = int.from_bytes(icb, 'big')
        
        # 如果支持并行处理且块数较多
        if self.supports_parallel and num_blocks >= 4:
            return self._parallel_gctr(icb, plaintext, num_blocks)
        else:
            return self._gctr(icb, plaintext)
    
    def _parallel_gctr(self, icb: bytes, plaintext: bytes, num_blocks: int) -> bytes:
        """并行GCTR处理"""
        ciphertext = bytearray()
        counter_base = int.from_bytes(icb, 'big')
        
        # 每次并行处理4个块
        for i in range(0, num_blocks, 4):
            batch_size = min(4, num_blocks - i)
            
            # 准备计数器块
            counter_blocks = []
            for j in range(batch_size):
                counter = (counter_base + i + j).to_bytes(16, 'big')
                counter_blocks.append(counter)
            
            # 并行加密计数器块
            encrypted_counters = self._parallel_encrypt_blocks(counter_blocks)
            
            # 与明文异或
            for j in range(batch_size):
                block_start = (i + j) * 16
                block_end = min(block_start + 16, len(plaintext))
                chunk = plaintext[block_start:block_end]
                
                encrypted_counter = encrypted_counters[j]
                for k in range(len(chunk)):
                    ciphertext.append(chunk[k] ^ encrypted_counter[k])
        
        return bytes(ciphertext)
    
    def _parallel_encrypt_blocks(self, blocks: List[bytes]) -> List[bytes]:
        """并行加密多个块"""
        # 如果SM4实现支持并行处理
        if hasattr(self.sm4, '_parallel_encrypt_blocks'):
            return self.sm4._parallel_encrypt_blocks(blocks)
        else:
            # 回退到顺序处理
            return [self._sm4_encrypt_block(block) for block in blocks]
    
    def encrypt(self, iv: bytes, plaintext: bytes, auth_data: bytes = b'') -> Tuple[bytes, bytes]:
        """
        SM4-GCM加密
        
        Args:
            iv: 初始化向量 (12字节推荐)
            plaintext: 明文
            auth_data: 附加认证数据
            
        Returns:
            (密文, 认证标签)
        """
        if len(iv) != 12:
            raise ValueError("推荐使用12字节IV")
        
        # 生成Hash子密钥
        h = self._sm4_encrypt_block(b'\x00' * 16)
        
        # 构造初始计数器
        icb = iv + b'\x00\x00\x00\x01'
        
        # GCTR加密
        ciphertext = self._optimized_gctr(icb, plaintext)
        
        # 计算认证标签
        s = self._ghash(auth_data, ciphertext, h)
        
        # 计算最终标签
        tag_icb = iv + b'\x00\x00\x00\x01'
        tag_mask = self._sm4_encrypt_block(tag_icb)
        tag = bytes(a ^ b for a, b in zip(s, tag_mask))
        
        return ciphertext, tag
    
    def decrypt(self, iv: bytes, ciphertext: bytes, tag: bytes, auth_data: bytes = b'') -> bytes:
        """
        SM4-GCM解密
        
        Args:
            iv: 初始化向量
            ciphertext: 密文
            tag: 认证标签
            auth_data: 附加认证数据
            
        Returns:
            明文
            
        Raises:
            ValueError: 认证失败
        """
        if len(iv) != 12:
            raise ValueError("推荐使用12字节IV")
        
        # 生成Hash子密钥
        h = self._sm4_encrypt_block(b'\x00' * 16)
        
        # 验证认证标签
        s = self._ghash(auth_data, ciphertext, h)
        tag_icb = iv + b'\x00\x00\x00\x01'
        tag_mask = self._sm4_encrypt_block(tag_icb)
        expected_tag = bytes(a ^ b for a, b in zip(s, tag_mask))
        
        if tag != expected_tag:
            raise ValueError("认证标签验证失败")
        
        # GCTR解密 (与加密相同)
        icb = iv + b'\x00\x00\x00\x01'
        plaintext = self._optimized_gctr(icb, ciphertext)
        
        return plaintext


class SM4_GCM_Advanced(SM4_GCM_Optimized):
    """高级优化的SM4-GCM实现"""
    
    def __init__(self, key: bytes, use_optimization='ttable'):
        super().__init__(key, use_optimization)
        
        # 高级优化特性
        self.cache_size = 1024  # 缓存大小
        self.ghash_cache = {}   # GHASH结果缓存
        self.counter_cache = {} # 计数器加密缓存
        
        # 预计算更多优化表
        self._precompute_advanced_tables()
    
    def _precompute_advanced_tables(self):
        """预计算高级优化表"""
        # 预计算常用IV的初始化向量
        self.common_ivs = {}
        
        # 预计算H的更多幂次用于更大的并行度
        h = self._sm4_encrypt_block(b'\x00' * 16)
        
        # 扩展到H^16以支持更大的并行处理
        while len(self.h_powers) < 17:
            next_power = self._ghash_optimized_gfmul(self.h_powers[-1], h)
            self.h_powers.append(next_power)
        
        # 预计算字节级别的GHASH表
        self.byte_ghash_tables = []
        for byte_pos in range(16):
            table = {}
            for val in range(256):
                block = bytearray(16)
                block[byte_pos] = val
                table[val] = self._ghash_optimized_gfmul(bytes(block), h)
            self.byte_ghash_tables.append(table)
    
    def _ultra_fast_ghash(self, data_blocks: List[bytes], h: bytes) -> bytes:
        """
        超快速GHASH实现，使用字节级查表
        
        Args:
            data_blocks: 数据块列表
            h: Hash子密钥
            
        Returns:
            GHASH结果
        """
        if len(data_blocks) == 0:
            return b'\x00' * 16
        
        # 使用字节级查表加速
        result = b'\x00' * 16
        
        for block in data_blocks:
            # 与当前结果异或
            result = bytes(a ^ b for a, b in zip(result, block))
            
            # 使用预计算的字节表快速计算GF乘法
            new_result = bytearray(16)
            for byte_pos in range(16):
                byte_val = result[byte_pos]
                contribution = self.byte_ghash_tables[byte_pos][byte_val]
                for i in range(16):
                    new_result[i] ^= contribution[i]
            
            result = bytes(new_result)
        
        return result
    
    def encrypt_stream(self, iv: bytes, plaintext_stream, auth_data: bytes = b'', 
                      chunk_size: int = 8192) -> Tuple[bytes, bytes]:
        """
        流式加密，适用于大文件
        
        Args:
            iv: 初始化向量
            plaintext_stream: 明文流（可迭代对象）
            auth_data: 附加认证数据
            chunk_size: 处理块大小
            
        Returns:
            (密文, 认证标签)
        """
        if len(iv) != 12:
            raise ValueError("推荐使用12字节IV")
        
        # 初始化
        h = self._sm4_encrypt_block(b'\x00' * 16)
        icb = iv + b'\x00\x00\x00\x01'
        
        ciphertext_chunks = []
        all_cipher_blocks = []
        counter = int.from_bytes(icb, 'big')
        
        # 处理认证数据
        auth_blocks = []
        if auth_data:
            # 填充auth_data到16字节边界
            auth_len = len(auth_data)
            if auth_len % 16:
                auth_data += b'\x00' * (16 - (auth_len % 16))
            
            for i in range(0, len(auth_data), 16):
                auth_blocks.append(auth_data[i:i+16])
        
        # 流式处理明文
        total_plaintext_len = 0
        
        if hasattr(plaintext_stream, 'read'):
            # 文件对象
            while True:
                chunk = plaintext_stream.read(chunk_size)
                if not chunk:
                    break
                
                total_plaintext_len += len(chunk)
                cipher_chunk = self._process_chunk(chunk, counter)
                ciphertext_chunks.append(cipher_chunk)
                
                # 收集密文块用于GHASH
                for i in range(0, len(cipher_chunk), 16):
                    block = cipher_chunk[i:i+16]
                    if len(block) < 16:
                        block += b'\x00' * (16 - len(block))
                    all_cipher_blocks.append(block)
                
                counter += (len(chunk) + 15) // 16
        else:
            # 可迭代对象
            for chunk in plaintext_stream:
                total_plaintext_len += len(chunk)
                cipher_chunk = self._process_chunk(chunk, counter)
                ciphertext_chunks.append(cipher_chunk)
                
                # 收集密文块用于GHASH
                for i in range(0, len(cipher_chunk), 16):
                    block = cipher_chunk[i:i+16]
                    if len(block) < 16:
                        block += b'\x00' * (16 - len(block))
                    all_cipher_blocks.append(block)
                
                counter += (len(chunk) + 15) // 16
        
        # 合并密文
        ciphertext = b''.join(ciphertext_chunks)
        
        # 计算GHASH
        all_blocks = auth_blocks + all_cipher_blocks
        
        # 添加长度块
        len_block = struct.pack('>QQ', len(auth_data) * 8, total_plaintext_len * 8)
        all_blocks.append(len_block)
        
        # 使用优化的GHASH
        s = self._ultra_fast_ghash(all_blocks, h)
        
        # 计算认证标签
        tag_icb = iv + b'\x00\x00\x00\x01'
        tag_mask = self._sm4_encrypt_block(tag_icb)
        tag = bytes(a ^ b for a, b in zip(s, tag_mask))
        
        return ciphertext, tag
    
    def _process_chunk(self, chunk: bytes, counter_start: int) -> bytes:
        """处理单个数据块"""
        return self._optimized_gctr((counter_start).to_bytes(16, 'big'), chunk)


if __name__ == "__main__":
    # 示例使用
    key = b'1234567890123456'  # 16字节密钥
    iv = b'123456789012'       # 12字节IV
    plaintext = b'Hello, SM4-GCM! This is a test message for authenticated encryption.'
    auth_data = b'Additional authenticated data'
    
    print("=== SM4-GCM 软件优化实现测试 ===\n")
    
    # 测试不同优化级别
    optimizations = ['basic', 'ttable', 'aesni', 'modern']
    
    for opt in optimizations:
        print(f"测试 {opt.upper()} 优化:")
        
        try:
            # 创建GCM实例
            if opt == 'basic':
                gcm = SM4_GCM_Base(key, opt)
            elif opt in ['ttable', 'aesni', 'modern']:
                gcm = SM4_GCM_Optimized(key, opt)
            
            # 性能测试
            start_time = time.time()
            
            # 加密
            ciphertext, tag = gcm.encrypt(iv, plaintext, auth_data)
            
            # 解密
            decrypted = gcm.decrypt(iv, ciphertext, tag, auth_data)
            
            end_time = time.time()
            
            # 验证正确性
            if decrypted == plaintext:
                print(f"  ✓ 正确性验证通过")
                print(f"  ✓ 加密+解密时间: {(end_time - start_time)*1000:.2f}ms")
                print(f"  ✓ 密文长度: {len(ciphertext)} 字节")
                print(f"  ✓ 认证标签: {tag.hex()}")
            else:
                print(f"  ✗ 正确性验证失败")
            
        except Exception as e:
            print(f"  ✗ 错误: {e}")
        
        print()
    
    print("=== 高级特性测试 ===\n")
    
    # 测试高级优化
    try:
        advanced_gcm = SM4_GCM_Advanced(key, 'ttable')
        
        # 流式加密测试
        large_data = b'Large data chunk ' * 1000  # 约16KB数据
        
        start_time = time.time()
        stream_cipher, stream_tag = advanced_gcm.encrypt_stream(
            iv, [large_data[i:i+1024] for i in range(0, len(large_data), 1024)], auth_data
        )
        end_time = time.time()
        
        print(f"流式加密测试:")
        print(f"  ✓ 数据大小: {len(large_data)} 字节")
        print(f"  ✓ 处理时间: {(end_time - start_time)*1000:.2f}ms")
        print(f"  ✓ 吞吐量: {len(large_data)/(end_time - start_time)/1024/1024:.2f} MB/s")
        
        # 验证流式加密结果
        regular_cipher, regular_tag = advanced_gcm.encrypt(iv, large_data, auth_data)
        if stream_cipher == regular_cipher and stream_tag == regular_tag:
            print(f"  ✓ 流式加密结果验证通过")
        else:
            print(f"  ✗ 流式加密结果验证失败")
        
    except Exception as e:
        print(f"高级特性测试错误: {e}")
