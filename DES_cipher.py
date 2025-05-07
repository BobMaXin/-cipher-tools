# 初始置换选择表PC-1
PC1 = [
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4
]

# 循环左移位数表
SHIFT = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

# 置换选择表PC-2
PC2 = [
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
]

def key_schedule(key):
    """生成16个48位的子密钥"""
    # 初始置换选择PC-1，64位->56位
    key_pc1 = permute(key, PC1, 56)
    
    # 分成左右两部分，各28位
    left = key_pc1[:28]
    right = key_pc1[28:]
    
    subkeys = []
    for i in range(16):
        # 循环左移
        left = left_shift(left, SHIFT[i])
        right = left_shift(right, SHIFT[i])
        
        # 合并左右部分
        combined = left + right
        
        # 置换选择PC-2，56位->48位
        subkey = permute(combined, PC2, 48)
        subkeys.append(subkey)
    
    return subkeys

def permute(block, table, size):
    """根据置换表进行置换"""
    return [block[x-1] for x in table]

def left_shift(bits, shift):
    """循环左移"""
    return bits[shift:] + bits[:shift]

# 初始置换表IP
IP = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
]

# 逆初始置换表IP^-1
IP_INV = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
]

# 扩展置换表E
E = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
]

# S盒
S_BOX = [
    # S1
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ],
    # S2
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    ],
    # S3
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
    ],
    # S4
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    ],
    # S5
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    ],
    # S6
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
    ],
    # S7
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
    ],
    # S8
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
    ]
]

# P置换表
P = [
    16, 7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2, 8, 24, 14,
    32, 4, 27, 3,
    9, 19, 13, 30,
    6, 22, 11, 4,
    25
]

def des_encrypt(block, key):
    """DES加密"""
    subkeys = key_schedule(key)
    return des_crypt(block, subkeys)

def des_decrypt(block, key):
    """DES解密"""
    subkeys = key_schedule(key)
    # 解密时子密钥使用顺序相反
    return des_crypt(block, subkeys[::-1])

def des_crypt(block, subkeys):
    """DES加解密核心函数"""
    # 初始置换IP
    block = permute(block, IP, 64)
    
    # 分成左右两部分，各32位
    left = block[:32]
    right = block[32:]
    
    # 16轮Feistel结构
    for i in range(16):
        # 保存右半部分
        right_old = right.copy()
        
        # 扩展置换E，32位->48位
        expanded = permute(right, E, 48)
        
        # 与子密钥异或
        expanded = xor(expanded, subkeys[i])
        
        # S盒替换，48位->32位
        sboxed = s_box_substitution(expanded)
        
        # P置换
        pboxed = permute(sboxed, P, 32)
        
        # 与左半部分异或
        right = xor(left, pboxed)
        
        # 左半部分更新为旧的右半部分
        left = right_old
    
    # 最后交换左右部分
    combined = right + left
    
    # 逆初始置换IP^-1
    ciphertext = permute(combined, IP_INV, 64)
    
    return ciphertext

def xor(bits1, bits2):
    """按位异或"""
    return [b1 ^ b2 for b1, b2 in zip(bits1, bits2)]

def s_box_substitution(bits):
    """S盒替换"""
    result = []
    for i in range(8):
        # 每6位一组
        chunk = bits[i*6:(i+1)*6]
        
        # 计算行和列
        row = (chunk[0] << 1) + chunk[5]
        col = (chunk[1] << 3) + (chunk[2] << 2) + (chunk[3] << 1) + chunk[4]
        
        # 从S盒中取值
        val = S_BOX[i][row][col]
        
        # 转换为4位二进制
        result.extend([(val >> 3) & 1, (val >> 2) & 1, (val >> 1) & 1, val & 1])
    
    return result


def string_to_bit_list(text):
    """将字符串转换为位列表"""
    bit_list = []
    for char in text:
        # 每个字符8位
        bits = bin(ord(char))[2:].zfill(8)
        bit_list.extend([int(b) for b in bits])
    return bit_list

def bit_list_to_string(bit_list):
    """将位列表转换为字符串"""
    chars = []
    for i in range(0, len(bit_list), 8):
        byte = bit_list[i:i+8]
        chars.append(chr(int(''.join(map(str, byte)), 2)))
    return ''.join(chars)

def pad_block(block, size):
    """填充块到指定大小"""
    return block + [0] * (size - len(block))


# 示例使用
if __name__ == "__main__":
    # 明文和密钥(64位)
    plaintext = "HelloDES"
    key = "SecretK "
    
    # 转换为位列表
    plaintext_bits = string_to_bit_list(plaintext)
    key_bits = string_to_bit_list(key)
    
    # 确保是64位(不足则填充)
    plaintext_bits = pad_block(plaintext_bits, 64)
    key_bits = pad_block(key_bits, 64)
    
    # 加密
    ciphertext_bits = des_encrypt(plaintext_bits, key_bits)
    ciphertext = bit_list_to_string(ciphertext_bits)
    print("加密结果:", ciphertext)
    
    # 解密
    decrypted_bits = des_decrypt(ciphertext_bits, key_bits)
    decrypted_text = bit_list_to_string(decrypted_bits)
    print("解密结果:", decrypted_text)