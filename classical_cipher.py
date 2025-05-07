from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import base64

class ClassicalCipher:
    def __init__(self):
        pass

    def caesar_cipher_encrypt(self, plaintext, shift):
        """凯撒密码加密"""
        ciphertext = ""
        for char in plaintext:
            if char.isalpha():
                shift_amount = shift % 26
                if char.islower():
                    ciphertext += chr((ord(char) - ord('a') + shift_amount) % 26 + ord('a'))
                else:
                    ciphertext += chr((ord(char) - ord('A') + shift_amount) % 26 + ord('A'))
            else:
                ciphertext += char
        return ciphertext

    def caesar_cipher_decrypt(self, ciphertext, shift):
        """凯撒密码解密"""
        return self.caesar_cipher_encrypt(ciphertext, -shift)

    def substitution_cipher_encrypt(self, plaintext, key):
        """替换密码加密"""
        alphabet = 'abcdefghijklmnopqrstuvwxyz'
        ciphertext = ""
        for char in plaintext:
            if char.lower() in alphabet:
                index = alphabet.index(char.lower())
                ciphertext += key[index] if char.islower() else key[index].upper()
            else:
                ciphertext += char
        return ciphertext

    def substitution_cipher_decrypt(self, ciphertext, key):
        """替换密码解密"""
        alphabet = 'abcdefghijklmnopqrstuvwxyz'
        plaintext = ""
        for char in ciphertext:
            if char.lower() in key:
                index = key.lower().index(char.lower())
                plaintext += alphabet[index] if char.islower() else alphabet[index].upper()
            else:
                plaintext += char
        return plaintext

    def vigenere_cipher_encrypt(self, plaintext, key):
        """维吉尼亚密码加密"""
        ciphertext = ""
        key_length = len(key)
        for i, char in enumerate(plaintext):
            if char.isalpha():
                shift = ord(key[i % key_length].lower()) - ord('a')
                if char.islower():
                    ciphertext += chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
                else:
                    ciphertext += chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
            else:
                ciphertext += char
        return ciphertext

    def vigenere_cipher_decrypt(self, ciphertext, key):
        """维吉尼亚密码解密"""
        plaintext = ""
        key_length = len(key)
        for i, char in enumerate(ciphertext):
            if char.isalpha():
                shift = ord(key[i % key_length].lower()) - ord('a')
                if char.islower():
                    plaintext += chr((ord(char) - ord('a') - shift) % 26 + ord('a'))
                else:
                    plaintext += chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
            else:
                plaintext += char
        return plaintext

    def transposition_cipher_encrypt(self, plaintext, key):
        """置换密码加密"""
        # 将明文按密钥长度分组
        num_columns = len(key)
        num_rows = -(-len(plaintext) // num_columns)  # 向上取整
        # 填充空格
        plaintext += ' ' * (num_rows * num_columns - len(plaintext))
        # 按列读取
        ciphertext = ''
        for col in sorted(key):
            index = key.index(col)
            ciphertext += ''.join(plaintext[index + i * num_columns] for i in range(num_rows))
        return ciphertext

    def transposition_cipher_decrypt(self, ciphertext, key):
        """置换密码解密"""
        num_columns = len(key)
        num_rows = -(-len(ciphertext) // num_columns)
        # 计算每列的长度
        col_lengths = [num_rows] * num_columns
        # 重建矩阵
        matrix = [''] * num_columns
        pos = 0
        for col in sorted(key):
            index = key.index(col)
            matrix[index] = ciphertext[pos:pos + col_lengths[index]]
            pos += col_lengths[index]
        # 按行读取
        plaintext = ''
        for row in range(num_rows):
            for col in range(num_columns):
                plaintext += matrix[col][row]
        return plaintext.rstrip()

    def affine_cipher_encrypt(self, plaintext, a, b):
        """仿射密码加密"""
        # 检查a是否与26互质
        def gcd(a, b):
            while b:
                a, b = b, a % b
            return a

        if gcd(a, 26) != 1:
            raise ValueError("a必须与26互质")

        ciphertext = ''
        for char in plaintext:
            if char.isalpha():
                # 统一转换为小写处理
                char_lower = char.lower()
                # 计算加密后的字符
                encrypted_char = chr(((a * (ord(char_lower) - ord('a')) + b) % 26) + ord('a'))
                # 恢复原大小写
                if char.isupper():
                    ciphertext += encrypted_char.upper()
                else:
                    ciphertext += encrypted_char
            else:
                ciphertext += char
        return ciphertext

    def affine_cipher_decrypt(self, ciphertext, a, b):
        """仿射密码解密"""
        # 检查a是否与26互质
        def gcd(a, b):
            while b:
                a, b = b, a % b
            return a

        if gcd(a, 26) != 1:
            raise ValueError("a必须与26互质")

        # 计算a的模逆
        def mod_inverse(a, m):
            for i in range(1, m):
                if (a * i) % m == 1:
                    return i
            return None

        a_inv = mod_inverse(a, 26)
        if a_inv is None:
            raise ValueError("a和26必须互质")
        plaintext = ''
        for char in ciphertext:
            if char.isalpha():
                # 统一转换为小写处理
                char_lower = char.lower()
                # 计算解密后的字符
                decrypted_char = chr(((a_inv * (ord(char_lower) - ord('a') - b)) % 26) + ord('a'))
                # 恢复原大小写
                if char.isupper():
                    plaintext += decrypted_char.upper()
                else:
                    plaintext += decrypted_char
            else:
                plaintext += char
        return plaintext

    def playfair_cipher_encrypt(self, plaintext, key):
        """Playfair密码加密"""
        # 生成5x5矩阵
        def create_square(key):
            key = key.lower().replace('j', 'i')
            alphabet = 'abcdefghiklmnopqrstuvwxyz'
            square = []
            for char in key + alphabet:
                if char not in square:
                    square.append(char)
            return [square[i:i+5] for i in range(0, 25, 5)]

        # 处理明文
        def prepare_text(text):
            text = text.lower().replace('j', 'i')
            text = ''.join(filter(str.isalpha, text))
            i = 0
            while i < len(text) - 1:
                if text[i] == text[i+1]:
                    text = text[:i+1] + 'x' + text[i+1:]
                i += 2
            if len(text) % 2 != 0:
                text += 'x'
            return text

        square = create_square(key)
        text = prepare_text(plaintext)
        ciphertext = ''
        for i in range(0, len(text), 2):
            a, b = text[i], text[i+1]
            row_a, col_a = [(i, row.index(a)) for i, row in enumerate(square) if a in row][0]
            row_b, col_b = [(i, row.index(b)) for i, row in enumerate(square) if b in row][0]
            if row_a == row_b:
                ciphertext += square[row_a][(col_a + 1) % 5] + square[row_b][(col_b + 1) % 5]
            elif col_a == col_b:
                ciphertext += square[(row_a + 1) % 5][col_a] + square[(row_b + 1) % 5][col_b]
            else:
                ciphertext += square[row_a][col_b] + square[row_b][col_a]
        return ciphertext

    def playfair_cipher_decrypt(self, ciphertext, key):
        """Playfair密码解密"""
        # 生成5x5矩阵
        def create_square(key):
            key = key.lower().replace('j', 'i')
            alphabet = 'abcdefghiklmnopqrstuvwxyz'
            square = []
            for char in key + alphabet:
                if char not in square:
                    square.append(char)
            return [square[i:i+5] for i in range(0, 25, 5)]

        square = create_square(key)
        plaintext = ''
        for i in range(0, len(ciphertext), 2):
            a, b = ciphertext[i], ciphertext[i+1]
            row_a, col_a = [(i, row.index(a)) for i, row in enumerate(square) if a in row][0]
            row_b, col_b = [(i, row.index(b)) for i, row in enumerate(square) if b in row][0]
            if row_a == row_b:
                plaintext += square[row_a][(col_a - 1) % 5] + square[row_b][(col_b - 1) % 5]
            elif col_a == col_b:
                plaintext += square[(row_a - 1) % 5][col_a] + square[(row_b - 1) % 5][col_b]
            else:
                plaintext += square[row_a][col_b] + square[row_b][col_a]
        return plaintext

    def des_encrypt(self, plaintext, key):
        """DES加密"""
        try:
            # DES密钥必须是8字节
            if len(key) != 8:
                raise ValueError("DES密钥必须是8字节")
            cipher = DES.new(key.encode(), DES.MODE_ECB)
            padded_plaintext = pad(plaintext.encode(), DES.block_size)
            ciphertext = cipher.encrypt(padded_plaintext)
            return base64.b64encode(ciphertext).decode()
        except Exception as e:
            raise ValueError(f"DES加密失败: {str(e)}")

    def des_decrypt(self, ciphertext, key):
        """DES解密"""
        try:
            # DES密钥必须是8字节
            if len(key) != 8:
                raise ValueError("DES密钥必须是8字节")
            cipher = DES.new(key.encode(), DES.MODE_ECB)
            decrypted_data = cipher.decrypt(base64.b64decode(ciphertext))
            return unpad(decrypted_data, DES.block_size).decode()
        except Exception as e:
            raise ValueError(f"DES解密失败: {str(e)}")

# 示例用法
if __name__ == "__main__":
    cipher = ClassicalCipher()
    # 凯撒密码示例
    encrypted = cipher.caesar_cipher_encrypt("Hello World", 3)
    print("凯撒加密:", encrypted)
    decrypted = cipher.caesar_cipher_decrypt(encrypted, 3)
    print("凯撒解密:", decrypted)

    # 替换密码示例
    key = "zyxwvutsrqponmlkjihgfedcba"
    encrypted = cipher.substitution_cipher_encrypt("Hello World", key)
    print("替换加密:", encrypted)
    decrypted = cipher.substitution_cipher_decrypt(encrypted, key)
    print("替换解密:", decrypted)

    # 维吉尼亚密码示例
    key = "key"
    encrypted = cipher.vigenere_cipher_encrypt("Hello World", key)
    print("维吉尼亚加密:", encrypted)
    decrypted = cipher.vigenere_cipher_decrypt(encrypted, key)
    print("维吉尼亚解密:", decrypted)

    # 置换密码示例
    key = [3, 1, 4, 2]
    encrypted = cipher.transposition_cipher_encrypt("Hello World", key)
    print("置换加密:", encrypted)
    decrypted = cipher.transposition_cipher_decrypt(encrypted, key)
    print("置换解密:", decrypted)

    # 仿射密码示例
    a, b = 5, 8
    encrypted = cipher.affine_cipher_encrypt("Hello World", a, b)
    print("仿射加密:", encrypted)
    decrypted = cipher.affine_cipher_decrypt(encrypted, a, b)
    print("仿射解密:", decrypted)

    # Playfair密码示例
    key = "monarchy"
    encrypted = cipher.playfair_cipher_encrypt("Hello World", key)
    print("Playfair加密:", encrypted)
    decrypted = cipher.playfair_cipher_decrypt(encrypted, key)
    print("Playfair解密:", decrypted)