from PySide6.QtWidgets import (QApplication, QWidget, QVBoxLayout, QHBoxLayout, 
                              QLabel, QLineEdit, QPushButton, QComboBox, QTabWidget, QFormLayout, QSpacerItem, QSizePolicy)
from PySide6.QtGui import QFont
from classical_cipher import ClassicalCipher  # 导入 ClassicalCipher 类
import sqlite3
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import base64
import DES_cipher

class DatabaseManager:
    def __init__(self, db_name='cipher_data.db'):
        self.db_name = db_name

    def init_db(self):
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cipher_operations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                method TEXT NOT NULL,
                plaintext TEXT NOT NULL,
                param TEXT NOT NULL,
                result TEXT NOT NULL
            )
        ''')
        conn.commit()
        conn.close()

    def query(self, method, text, param):
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute('SELECT result FROM cipher_operations WHERE method=? AND plaintext=? AND param=?', (method, text, param))
        result = cursor.fetchone()
        conn.close()
        return result[0] if result else None

    def save(self, method, text, param, result):
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute('INSERT INTO cipher_operations (method, plaintext, param, result) VALUES (?, ?, ?, ?)', (method, text, param, result))
        conn.commit()
        conn.close()

class CipherApp(QWidget):
    def __init__(self):
        super().__init__()
        self.cipher = ClassicalCipher()
        self.db_manager = DatabaseManager()
        self.initUI()
        self.db_manager.init_db()

    def initUI(self):
        self.setWindowTitle('密码学工具')
        self.setGeometry(100, 100, 600, 400)

        # 主布局
        main_layout = QVBoxLayout()

        # 创建选项卡
        self.tabs = QTabWidget()
        self.tabs.setFont(QFont('Arial', 12))

        # 古典密码选项卡
        self.classical_tab = QWidget()
        self.initClassicalUI()
        self.tabs.addTab(self.classical_tab, "古典密码")

        # 现代密码选项卡
        self.modern_tab = QWidget()
        self.initModernUI()
        self.tabs.addTab(self.modern_tab, "现代密码")

        main_layout.addWidget(self.tabs)
        self.setLayout(main_layout)

    def initClassicalUI(self):
        layout = QVBoxLayout()

        # 加密方法选择
        form_layout = QFormLayout()
        self.method_label = QLabel('加密方法:')
        self.method_label.setFont(QFont('Arial', 12))
        self.method_combo = QComboBox()
        self.method_combo.setFont(QFont('Arial', 12))
        self.method_combo.addItems(['凯撒密码', '替换密码', '维吉尼亚密码', '置换密码', '仿射密码', 'Playfair密码'])
        self.method_combo.currentTextChanged.connect(self.updateParamHint)
        form_layout.addRow(self.method_label, self.method_combo)

        # 输入文本
        self.input_label = QLabel('输入文本:')
        self.input_label.setFont(QFont('Arial', 12))
        self.input_text = QLineEdit()
        self.input_text.setFont(QFont('Arial', 12))
        form_layout.addRow(self.input_label, self.input_text)

        # 参数输入
        self.param_label = QLabel('参数:')
        self.param_label.setFont(QFont('Arial', 12))
        self.param_text = QLineEdit()
        self.param_text.setFont(QFont('Arial', 12))
        self.param_hint = QLabel()
        self.param_hint.setFont(QFont('Arial', 10))
        self.param_hint.setStyleSheet("color: #888888;")
        param_layout = QHBoxLayout()
        param_layout.addWidget(self.param_text)
        param_layout.addWidget(self.param_hint)
        form_layout.addRow(self.param_label, param_layout)

        # 操作按钮
        button_layout = QHBoxLayout()
        self.encrypt_button = QPushButton('加密')
        self.encrypt_button.setFont(QFont('Arial', 12))
        self.encrypt_button.setStyleSheet("background-color: #4CAF50; color: white; border: none; padding: 10px 20px; border-radius: 5px;")
        self.encrypt_button.clicked.connect(self.encrypt)
        self.decrypt_button = QPushButton('解密')
        self.decrypt_button.setFont(QFont('Arial', 12))
        self.decrypt_button.setStyleSheet("background-color: #008CBA; color: white; border: none; padding: 10px 20px; border-radius: 5px;")
        self.decrypt_button.clicked.connect(self.decrypt)
        button_layout.addWidget(self.encrypt_button)
        button_layout.addWidget(self.decrypt_button)
        form_layout.addRow(button_layout)

        # 结果显示
        self.result_label = QLabel('结果:')
        self.result_label.setFont(QFont('Arial', 12))
        self.result_text = QLineEdit()
        self.result_text.setFont(QFont('Arial', 12))
        self.result_text.setReadOnly(True)
        form_layout.addRow(self.result_label, self.result_text)

        layout.addLayout(form_layout)

        # 添加间距
        spacer = QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding)
        layout.addItem(spacer)

        self.classical_tab.setLayout(layout)

    def initModernUI(self):
        layout = QVBoxLayout()

        # 加密方法选择
        form_layout = QFormLayout()
        self.method_label = QLabel('加密方法:')
        self.method_label.setFont(QFont('Arial', 12))
        self.method_combo = QComboBox()
        self.method_combo.setFont(QFont('Arial', 12))
        self.method_combo.addItems(['AES', 'RSA', 'DES'])
        self.method_combo.currentTextChanged.connect(self.updateParamHint)
        form_layout.addRow(self.method_label, self.method_combo)

        # 输入文本
        self.input_label = QLabel('输入文本:')
        self.input_label.setFont(QFont('Arial', 12))
        self.input_text = QLineEdit()
        self.input_text.setFont(QFont('Arial', 12))
        form_layout.addRow(self.input_label, self.input_text)

        # 参数输入
        self.param_label = QLabel('参数:')
        self.param_label.setFont(QFont('Arial', 12))
        self.param_text = QLineEdit()
        self.param_text.setFont(QFont('Arial', 12))
        self.param_hint = QLabel()
        self.param_hint.setFont(QFont('Arial', 10))
        self.param_hint.setStyleSheet("color: #888888;")
        param_layout = QHBoxLayout()
        param_layout.addWidget(self.param_text)
        param_layout.addWidget(self.param_hint)
        form_layout.addRow(self.param_label, param_layout)

        # 操作按钮
        button_layout = QHBoxLayout()
        self.encrypt_button = QPushButton('加密')
        self.encrypt_button.setFont(QFont('Arial', 12))
        self.encrypt_button.setStyleSheet("background-color: #4CAF50; color: white; border: none; padding: 10px 20px; border-radius: 5px;")
        self.encrypt_button.clicked.connect(self.encrypt)
        self.decrypt_button = QPushButton('解密')
        self.decrypt_button.setFont(QFont('Arial', 12))
        self.decrypt_button.setStyleSheet("background-color: #008CBA; color: white; border: none; padding: 10px 20px; border-radius: 5px;")
        self.decrypt_button.clicked.connect(self.decrypt)
        button_layout.addWidget(self.encrypt_button)
        button_layout.addWidget(self.decrypt_button)
        form_layout.addRow(button_layout)

        # 结果显示
        self.result_label = QLabel('结果:')
        self.result_label.setFont(QFont('Arial', 12))
        self.result_text = QLineEdit()
        self.result_text.setFont(QFont('Arial', 12))
        self.result_text.setReadOnly(True)
        form_layout.addRow(self.result_label, self.result_text)

        layout.addLayout(form_layout)

        # 添加间距
        spacer = QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding)
        layout.addItem(spacer)

        self.modern_tab.setLayout(layout)

    def encrypt(self):
        method = self.method_combo.currentText()
        plaintext = self.input_text.text()
        param = self.param_text.text()

        result = self.db_manager.query(method, plaintext, param)
        if result:
            self.result_text.setText(result)
            return

        try:
            if method == 'AES':
                raise ValueError("AES加密已移除，请使用DES加密")
            elif method == 'RSA':
                raise ValueError("RSA加密已移除，请使用DES加密")
            elif method == 'DES':
                            # 转换为位列表
                plaintext_bits = DES_cipher.string_to_bit_list(plaintext)
                key_bits = DES_cipher.string_to_bit_list(param)
                
                # 确保是64位(不足则填充)
                plaintext_bits = DES_cipher.pad_block(plaintext_bits, 64)
                key_bits = DES_cipher.pad_block(key_bits, 64)
                
                # 加密
                ciphertext_bits = DES_cipher.des_encrypt(plaintext_bits, key_bits)
                result = DES_cipher.bit_list_to_string(ciphertext_bits)
                
    

                #result = DES_cipher.des_encrypt(plaintext.encode(), param.encode())
            elif method == '凯撒密码':
                shift = int(param)
                result = self.cipher.caesar_cipher_encrypt(plaintext, shift)
            elif method == '替换密码':
                result = self.cipher.substitution_cipher_encrypt(plaintext, param)
            elif method == '维吉尼亚密码':
                result = self.cipher.vigenere_cipher_encrypt(plaintext, param)
            elif method == '置换密码':
                key = list(map(int, param.split()))
                result = self.cipher.transposition_cipher_encrypt(plaintext, key)
            elif method == '仿射密码':
                a, b = map(int, param.split())
                result = self.cipher.affine_cipher_encrypt(plaintext, a, b)
            elif method == 'Playfair密码':
                result = self.cipher.playfair_cipher_encrypt(plaintext, param)
            else:
                raise ValueError("未实现的加密方法")
        except Exception as e:
            self.result_text.setText(f"加密错误: {str(e)}")
            return

        self.db_manager.save(method, plaintext, param, result)
        self.result_text.setText(result)

    def decrypt(self):
        method = self.method_combo.currentText()
        ciphertext = self.input_text.text()
        param = self.param_text.text()

        result = self.db_manager.query(method, ciphertext, param)
        if result:
            self.result_text.setText(result)
            return

        try:
            if method == 'AES':
                raise ValueError("AES解密已移除，请使用DES解密")
            elif method == 'RSA':
                raise ValueError("RSA解密已移除，请使用DES解密")
            elif method == 'DES':
                
                #result = des_decrypt(ciphertext.encode(), param.encode())
                             # 转换为位列表
                plaintext_bits = DES_cipher.string_to_bit_list(ciphertext)
                key_bits = DES_cipher.string_to_bit_list(param)
                
                # 确保是64位(不足则填充)
                plaintext_bits = DES_cipher.pad_block(plaintext_bits, 64)
                key_bits = DES_cipher.pad_block(key_bits, 64)
                


                deciphertext_bits = DES_cipher.des_decrypt(plaintext_bits, key_bits)
                result = DES_cipher.bit_list_to_string(deciphertext_bits)
            elif method == '凯撒密码':
                shift = int(param)
                result = self.cipher.caesar_cipher_decrypt(ciphertext, shift)
            elif method == '替换密码':
                result = self.cipher.substitution_cipher_decrypt(ciphertext, param)
            elif method == '维吉尼亚密码':
                result = self.cipher.vigenere_cipher_decrypt(ciphertext, param)
            elif method == '置换密码':
                key = list(map(int, param.split()))
                result = self.cipher.transposition_cipher_decrypt(ciphertext, key)
            elif method == '仿射密码':
                a, b = map(int, param.split())
                result = self.cipher.affine_cipher_decrypt(ciphertext, a, b)
            elif method == 'Playfair密码':
                result = self.cipher.playfair_cipher_decrypt(ciphertext, param)
            else:
                raise ValueError("未实现的解密方法")
        except Exception as e:
            self.result_text.setText(f"解密错误: {str(e)}")
            return

        self.db_manager.save(method, ciphertext, param, result)
        self.result_text.setText(result)

    def updateParamHint(self):
        method = self.method_combo.currentText()
        if method == 'AES':
            self.param_hint.setText("AES加密已移除，请使用DES加密")
        elif method == 'RSA':
            self.param_hint.setText("RSA加密已移除，请使用DES加密")
        elif method == 'DES':
            self.param_hint.setText("请输入一个8字节的DES密钥")
        elif method == '凯撒密码':
            self.param_hint.setText("请输入一个整数作为位移量")
        elif method == '替换密码':
            self.param_hint.setText("请输入26个字母的替换表，如：zyxwvutsrqponmlkjihgfedcba")
        elif method == '维吉尼亚密码':
            self.param_hint.setText("请输入一个密钥字符串，如：key")
        elif method == '置换密码':
            self.param_hint.setText("请输入一组整数作为密钥，用空格分隔，如：3 1 4 2")
        elif method == '仿射密码':
            self.param_hint.setText("请输入两个整数a和b，用空格分隔，且a必须与26互质，如：5 8")
        elif method == 'Playfair密码':
            self.param_hint.setText("请输入一个密钥字符串，如：monarchy")
        else:
            self.param_hint.setText("")

if __name__ == "__main__":
    app = QApplication([])
    window = CipherApp()
    window.show()
    app.exec()