from PySide6.QtWidgets import (QApplication, QWidget, QVBoxLayout, QHBoxLayout, 
                              QLabel, QLineEdit, QPushButton, QComboBox, QTabWidget, QFormLayout, QSpacerItem, QSizePolicy)
from PySide6.QtGui import QFont
from classical_cipher import ClassicalCipher  # 导入 ClassicalCipher 类
import sqlite3

# 初始化数据库
def init_db():
    conn = sqlite3.connect('cipher_data.db')
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

class CipherApp(QWidget):
    def __init__(self):
        super().__init__()
        self.cipher = ClassicalCipher()
        self.initUI()
        init_db()  # 初始化数据库

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
        label = QLabel("现代密码功能正在开发中...")
        label.setFont(QFont('Arial', 16))
        label.setStyleSheet("color: #888888;")
        layout.addWidget(label)
        self.modern_tab.setLayout(layout)

    def encrypt(self):
        method = self.method_combo.currentText()
        plaintext = self.input_text.text()
        param = self.param_text.text()

        # 查询数据库
        result = self.query_database(method, plaintext, param)
        if result:
            self.result_text.setText(result)
            return

        if method == '凯撒密码':
            try:
                shift = int(param)
                ciphertext = self.cipher.caesar_cipher_encrypt(plaintext, shift)
            except ValueError:
                self.result_text.setText("参数错误: 请输入整数")
                return
        elif method == '替换密码':
            ciphertext = self.cipher.substitution_cipher_encrypt(plaintext, param)
        elif method == '维吉尼亚密码':
            ciphertext = self.cipher.vigenere_cipher_encrypt(plaintext, param)
        elif method == '置换密码':
            try:
                key = list(map(int, param.split()))
                ciphertext = self.cipher.transposition_cipher_encrypt(plaintext, key)
            except ValueError:
                self.result_text.setText("参数错误: 请输入整数列表")
                return
        elif method == '仿射密码':
            try:
                a, b = map(int, param.split())
                ciphertext = self.cipher.affine_cipher_encrypt(plaintext, a, b)
            except ValueError:
                self.result_text.setText("参数错误: 请输入两个整数a和b，且a必须与26互质")
                return
        elif method == 'Playfair密码':
            ciphertext = self.cipher.playfair_cipher_encrypt(plaintext, param)
        else:
            self.result_text.setText("未实现的加密方法")
            return

        # 保存到数据库
        self.save_to_database(method, plaintext, param, ciphertext)
        self.result_text.setText(ciphertext)

    def decrypt(self):
        method = self.method_combo.currentText()
        ciphertext = self.input_text.text()
        param = self.param_text.text()

        # 查询数据库
        result = self.query_database(method, ciphertext, param)
        if result:
            self.result_text.setText(result)
            return

        if method == '凯撒密码':
            try:
                shift = int(param)
                plaintext = self.cipher.caesar_cipher_decrypt(ciphertext, shift)
            except ValueError:
                self.result_text.setText("参数错误: 请输入整数")
                return
        elif method == '替换密码':
            plaintext = self.cipher.substitution_cipher_decrypt(ciphertext, param)
        elif method == '维吉尼亚密码':
            plaintext = self.cipher.vigenere_cipher_decrypt(ciphertext, param)
        elif method == '置换密码':
            try:
                key = list(map(int, param.split()))
                plaintext = self.cipher.transposition_cipher_decrypt(ciphertext, key)
            except ValueError:
                self.result_text.setText("参数错误: 请输入整数列表")
                return
        elif method == '仿射密码':
            try:
                a, b = map(int, param.split())
                plaintext = self.cipher.affine_cipher_decrypt(ciphertext, a, b)
            except ValueError:
                self.result_text.setText("参数错误: 请输入两个整数a和b，且a必须与26互质")
                return
        elif method == 'Playfair密码':
            plaintext = self.cipher.playfair_cipher_decrypt(ciphertext, param)
        else:
            self.result_text.setText("未实现的解密方法")
            return

        # 保存到数据库
        self.save_to_database(method, ciphertext, param, plaintext)
        self.result_text.setText(plaintext)

    def updateParamHint(self):
        method = self.method_combo.currentText()
        if method == '凯撒密码':
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

    def query_database(self, method, text, param):
        conn = sqlite3.connect('cipher_data.db')
        cursor = conn.cursor()
        cursor.execute('SELECT result FROM cipher_operations WHERE method=? AND plaintext=? AND param=?', (method, text, param))
        result = cursor.fetchone()
        conn.close()
        return result[0] if result else None

    def save_to_database(self, method, text, param, result):
        conn = sqlite3.connect('cipher_data.db')
        cursor = conn.cursor()
        cursor.execute('INSERT INTO cipher_operations (method, plaintext, param, result) VALUES (?, ?, ?, ?)', (method, text, param, result))
        conn.commit()
        conn.close()

if __name__ == "__main__":
    app = QApplication([])
    window = CipherApp()
    window.show()
    app.exec()