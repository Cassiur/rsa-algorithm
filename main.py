import os
import random
import gmpy2
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
from PyQt5.QtWidgets import QApplication, QMainWindow, QPushButton, QTextEdit, QLabel, QVBoxLayout, QWidget, QFileDialog, QMessageBox
import json

class CryptoSystem(QMainWindow):
    def __init__(self, n, e, d, p, q, r, dp, dq, dr, qinv, rinv):
        super().__init__()
        self.n = n
        self.e = e
        self.d = d
        self.p = p
        self.q = q
        self.r = r
        self.dp = dp
        self.dq = dq
        self.dr = dr
        self.qinv = qinv
        self.rinv = rinv
        self.initUI()

    def initUI(self):
        # 设置窗口标题和大小
        self.setWindowTitle('加密系统')
        self.setGeometry(100, 100, 800, 600)

        # 创建一个垂直布局
        layout = QVBoxLayout()

        # 创建标签和文本编辑框
        label = QLabel('请输入要加密的消息：')
        layout.addWidget(label)
        self.message_entry = QTextEdit()
        layout.addWidget(self.message_entry)

        # 创建加密按钮
        encrypt_button = QPushButton('加密消息')
        encrypt_button.clicked.connect(self.encrypt_message)
        layout.addWidget(encrypt_button)

        # 历史记录文本框
        self.history_text = QTextEdit()
        self.history_text.setReadOnly(True)  # 设置为只读
        layout.addWidget(self.history_text)

        # 清除历史记录按钮
        clear_history_button = QPushButton('清除历史记录')
        clear_history_button.clicked.connect(self.clear_history)
        layout.addWidget(clear_history_button)

        # 设置布局到中心窗口
        central_widget = QWidget()
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)

    def clear_history(self):
        self.history_text.clear()

    def encrypt_message(self):
        original_message = self.message_entry.toPlainText()
        if not original_message:
            QMessageBox.critical(self, "错误", "消息不能为空！")
            return

        # 获取或生成AES密钥
        aes_key = get_or_generate_aes_key()

        # 使用AES加密消息
        ciphertext, nonce = aes_encrypt(original_message, aes_key)

        # 使用RSA-CRT算法加密AES密钥
        encrypted_aes_key = encrypt(int.from_bytes(aes_key, byteorder='big'), self.e, self.n)

        # 使用RSA-CRT算法解密AES密钥
        decrypted_aes_key = decrypt(encrypted_aes_key, self.p, self.q, self.r, self.dp, self.dq, self.dr, self.qinv, self.rinv)

        # 使用解密后的AES密钥解密消息
        decrypted_message = aes_decrypt(ciphertext, aes_key, nonce)

        # 更新历史记录
        self.history_text.append(f"原始消息: {original_message}\n加密后的消息: {base64.b64encode(ciphertext).decode()}\n解密后的消息: {decrypted_message}\n\n")

        # 显示加密和解密后的消息
        QMessageBox.information(self, "加密结果", f"原始消息: {original_message}\n加密后的消息: {base64.b64encode(ciphertext).decode()}\n解密后的消息: {decrypted_message}")

# # Karatsuba乘法
# def karatsuba(x, y):
#     if x < 10 or y < 10:
#         return x * y
#     else:
#         n = max(len(str(x)), len(str(y)))
#         half = n // 2

#         high_x, low_x = x // 10**half, x % 10**half
#         high_y, low_y = y // 10**half, y % 10**half

#         z0 = karatsuba(low_x, low_y)
#         z1 = karatsuba((low_x + high_x), (low_y + high_y))
#         z2 = karatsuba(high_x, high_y)

#         return (z2 * 10**(2 * half)) + ((z1 - z2 - z0) * 10**half) + z0

#蒙哥马利算法，未能实现
# class Montgomery:
#     def __init__(self, modulus):
#         self.modulus = modulus
#         self.r = 1 << (modulus.bit_length() + 1)  # R值为2的幂，大于modulus
#         self.r_inv = pow(self.r, -1, modulus)
#         self.m_inv = pow(modulus, -1, self.r)

#     def reduce(self, t):
#         m = (t * self.m_inv) % self.r
#         t = (t + m * self.modulus) >> (self.modulus.bit_length() + 1)
#         if t >= self.modulus:
#             t -= self.modulus
#         return t

#     def to_montgomery(self, x):
#         return (x * self.r) % self.modulus

#     def from_montgomery(self, x):
#         return (x * self.r_inv) % self.modulus

#     def montgomery_multiply(self, x, y):
#         return self.reduce(x * y)

# 从环境变量中获取或生成AES密钥
def get_or_generate_aes_key():
    aes_key_env = os.getenv("AES_KEY")
    if aes_key_env:
        return aes_key_env.encode('utf-8')
    else:
        aes_key = get_random_bytes(16)
        os.environ["AES_KEY"] = aes_key.hex()
        return aes_key

# # 快速幂算法，使用Karatsuba乘法
# def pow_mod(p, q, n):
#     res = 1
#     p = p % n
#     while q:
#         if q & 1:
#             res = karatsuba(res, p) % n
#         q >>= 1
#         p = karatsuba(p, p) % n
#     return res

#快速幂算法，不含Karatsuba乘法
def pow_mod(p, q, n):
    res = 1
    p = p % n
    while q:
        if q & 1:
            res = (res * p) % n
        q >>= 1
        p = (p * p) % n
    return res

def is_prime(n, k=10):
    if n == 2 or n == 3:
        return True
    if n <= 1 or n % 2 == 0:
        return False
    # 将n-1分解为d*2^r
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    # 进行k次测试
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def hamming_weight(n):
    weight = 0
    while n:
        weight += n & 1
        n >>= 1
    return weight

def generate_large_prime(keysize=2048, max_hamming_weight=None):
    # 如果没有指定最大汉明重量，则默认为keysize的一半
    if max_hamming_weight is None:
        max_hamming_weight = keysize // 2
    while True:
        num = random.getrandbits(keysize)
        if is_prime(num) and hamming_weight(num) <= max_hamming_weight:
            return num

# 生成三个低汉明重量的大素数p、q、r
p = generate_large_prime(512, max_hamming_weight=256)
q = generate_large_prime(512, max_hamming_weight=256)
r = generate_large_prime(512, max_hamming_weight=256)

n = p * q * r
phi = (p-1) * (q-1) * (r-1)

# 选择一个与phi互质的整数e作为公钥指数
e = 65537

# 计算d，满足(e * d) mod phi = 1，d作为私钥指数
d = gmpy2.invert(e, phi)

# 计算CRT参数
dp = d % (p-1)
dq = d % (q-1)
dr = d % (r-1)
qinv = gmpy2.invert(q, p)
rinv = gmpy2.invert(r, p*q)

def encrypt(m, e, n):
    return pow(m, e, n)

def decrypt(c, p, q, r, dp, dq, dr, qinv, rinv):
    # 使用二进制指数化算法进行模幂运算
    m1 = pow_mod(c, dp, p)
    m2 = pow_mod(c, dq, q)
    m3 = pow_mod(c, dr, r)

    # 继续使用之前的CRT逻辑
    h = (qinv * (m1 - m2)) % p
    m = m2 + h * q
    h = (rinv * (m - m3)) % (p*q)
    m = m3 + h * r
    return m

# AES加密函数
def aes_encrypt(message, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
    return ciphertext, cipher.nonce

# AES解密函数
def aes_decrypt(ciphertext, key, nonce):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext.decode('utf-8')

def main():
    # 创建应用程序和窗口
    app = QApplication([])
    window = CryptoSystem(n, e, d, p, q, r, dp, dq, dr, qinv, rinv)
    window.show()
    app.exec_()

if __name__ == "__main__":
    main()