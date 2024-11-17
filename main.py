import tkinter as tk
from tkinter import messagebox
from PIL import Image, ImageTk, ImageDraw
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import padding
import os
import sys

def resource_path(relative_path):
    """获取资源文件的绝对路径，兼容打包后的环境"""
    try:
        # PyInstaller创建临时文件夹，并将路径存储在 _MEIPASS
        base_path = sys._MEIPASS
    except AttributeError:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

# 加密函数
def encrypt_message(message, password):
    salt = os.urandom(16)
    kdf = Scrypt(salt=salt, length=32, n=2 ** 14, r=8, p=1)
    key = kdf.derive(password.encode())

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(128).padder()
    padded_message = padder.update(message.encode()) + padder.finalize()

    ciphertext = encryptor.update(padded_message) + encryptor.finalize()

    return salt + iv + ciphertext

# 解密函数
def decrypt_message(encrypted_message, password):
    if len(encrypted_message) < 32:
        raise ValueError("Encrypted message is too short.")

    try:
        salt = encrypted_message[:16]
        iv = encrypted_message[16:32]
        ciphertext = encrypted_message[32:]

        kdf = Scrypt(salt=salt, length=32, n=2 ** 14, r=8, p=1)
        key = kdf.derive(password.encode())

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()

        padded_message = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        message = unpadder.update(padded_message) + unpadder.finalize()

        return message.decode('utf-8')
    except Exception:
        raise ValueError("Decryption failed. Invalid ciphertext or password.")

# 裁剪圆形照片的函数
def create_round_image(img_path, size=(80, 80)):
    img = Image.open(img_path).resize(size).convert("RGBA")
    bigsize = (img.size[0] * 3, img.size[1] * 3)
    mask = Image.new('L', bigsize, 0)
    draw = ImageDraw.Draw(mask)
    draw.ellipse((0, 0) + bigsize, fill=255)
    mask = mask.resize(img.size)
    img.putalpha(mask)
    return img

# GUI 逻辑
def process():
    mode = mode_var.get()
    message = entry_message.get("1.0", tk.END).strip()
    password = entry_password.get().strip()

    if not message or not password:
        messagebox.showerror("错误", "消息和密码不能为空。")
        return

    entry_result.delete("1.0", tk.END)
    entry_message.delete("1.0", tk.END)

    if mode == "Encrypt":
        try:
            encrypted = encrypt_message(message, password)
            entry_result.insert("1.0", encrypted.hex())
            messagebox.showinfo("成功", "加密成功。")
        except Exception as e:
            messagebox.showerror("错误", f"加密失败：{e}")
    elif mode == "Decrypt":
        try:
            encrypted_message = bytes.fromhex(message)
            decrypted = decrypt_message(encrypted_message, password)
            entry_result.insert("1.0", decrypted)
            messagebox.showinfo("成功", "解密成功。")
        except Exception as e:
            messagebox.showerror("错误", f"解密失败：{e}")

def switch_mode():
    mode = mode_var.get()
    if mode == "Encrypt":
        label_message.config(text="输入明文：")
        label_result.config(text="密文（Hex）：")
        button_process.config(text="加密")
    else:
        label_message.config(text="输入密文（Hex）：")
        label_result.config(text="明文：")
        button_process.config(text="解密")
    entry_message.delete("1.0", tk.END)
    entry_result.delete("1.0", tk.END)

# GUI 设置
root = tk.Tk()
root.title("本地加密解密工具")

# 添加软件名称
label_software_name = tk.Label(root, text="本地加密解密工具", font=("Arial", 18, "bold"))
label_software_name.pack(pady=(10, 5))

# 添加名字和头像的框架
info_frame = tk.Frame(root)
info_frame.pack(pady=(0, 10))

# 加载并裁剪圆形照片
try:
    image_path = resource_path("photo.jpg")  # 使用 resource_path 获取图片路径
    # 调试信息：显示尝试加载的路径
    print(f"尝试加载图片路径: {image_path}")  # 在命令行运行时可见
    round_img = create_round_image(image_path, size=(40, 40))
    photo = ImageTk.PhotoImage(round_img)
    label_photo = tk.Label(info_frame, image=photo)
    label_photo.image = photo  # 保持引用
    label_photo.pack(side=tk.LEFT, padx=5)
except Exception as e:
    messagebox.showerror("错误", f"无法加载照片：{e}")
    label_photo = tk.Label(info_frame, text="")
    label_photo.pack(side=tk.LEFT, padx=5)

# 显示名字
your_name = "作者：Yoyi"  # 请替换为您的实际名字
label_name = tk.Label(info_frame, text=your_name, font=("Arial", 12))
label_name.pack(side=tk.LEFT, padx=5)

# 模式选择
mode_var = tk.StringVar(value="Encrypt")
mode_frame = tk.Frame(root)
tk.Radiobutton(mode_frame, text="加密", variable=mode_var, value="Encrypt", command=switch_mode).pack(side=tk.LEFT)
tk.Radiobutton(mode_frame, text="解密", variable=mode_var, value="Decrypt", command=switch_mode).pack(side=tk.LEFT)
mode_frame.pack(pady=5)

# 输入消息
label_message = tk.Label(root, text="输入明文：")
label_message.pack(anchor="w", padx=10)
entry_message = tk.Text(root, height=5, width=60)
entry_message.pack(padx=10, pady=5)

# 输入密码
tk.Label(root, text="密码：").pack(anchor="w", padx=10)
entry_password = tk.Entry(root, show="*", width=30)
entry_password.pack(padx=10, pady=5)

# 加密/解密按钮
button_process = tk.Button(root, text="加密", command=process)
button_process.pack(pady=10)

# 显示结果
label_result = tk.Label(root, text="密文（Hex）：")
label_result.pack(anchor="w", padx=10)
entry_result = tk.Text(root, height=5, width=60)
entry_result.pack(padx=10, pady=5)

root.mainloop()
