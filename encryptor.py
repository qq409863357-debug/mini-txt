import os
import sys
import tempfile
import subprocess
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# 配置
SALT_SIZE = 16
IV_SIZE = 16
ITERATIONS = 100000
ENC_EXTENSION = ".wt"

def resource_path(relative_path):
    """ 获取真地实际路径，适配 PyInstaller """
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)

class TextEncryptor:
    @staticmethod
    def derive_key(password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=ITERATIONS,
            backend=default_backend()
        )
        return kdf.derive(password.encode())

    @staticmethod
    def encrypt_file(file_path: str, password: str):
        with open(file_path, 'rb') as f:
            data = f.read()

        enc_file_path = file_path + ENC_EXTENSION
        if file_path.endswith(".txt"):
             enc_file_path = file_path[:-4] + ENC_EXTENSION

        TextEncryptor.encrypt_to_file(data, password, enc_file_path)
        os.remove(file_path)
        return enc_file_path

    @staticmethod
    def encrypt_to_file(data: bytes, password: str, output_path: str):
        salt = os.urandom(SALT_SIZE)
        key = TextEncryptor.derive_key(password, salt)
        iv = os.urandom(IV_SIZE)
        
        pad_len = 16 - (len(data) % 16)
        data += bytes([pad_len] * pad_len)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(data) + encryptor.finalize()

        with open(output_path, 'wb') as f:
            f.write(salt + iv + encrypted_data)

    @staticmethod
    def decrypt_to_memory(file_path: str, password: str):
        with open(file_path, 'rb') as f:
            salt = f.read(SALT_SIZE)
            iv = f.read(IV_SIZE)
            encrypted_data = f.read()

        key = TextEncryptor.derive_key(password, salt)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        try:
            padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
            pad_len = padded_data[-1]
            if pad_len > 16: raise ValueError()
            return padded_data[:-pad_len]
        except Exception:
            raise ValueError("密码错误或文件损坏")

class App(tk.Tk):
    def __init__(self, target_file=None):
        super().__init__()
        # 1. 立即隐藏窗口，防止初始化时的视觉闪燥
        self.withdraw()
        self.title("极简文本加密助手")
        
        # 2. 移除原生标题栏
        self.overrideredirect(True)
        
        # 3. 窗口大小与居中
        width, height = 440, 360
        self.center_window(width, height)
        self.target_file = target_file
        
        # 4. 皮肤设置
        self.style = ttk.Style(self)
        self.tk.call("source", resource_path("azure.tcl"))
        self.tk.call("set_theme", "dark")
        
        self.setup_custom_title_bar()
        self.setup_ui()
        
        # 5. 预设任务栏样式 (在显示前完成)
        self.prepare_taskbar_style()
        
        # 6. 初始化完成后一次性显现
        self.after(50, self.deiconify)

    def prepare_taskbar_style(self):
        # 预先设置 Windows 窗口样式，确保任务栏标签在显示时即刻就绪
        import ctypes
        GWL_EXSTYLE = -20
        WS_EX_APPWINDOW = 0x00040000
        WS_EX_TOOLWINDOW = 0x00000080
        
        self.update() 
        hwnd = ctypes.windll.user32.GetParent(self.winfo_id())
        if hwnd == 0: hwnd = self.winfo_id()
        
        style = ctypes.windll.user32.GetWindowLongW(hwnd, GWL_EXSTYLE)
        style = style & ~WS_EX_TOOLWINDOW
        style = style | WS_EX_APPWINDOW
        ctypes.windll.user32.SetWindowLongW(hwnd, GWL_EXSTYLE, style)

    def show_in_taskbar(self):
        # 仅由于最小化恢复时调用的辅助补丁
        self.prepare_taskbar_style()
        self.deiconify()

    def center_window(self, width, height):
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f'{width}x{height}+{x}+{y}')

    def setup_custom_title_bar(self):
        # 标题栏容器
        self.title_bar = tk.Frame(self, bg="#212121", height=40, highlightthickness=0)
        self.title_bar.pack(fill="x", side="top")
        
        # 标题文字 (添加图标占位)
        title_label = tk.Label(self.title_bar, text=" 🔏 极简文本加密助手", bg="#212121", fg="#ffffff", font=("微软雅黑", 10))
        title_label.pack(side="left", padx=10)
        
        # 关闭按钮
        close_btn = tk.Button(self.title_bar, text=" ✕ ", bg="#212121", fg="white", bd=0, 
                             activebackground="#e81123", activeforeground="white", 
                             command=self.quit, font=("微软雅黑", 11), cursor="hand2")
        close_btn.pack(side="right", fill="both")
        
        # 最小化按钮
        min_btn = tk.Button(self.title_bar, text=" — ", bg="#212121", fg="white", bd=0, 
                           activebackground="#333333", activeforeground="white", 
                           command=self.minimize, font=("微软雅黑", 9), cursor="hand2")
        min_btn.pack(side="right", fill="both")

        # 绑定拖拽事件
        self.title_bar.bind("<ButtonPress-1>", self.start_move)
        self.title_bar.bind("<B1-Motion>", self.do_move)
        title_label.bind("<ButtonPress-1>", self.start_move)
        title_label.bind("<B1-Motion>", self.do_move)

    def minimize(self):
        self.overrideredirect(False)
        self.iconify()
        self.bind("<FocusIn>", self.on_deiconify)

    def on_deiconify(self, event):
        self.overrideredirect(True)
        self.show_in_taskbar() # 恢复任务栏补丁
        self.unbind("<FocusIn>")

    def start_move(self, event):
        self.x = event.x
        self.y = event.y

    def do_move(self, event):
        deltax = event.x - self.x
        deltay = event.y - self.y
        x = self.winfo_x() + deltax
        y = self.winfo_y() + deltay
        self.geometry(f"+{x}+{y}")

    def setup_ui(self):
        # 修正: 设置 highlightcolor 解决选中后变蓝的问题
        outer_frame = tk.Frame(self, bg="#212121", highlightthickness=1, 
                              highlightbackground="#3d3d3d", highlightcolor="#3d3d3d")
        outer_frame.pack(expand=True, fill="both")
        
        container = ttk.Frame(outer_frame, padding=30)
        container.pack(expand=True, fill="both")

        ttk.Label(container, text="安全加密 · 极简办公", font=("微软雅黑", 14, "bold")).pack(pady=(0, 20))
        
        self.password_entry = ttk.Entry(container, show="*", width=30, justify="center")
        self.password_entry.pack(pady=5, ipady=6)
        self.password_entry.bind("<Return>", lambda e: self.process())
        self.password_entry.focus()
        
        ttk.Label(container, text="输入 AES-256 访问密码", font=("微软雅黑", 9), foreground="gray").pack(pady=(0, 15))

        if self.target_file:
            filename = os.path.basename(self.target_file)
            ttk.Label(container, text=f"📂 处理: {filename}", foreground="#007acc").pack(pady=5)
            btn_text = "解密并查看"
        else:
            btn_text = "选择文件加密"

        self.action_btn = ttk.Button(container, text=btn_text, command=self.process, style="Accent.TButton", cursor="hand2")
        self.action_btn.pack(pady=15, fill="x")

        if not self.target_file:
            # 修正: 按用户要求修改按钮文本
            reg_btn = ttk.Button(container, text="首次运行点击关联加密文件", command=self.register_context_menu, style="Ghost.TButton", cursor="hand2")
            reg_btn.pack(pady=0)


    def register_context_menu(self):
        import winreg
        import ctypes
        exe_path = sys.executable if getattr(sys, 'frozen', False) else __file__
        try:
            # 1. 关联后缀
            key = winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, ".wt")
            winreg.SetValue(key, "", winreg.REG_SZ, "MinimalTextEncryptor")
            # 2. 打开命令
            key = winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, "MinimalTextEncryptor\\shell\\open\\command")
            winreg.SetValue(key, "", winreg.REG_SZ, f'"{exe_path}" "%1"')
            # 3. 图标设置
            icon_key = winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, "MinimalTextEncryptor\\DefaultIcon")
            winreg.SetValue(icon_key, "", winreg.REG_SZ, f'"{exe_path}",0')
            # 4. 驱动变更通知
            ctypes.windll.shell32.SHChangeNotify(0x08000000, 0, None, None)
            messagebox.showinfo("成功", "右键关联成功！")
        except Exception as e:
            messagebox.showerror("权限不足", f"请以管理员身份运行！\n{e}")

    def process(self):
        password = self.password_entry.get()
        if not password:
            messagebox.showwarning("提示", "请输入密码")
            return

        file_path = self.target_file or filedialog.askopenfilename(filetypes=[("Text", "*.txt"), ("Secure", "*.wt")])
        if not file_path: return

        try:
            if file_path.endswith(ENC_EXTENSION):
                data = TextEncryptor.decrypt_to_memory(file_path, password)
                with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as tmp:
                    tmp.write(data)
                    tmp_path = tmp.name
                
                self.withdraw()
                subprocess.run(['notepad.exe', tmp_path])
                
                # 读取记事本关闭后的内容并判断是否修改
                with open(tmp_path, 'rb') as f:
                    new_data = f.read()
                
                if new_data != data:
                    TextEncryptor.encrypt_to_file(new_data, password, file_path)
                
                if os.path.exists(tmp_path): os.remove(tmp_path)
                self.quit()
            
            elif file_path.endswith(".txt"):
                new_path = TextEncryptor.encrypt_file(file_path, password)
                messagebox.showinfo("完成", f"已加密为:\n{os.path.basename(new_path)}")
                self.quit()
        except Exception as e:
            messagebox.showerror("认证失败", "密码不正确或文件已损坏")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else None
    app = App(target)
    app.mainloop()


