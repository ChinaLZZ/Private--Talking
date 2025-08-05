import socket
import threading
import json
import sqlite3
import os
import datetime
import base64
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, simpledialog
from collections import defaultdict

# 1. 简易异或加密/解密工具

def xor_crypt(data, key=0x5A):
    if isinstance(data, str):
        data = data.encode('utf-8')
    return bytes([b ^ key for b in data]).decode('latin1')

def xor_decrypt(data, key=0x5A):
    if isinstance(data, str):
        data = data.encode('latin1')
    return bytes([b ^ key for b in data]).decode('utf-8')

class ChatServer:
    def __init__(self, host='0.0.0.0', port=5000):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # 客户端连接管理
        self.clients = {}  # {username: (socket, address)}
        self.client_sockets = {}  # {socket: username}
        
        # 聊天记录管理
        self.chat_sessions = {}  # {(user1, user2): [messages]}
        
        # GUI相关
        self.root = None
        self.chat_display = None
        self.users_listbox = None
        self.chat_sessions_listbox = None
        self.status_label = None
        
        # 数据库初始化
        self.init_database()
        
        # 语言支持
        self.languages = {
            'cn': {
                'server_started': '服务器已启动，监听端口: {}',
                'client_connected': '客户端连接: {} ({})',
                'client_disconnected': '客户端断开连接: {}',
                'user_online': '用户 {} 已上线',
                'user_offline': '用户 {} 已下线',
                'message_logged': '消息已记录',
                'file_logged': '文件传输已记录',
                'server_title': 'Private Talking 服务器管理',
                'current_ip': '当前IP: {}',
                'online_users': '在线用户',
                'chat': '服务器监控',
                'enable_lock': '启用锁',
                'disable_lock': '解除锁',
                'change_password': '更改密码',
                'enter_password': '请输入密码:',
                'confirm_password': '请确认密码:',
                'password_mismatch': '密码不匹配',
                'lock_enabled': '用户锁已启用',
                'lock_disabled': '用户锁已解除',
                'password_changed': '密码已更改',
                'wrong_password': '密码错误',
                'enter_old_password': '请输入原密码:',
                'enter_new_password': '请输入新密码:'
            },
            'en': {
                'server_started': 'Server started, listening on port: {}',
                'client_connected': 'Client connected: {} ({})',
                'client_disconnected': 'Client disconnected: {}',
                'user_online': 'User {} is online',
                'user_offline': 'User {} is offline',
                'message_logged': 'Message logged',
                'file_logged': 'File transfer logged',
                'server_title': 'Private Talking Server Management',
                'current_ip': 'Current IP: {}',
                'online_users': 'Online Users',
                'chat': 'Server Monitor',
                'enable_lock': 'Enable Lock',
                'disable_lock': 'Disable Lock',
                'change_password': 'Change Password',
                'enter_password': 'Enter password:',
                'confirm_password': 'Confirm password:',
                'password_mismatch': 'Password mismatch',
                'lock_enabled': 'User lock enabled',
                'lock_disabled': 'User lock disabled',
                'password_changed': 'Password changed',
                'wrong_password': 'Wrong password',
                'enter_old_password': 'Enter old password:',
                'enter_new_password': 'Enter new password:'
            }
        }
        
    def init_database(self):
        """初始化数据库"""
        self.db = sqlite3.connect('chat_server.db', check_same_thread=False)
        self.cursor = self.db.cursor()
        
        # 创建用户表
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                last_login TIMESTAMP,
                status TEXT
            )
        ''')
        
        # 创建消息日志表
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender TEXT,
                receiver TEXT,
                message TEXT,
                timestamp TIMESTAMP,
                message_type TEXT,
                is_private BOOLEAN
            )
        ''')
        
        self.db.commit()
    
    def log_message(self, sender, receiver, message, message_type='text', is_private=False):
        """记录消息到数据库"""
        try:
            self.cursor.execute('''
                INSERT INTO messages (sender, receiver, message, timestamp, message_type, is_private)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (sender, receiver, message, datetime.datetime.now(), message_type, is_private))
            self.db.commit()
        except Exception as e:
            print(f"Error logging message: {e}")
    
    def setup_gui(self):
        """设置GUI界面"""
        self.root = tk.Tk()
        self.language = 'cn'  # 默认中文
        self.root.title(self.languages[self.language]['server_title'])
        self.root.geometry("1200x800")
        self.root.configure(bg='#f0f0f0')

        # 主框架
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # 顶部状态栏
        top_frame = ttk.Frame(main_frame)
        top_frame.pack(fill=tk.X, pady=(0, 10))

        # 语言选择
        ttk.Label(top_frame, text=self.languages[self.language]['language_label'] if 'language_label' in self.languages[self.language] else ("语言:" if self.language=='cn' else "Language:")).pack(side=tk.LEFT, padx=(0, 10))
        self.language_var = tk.StringVar(value=self.language)
        language_combo = ttk.Combobox(top_frame, textvariable=self.language_var, values=["cn", "en"], state="readonly", width=10)
        language_combo.pack(side=tk.LEFT, padx=(0, 20))
        language_combo.bind('<<ComboboxSelected>>', self.on_language_change)

        # 当前IP显示
        import socket
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
        except:
            local_ip = "127.0.0.1"

        self.status_label = ttk.Label(top_frame, text=f"{self.languages[self.language]['current_ip'].format(local_ip)} | {self.languages[self.language]['server_started'].split(',')[0]}: {self.port}")
        self.status_label.pack(side=tk.LEFT)

        # 主要内容区域
        content_frame = ttk.Frame(main_frame)
        content_frame.pack(fill=tk.BOTH, expand=True)
        
        # 左侧面板
        left_panel = ttk.Frame(content_frame, width=300)
        left_panel.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        left_panel.pack_propagate(False)
        
        # 在线用户列表
        ttk.Label(left_panel, text=self.languages[self.language]['online_users'], font=('Arial', 12, 'bold')).pack(anchor=tk.W, pady=(0, 5))
        self.users_listbox = tk.Listbox(left_panel, height=8)
        self.users_listbox.pack(fill=tk.X, pady=(0, 10))
        
        # 聊天会话列表
        ttk.Label(left_panel, text=self.languages[self.language]['chat'], font=('Arial', 12, 'bold')).pack(anchor=tk.W, pady=(0, 5))
        self.chat_sessions_listbox = tk.Listbox(left_panel, height=8)
        self.chat_sessions_listbox.pack(fill=tk.X)
        self.chat_sessions_listbox.bind('<<ListboxSelect>>', self.on_chat_session_select)
        
        # 右侧聊天显示区域
        chat_frame = ttk.Frame(content_frame)
        chat_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        # 聊天标题
        self.chat_title_label = ttk.Label(chat_frame, text=self.languages[self.language]['chat'], font=('Arial', 14, 'bold'))
        self.chat_title_label.pack(anchor=tk.W, pady=(0, 5))
        
        # 聊天记录显示区域
        self.chat_display = scrolledtext.ScrolledText(chat_frame, height=25, wrap=tk.WORD)
        self.chat_display.pack(fill=tk.BOTH, expand=True)
        
        # 解密按钮
        self.decrypt_button = ttk.Button(chat_frame, text=self.languages[self.language]['decrypt_button'] if 'decrypt_button' in self.languages[self.language] else ("解密" if self.language=='cn' else "Decrypt"), command=self.decrypt_chat_history)
        self.decrypt_button.pack(anchor=tk.W, pady=(5, 0))
        
        # 更新列表
        self.update_gui_lists()
    
    def update_gui_lists(self):
        """更新GUI列表"""
        # 更新在线用户列表
        self.users_listbox.delete(0, tk.END)
        for username in self.clients.keys():
            self.users_listbox.insert(tk.END, username)
        
        # 更新聊天会话列表
        self.chat_sessions_listbox.delete(0, tk.END)
        for session_key in self.chat_sessions.keys():
            if isinstance(session_key, tuple):
                session_name = f"{session_key[0]} ↔ {session_key[1]}"
            else:
                session_name = session_key
            self.chat_sessions_listbox.insert(tk.END, session_name)
    
    def on_chat_session_select(self, event=None):
        """聊天会话选择事件"""
        selection = self.chat_sessions_listbox.curselection()
        if selection:
            session_name = self.chat_sessions_listbox.get(selection[0])
            self.chat_title_label.config(text=f"会话: {session_name}")
            
            # 显示聊天记录
            self.chat_display.delete(1.0, tk.END)
            
            # 查找对应的会话
            for session_key, messages in self.chat_sessions.items():
                if isinstance(session_key, tuple):
                    display_name = f"{session_key[0]} ↔ {session_key[1]}"
                else:
                    display_name = session_key
                
                if display_name == session_name:
                    for msg in messages:
                        timestamp = msg.get('timestamp', '')
                        sender = msg.get('sender', '')
                        message = msg.get('message', '')
                        is_private = msg.get('is_private', False)
                        
                        display_msg = f"[{timestamp}] {sender}: {message}"
                        if is_private:
                            display_msg += " (阅后即焚)"
                        self.chat_display.insert(tk.END, display_msg + "\n")
                    break
    
    def start(self):
        """启动服务器"""
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            
            # 设置GUI
            self.setup_gui()
            
            # 启动服务器监听线程
            server_thread = threading.Thread(target=self.server_listen_loop)
            server_thread.daemon = True
            server_thread.start()
            
            print(f"服务器已启动，监听端口: {self.port}")
            
            # 启动GUI主循环
            self.root.mainloop()
                
        except Exception as e:
            print(f"服务器错误: {e}")
        finally:
            self.server_socket.close()
    
    def server_listen_loop(self):
        """服务器监听循环"""
        while True:
            try:
                client_socket, address = self.server_socket.accept()
                client_thread = threading.Thread(target=self.handle_client, args=(client_socket, address))
                client_thread.daemon = True
                client_thread.start()
            except Exception as e:
                print(f"接受连接错误: {e}")
                break
    
    def handle_client(self, client_socket, address):
        """处理客户端连接"""
        try:
            # 接收客户端信息
            data = client_socket.recv(1024).decode('utf-8')
            client_info = json.loads(data)
            username = client_info['username']
            language = client_info.get('language', 'cn')
            
            # 检查用户名是否已存在
            if username in self.clients:
                response = {'type': 'error', 'message': '用户名已存在'}
                client_socket.send(json.dumps(response).encode('utf-8'))
                client_socket.close()
                return
            
            # 添加客户端到列表
            self.clients[username] = (client_socket, address)
            self.client_sockets[client_socket] = username
            
            # 更新用户状态
            self.cursor.execute('''
                INSERT OR REPLACE INTO users (username, last_login, status)
                VALUES (?, ?, ?)
            ''', (username, datetime.datetime.now(), 'online'))
            self.db.commit()
            
            # 发送连接成功消息
            response = {
                'type': 'connection_success',
                'message': '连接成功',
                'online_users': list(self.clients.keys())
            }
            client_socket.send(json.dumps(response).encode('utf-8'))
            
            # 广播用户上线消息
            self.broadcast_user_status(username, 'online')
            
            # 更新GUI
            if self.root:
                self.root.after(0, self.update_gui_lists)
            
            print(f"客户端连接: {username} ({address})")
            
            # 处理客户端消息
            while True:
                try:
                    data = client_socket.recv(4096).decode('utf-8')
                    if not data:
                        break
                    
                    message_data = json.loads(data)
                    self.process_message(username, message_data)
                    
                except Exception as e:
                    print(f"处理客户端消息错误: {e}")
                    break
                    
        except Exception as e:
            print(f"客户端处理错误: {e}")
        finally:
            self.remove_client(username, client_socket)
    
    def remove_client(self, username, client_socket):
        """移除断开连接的客户端"""
        if username in self.clients:
            del self.clients[username]
        if client_socket in self.client_sockets:
            del self.client_sockets[client_socket]
        
        # 更新用户状态
        self.cursor.execute('''
            UPDATE users SET status = 'offline' WHERE username = ?
        ''', (username,))
        self.db.commit()
        
        # 广播用户下线消息
        self.broadcast_user_status(username, 'offline')
        
        # 更新GUI
        if self.root:
            self.root.after(0, self.update_gui_lists)
        
        print(f"客户端断开连接: {username}")
        client_socket.close()
    
    def broadcast_user_status(self, username, status):
        """广播用户状态变化"""
        message = {
            'type': 'user_status',
            'username': username,
            'status': status
        }
        self.broadcast_message(message, exclude_username=username)
    
    def process_message(self, sender, message_data):
        """处理客户端消息"""
        msg_type = message_data.get('type')
        
        if msg_type == 'private_message':
            self.handle_private_message(sender, message_data)
        elif msg_type == 'public_message':
            self.handle_public_message(sender, message_data)
        elif msg_type == 'group_request':
            self.handle_group_request(sender, message_data)
        elif msg_type == 'group_request_response':
            self.handle_group_request_response(sender, message_data)
    
    def handle_private_message(self, sender, message_data):
        """处理私聊消息"""
        receiver = message_data.get('receiver')
        message = message_data.get('message')
        is_private = message_data.get('is_private', False)
        
        if receiver in self.clients:
            # 发送给接收者
            response = {
                'type': 'private_message',
                'sender': sender,
                'message': message,
                'is_private': is_private,
                'timestamp': datetime.datetime.now().isoformat()
            }
            self.clients[receiver][0].send(json.dumps(response).encode('utf-8'))
            
            # 发送确认给发送者
            confirm = {
                'type': 'message_sent',
                'receiver': receiver,
                'message': message
            }
            self.clients[sender][0].send(json.dumps(confirm).encode('utf-8'))
            
            # 记录消息到数据库
            self.log_message(sender, receiver, message, 'text', is_private)
            
            # 记录到聊天会话
            session_key = tuple(sorted([sender, receiver]))
            if session_key not in self.chat_sessions:
                self.chat_sessions[session_key] = []
            
            self.chat_sessions[session_key].append({
                'sender': sender,
                'message': message,
                'timestamp': datetime.datetime.now().isoformat(),
                'is_private': is_private
            })
            
            # 更新GUI
            if self.root:
                self.root.after(0, self.update_gui_lists)
    
    def handle_public_message(self, sender, message_data):
        """处理公共消息"""
        message = message_data.get('message')
        
        # 发送给所有在线用户
        response = {
            'type': 'public_message',
            'sender': sender,
            'message': message,
            'timestamp': datetime.datetime.now().isoformat()
        }
        
        for username, (client_socket, _) in self.clients.items():
            if username != sender:
                try:
                    client_socket.send(json.dumps(response).encode('utf-8'))
                except Exception as e:
                    print(f"发送公共消息给 {username} 失败: {e}")
        
        # 记录消息到数据库
        self.log_message(sender, 'public', message, 'public')
        
        # 更新GUI
        if self.root:
            self.root.after(0, self.update_gui_lists)
    
    def handle_group_request(self, sender, message_data):
        """处理群组邀请请求"""
        group_name = message_data.get('group_name')
        members = message_data.get('members', [])
        
        if group_name not in self.group_requests:
            self.group_requests[group_name] = {
                'pending': set(members),
                'members': {sender},
                'admin': sender
            }
            
            # 发送邀请给成员
            for member in members:
                if member in self.clients:
                    response = {
                        'type': 'group_invitation',
                        'group_name': group_name,
                        'admin': sender
                    }
                    self.clients[member][0].send(json.dumps(response).encode('utf-8'))
    
    def handle_group_request_response(self, sender, message_data):
        """处理群组邀请响应"""
        group_name = message_data.get('group_name')
        accepted = message_data.get('accepted')
        
        if group_name in self.group_requests:
            if accepted:
                self.group_requests[group_name]['members'].add(sender)
                self.group_requests[group_name]['pending'].discard(sender)
                
                # 如果所有成员都同意了，创建群组
                if not self.group_requests[group_name]['pending']:
                    self.groups[group_name] = {
                        'members': self.group_requests[group_name]['members'].copy(),
                        'admin': self.group_requests[group_name]['admin']
                    }
                    
                    # 记录到数据库
                    self.cursor.execute('''
                        INSERT INTO groups (group_name, admin, created_time)
                        VALUES (?, ?, ?)
                    ''', (group_name, self.group_requests[group_name]['admin'], datetime.datetime.now()))
                    
                    for member in self.groups[group_name]['members']:
                        self.cursor.execute('''
                            INSERT INTO group_members (group_name, username, joined_time)
                            VALUES (?, ?, ?)
                        ''', (group_name, member, datetime.datetime.now()))
                    
                    self.db.commit()
                    
                    # 广播群组创建成功
                    response = {
                        'type': 'group_created',
                        'group_name': group_name,
                        'admin': self.group_requests[group_name]['admin']
                    }
                    self.broadcast_message(response)
                    
                    del self.group_requests[group_name]
    
    def broadcast_message(self, message, exclude_username=None):
        """广播消息给所有客户端"""
        for username, (client_socket, _) in self.clients.items():
            if username != exclude_username:
                try:
                    client_socket.send(json.dumps(message).encode('utf-8'))
                except Exception as e:
                    print(f"发送消息给 {username} 失败: {e}")

    def on_language_change(self, event=None):
        self.language = self.language_var.get()
        self.refresh_gui_language()

    def refresh_gui_language(self):
        # 刷新所有UI控件文本
        self.root.title(self.languages[self.language]['server_title'])
        # 状态栏
        import socket
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
        except:
            local_ip = "127.0.0.1"
        self.status_label.config(text=f"{self.languages[self.language]['current_ip'].format(local_ip)} | {self.languages[self.language]['server_started'].split(',')[0]}: {self.port}")
        # 用户锁按钮
        # 左侧面板
        for widget in self.root.winfo_children():
            for sub in widget.winfo_children():
                for subsub in sub.winfo_children():
                    if isinstance(subsub, ttk.Label):
                        txt = subsub.cget('text')
                        if '在线用户' in txt or 'Online Users' in txt:
                            subsub.config(text=self.languages[self.language]['online_users'])
                        elif '聊天会话' in txt or 'Chat Sessions' in txt:
                            subsub.config(text=self.languages[self.language]['chat'])
        # 聊天标题
        if hasattr(self, 'chat_title_label'):
            self.chat_title_label.config(text=self.languages[self.language]['chat'])
        # 其他弹窗、对话框等请在调用时用self.languages[self.language][...]

    def decrypt_chat_history(self):
        """解密当前会话的所有消息并显示"""
        selected_session_name = self.chat_sessions_listbox.get(self.chat_sessions_listbox.curselection()[0])
        
        # 查找对应的会话
        for session_key, messages in self.chat_sessions.items():
            if isinstance(session_key, tuple):
                display_name = f"{session_key[0]} ↔ {session_key[1]}"
            else:
                display_name = session_key
            
            if display_name == selected_session_name:
                self.chat_display.delete(1.0, tk.END) # 清空当前显示
                for msg in messages:
                    timestamp = msg.get('timestamp', '')
                    sender = msg.get('sender', '')
                    message = msg.get('message', '')
                    is_private = msg.get('is_private', False)
                    
                    # 解密消息
                    decrypted_message = xor_decrypt(message)
                    
                    display_msg = f"[{timestamp}] {sender}: {decrypted_message}"
                    if is_private:
                        display_msg += " (阅后即焚)"
                    self.chat_display.insert(tk.END, display_msg + "\n")
                break

if __name__ == '__main__':
    server = ChatServer()
    server.start() 