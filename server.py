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

class ChatServer:
    def __init__(self, host='0.0.0.0', port=5000):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # 客户端连接管理
        self.clients = {}  # {username: (socket, address)}
        self.client_sockets = {}  # {socket: username}
        
        # 群组管理
        self.groups = {}  # {group_name: {'members': set(), 'admin': username}}
        self.group_requests = {}  # {group_name: {'pending': set(), 'members': set(), 'admin': username}}
        
        # 聊天记录管理
        self.chat_sessions = {}  # {(user1, user2): [messages]}
        self.group_chat_sessions = {}  # {group_name: [messages]}
        
        # 用户锁功能
        self.user_lock_enabled = False
        self.user_lock_password = None
        
        # GUI相关
        self.root = None
        self.chat_display = None
        self.users_listbox = None
        self.groups_listbox = None
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
                'group_created': '群组 {} 已创建',
                'group_joined': '用户 {} 加入群组 {}',
                'group_left': '用户 {} 离开群组 {}',
                'server_title': 'Private Talking 服务器管理',
                'current_ip': '当前IP: {}',
                'online_users': '在线用户',
                'groups': '群组',
                'chat_sessions': '聊天会话',
                'user_lock': '用户锁',
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
                'enter_new_password': '请输入新密码:',
                'language_label': '语言:',
                'chat': '服务器监控'
            },
            'en': {
                'server_started': 'Server started, listening on port: {}',
                'client_connected': 'Client connected: {} ({})',
                'client_disconnected': 'Client disconnected: {}',
                'user_online': 'User {} is online',
                'user_offline': 'User {} is offline',
                'message_logged': 'Message logged',
                'file_logged': 'File transfer logged',
                'group_created': 'Group {} created',
                'group_joined': 'User {} joined group {}',
                'group_left': 'User {} left group {}',
                'server_title': 'Private Talking Server Management',
                'current_ip': 'Current IP: {}',
                'online_users': 'Online Users',
                'groups': 'Groups',
                'chat_sessions': 'Chat Sessions',
                'user_lock': 'User Lock',
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
                'enter_new_password': 'Enter new password:',
                'language_label': 'Language:',
                'chat': 'Server Monitor'
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
        
        # 创建文件传输日志表
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender TEXT,
                receiver TEXT,
                filename TEXT,
                filesize INTEGER,
                timestamp TIMESTAMP
            )
        ''')
        
        # 创建群组表
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS groups (
                group_name TEXT PRIMARY KEY,
                admin TEXT,
                created_time TIMESTAMP
            )
        ''')
        
        # 创建群组成员表
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS group_members (
                group_name TEXT,
                username TEXT,
                joined_time TIMESTAMP,
                PRIMARY KEY (group_name, username)
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
    
    def log_file_transfer(self, sender, receiver, filename, filesize):
        """记录文件传输到数据库"""
        try:
            self.cursor.execute('''
                INSERT INTO files (sender, receiver, filename, filesize, timestamp)
                VALUES (?, ?, ?, ?, ?)
            ''', (sender, receiver, filename, filesize, datetime.datetime.now()))
            self.db.commit()
        except Exception as e:
            print(f"Error logging file transfer: {e}")
    
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

        # 用户锁按钮
        lock_frame = ttk.Frame(top_frame)
        lock_frame.pack(side=tk.RIGHT)

        self.enable_lock_button = ttk.Button(lock_frame, text=self.languages[self.language]['enable_lock'], command=self.enable_user_lock)
        self.enable_lock_button.pack(side=tk.LEFT, padx=(0, 5))

        self.disable_lock_button = ttk.Button(lock_frame, text=self.languages[self.language]['disable_lock'], command=self.disable_user_lock, state=tk.DISABLED)
        self.disable_lock_button.pack(side=tk.LEFT, padx=(0, 5))

        self.change_password_button = ttk.Button(lock_frame, text=self.languages[self.language]['change_password'], command=self.change_password, state=tk.DISABLED)
        self.change_password_button.pack(side=tk.LEFT)

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
        
        # 群组列表
        ttk.Label(left_panel, text=self.languages[self.language]['groups'], font=('Arial', 12, 'bold')).pack(anchor=tk.W, pady=(0, 5))
        self.groups_listbox = tk.Listbox(left_panel, height=8)
        self.groups_listbox.pack(fill=tk.X, pady=(0, 10))
        
        # 聊天会话列表
        ttk.Label(left_panel, text=self.languages[self.language]['chat_sessions'], font=('Arial', 12, 'bold')).pack(anchor=tk.W, pady=(0, 5))
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
        
        # 更新列表
        self.update_gui_lists()
    
    def update_gui_lists(self):
        """更新GUI列表"""
        # 更新在线用户列表
        self.users_listbox.delete(0, tk.END)
        for username in self.clients.keys():
            self.users_listbox.insert(tk.END, username)
        
        # 更新群组列表
        self.groups_listbox.delete(0, tk.END)
        for group_name in self.groups.keys():
            self.groups_listbox.insert(tk.END, group_name)
        
        # 更新聊天会话列表
        self.chat_sessions_listbox.delete(0, tk.END)
        for session_key in self.chat_sessions.keys():
            if isinstance(session_key, tuple):
                session_name = f"{session_key[0]} ↔ {session_key[1]}"
            else:
                session_name = session_key
            self.chat_sessions_listbox.insert(tk.END, session_name)
        
        # 添加群组会话
        for group_name in self.group_chat_sessions.keys():
            self.chat_sessions_listbox.insert(tk.END, group_name)
    
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
            
            # 查找群组会话
            for group_name, messages in self.group_chat_sessions.items():
                if group_name == session_name:
                    for msg in messages:
                        timestamp = msg.get('timestamp', '')
                        sender = msg.get('sender', '')
                        message = msg.get('message', '')
                        
                        display_msg = f"[{timestamp}] {sender}: {message}"
                        self.chat_display.insert(tk.END, display_msg + "\n")
                    break
    
    def enable_user_lock(self):
        """启用用户锁"""
        if self.user_lock_enabled:
            messagebox.showinfo("提示", "用户锁已经启用")
            return
        
        # 输入密码
        password = tk.simpledialog.askstring("用户锁", self.languages[self.language]['enter_password'], show='*')
        if not password:
            return
        
        # 确认密码
        confirm_password = tk.simpledialog.askstring("用户锁", self.languages[self.language]['confirm_password'], show='*')
        if not confirm_password:
            return
        
        if password != confirm_password:
            messagebox.showerror("错误", self.languages[self.language]['password_mismatch'])
            return
        
        self.user_lock_enabled = True
        self.user_lock_password = password
        
        self.enable_lock_button.config(state=tk.DISABLED)
        self.disable_lock_button.config(state=tk.NORMAL)
        self.change_password_button.config(state=tk.NORMAL)
        
        messagebox.showinfo("成功", self.languages[self.language]['lock_enabled'])
    
    def disable_user_lock(self):
        """解除用户锁"""
        if not self.user_lock_enabled:
            messagebox.showinfo("提示", "用户锁未启用")
            return
        
        # 输入密码
        password = tk.simpledialog.askstring("用户锁", self.languages[self.language]['enter_password'], show='*')
        if not password:
            return
        
        if password != self.user_lock_password:
            messagebox.showerror("错误", self.languages[self.language]['wrong_password'])
            return
        
        self.user_lock_enabled = False
        self.user_lock_password = None
        
        self.enable_lock_button.config(state=tk.NORMAL)
        self.disable_lock_button.config(state=tk.DISABLED)
        self.change_password_button.config(state=tk.DISABLED)
        
        messagebox.showinfo("成功", self.languages[self.language]['lock_disabled'])
    
    def change_password(self):
        """更改密码"""
        if not self.user_lock_enabled:
            messagebox.showinfo("提示", "用户锁未启用")
            return
        
        # 输入原密码
        old_password = tk.simpledialog.askstring("用户锁", self.languages[self.language]['enter_old_password'], show='*')
        if not old_password:
            return
        
        if old_password != self.user_lock_password:
            messagebox.showerror("错误", self.languages[self.language]['wrong_password'])
            return
        
        # 输入新密码
        new_password = tk.simpledialog.askstring("用户锁", self.languages[self.language]['enter_new_password'], show='*')
        if not new_password:
            return
        
        # 确认新密码
        confirm_password = tk.simpledialog.askstring("用户锁", self.languages[self.language]['confirm_password'], show='*')
        if not confirm_password:
            return
        
        if new_password != confirm_password:
            messagebox.showerror("错误", self.languages[self.language]['password_mismatch'])
            return
        
        self.user_lock_password = new_password
        messagebox.showinfo("成功", self.languages[self.language]['password_changed'])
    
    def check_user_lock(self):
        """检查用户锁"""
        if not self.user_lock_enabled:
            return True
        
        password = tk.simpledialog.askstring("用户锁", self.languages[self.language]['enter_password'], show='*')
        if password == self.user_lock_password:
            return True
        else:
            messagebox.showerror("错误", self.languages[self.language]['wrong_password'])
            return False
    
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
                'online_users': list(self.clients.keys()),
                'groups': list(self.groups.keys())
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
        elif msg_type == 'group_message':
            self.handle_group_message(sender, message_data)
        elif msg_type == 'file_transfer':
            self.handle_file_transfer(sender, message_data)
        elif msg_type == 'create_group':
            self.handle_create_group(sender, message_data)
        elif msg_type == 'join_group':
            self.handle_join_group(sender, message_data)
        elif msg_type == 'leave_group':
            self.handle_leave_group(sender, message_data)
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
    
    def handle_group_message(self, sender, message_data):
        """处理群聊消息"""
        group_name = message_data.get('group_name')
        message = message_data.get('message')
        
        if group_name in self.groups and sender in self.groups[group_name]['members']:
            # 发送给群组所有成员
            response = {
                'type': 'group_message',
                'group_name': group_name,
                'sender': sender,
                'message': message,
                'timestamp': datetime.datetime.now().isoformat()
            }
            
            for member in self.groups[group_name]['members']:
                if member in self.clients and member != sender:
                    self.clients[member][0].send(json.dumps(response).encode('utf-8'))
            
            # 记录消息到数据库
            self.log_message(sender, group_name, message, 'group')
            
            # 记录到群聊会话
            if group_name not in self.group_chat_sessions:
                self.group_chat_sessions[group_name] = []
            
            self.group_chat_sessions[group_name].append({
                'sender': sender,
                'message': message,
                'timestamp': datetime.datetime.now().isoformat()
            })
            
            # 更新GUI
            if self.root:
                self.root.after(0, self.update_gui_lists)
    
    def handle_file_transfer(self, sender, message_data):
        """处理文件传输"""
        receiver = message_data.get('receiver')
        filename = message_data.get('filename')
        file_data = message_data.get('file_data')
        filesize = message_data.get('filesize')
        
        # 保存服务器副本
        try:
            safe_filename = f"{sender}---{receiver}---{filename}"
            with open(safe_filename, 'wb') as f:
                f.write(base64.b64decode(file_data))
        except Exception as e:
            print(f"保存文件副本失败: {e}")
        
        if receiver in self.clients:
            # 发送文件给接收者
            response = {
                'type': 'file_transfer',
                'sender': sender,
                'filename': filename,
                'file_data': file_data,
                'filesize': filesize,
                'timestamp': datetime.datetime.now().isoformat()
            }
            self.clients[receiver][0].send(json.dumps(response).encode('utf-8'))
            
            # 记录文件传输
            self.log_file_transfer(sender, receiver, filename, filesize)
    
    def handle_create_group(self, sender, message_data):
        """处理创建群组"""
        group_name = message_data.get('group_name')
        
        if group_name not in self.groups:
            self.groups[group_name] = {
                'members': {sender},
                'admin': sender
            }
            
            # 记录群组到数据库
            self.cursor.execute('''
                INSERT INTO groups (group_name, admin, created_time)
                VALUES (?, ?, ?)
            ''', (group_name, sender, datetime.datetime.now()))
            
            self.cursor.execute('''
                INSERT INTO group_members (group_name, username, joined_time)
                VALUES (?, ?, ?)
            ''', (group_name, sender, datetime.datetime.now()))
            
            self.db.commit()
            
            # 广播群组创建消息
            response = {
                'type': 'group_created',
                'group_name': group_name,
                'admin': sender
            }
            self.broadcast_message(response)
            
            # 更新GUI
            if self.root:
                self.root.after(0, self.update_gui_lists)
    
    def handle_join_group(self, sender, message_data):
        """处理加入群组"""
        group_name = message_data.get('group_name')
        
        if group_name in self.groups and sender not in self.groups[group_name]['members']:
            self.groups[group_name]['members'].add(sender)
            
            # 记录到数据库
            self.cursor.execute('''
                INSERT INTO group_members (group_name, username, joined_time)
                VALUES (?, ?, ?)
            ''', (group_name, sender, datetime.datetime.now()))
            self.db.commit()
            
            # 广播加入群组消息
            response = {
                'type': 'group_joined',
                'group_name': group_name,
                'username': sender
            }
            self.broadcast_message(response)
            
            # 更新GUI
            if self.root:
                self.root.after(0, self.update_gui_lists)
    
    def handle_leave_group(self, sender, message_data):
        """处理离开群组"""
        group_name = message_data.get('group_name')
        
        if group_name in self.groups and sender in self.groups[group_name]['members']:
            self.groups[group_name]['members'].remove(sender)
            
            # 从数据库删除
            self.cursor.execute('''
                DELETE FROM group_members WHERE group_name = ? AND username = ?
            ''', (group_name, sender))
            self.db.commit()
            
            # 广播离开群组消息
            response = {
                'type': 'group_left',
                'group_name': group_name,
                'username': sender
            }
            self.broadcast_message(response)
    
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
        self.enable_lock_button.config(text=self.languages[self.language]['enable_lock'])
        self.disable_lock_button.config(text=self.languages[self.language]['disable_lock'])
        self.change_password_button.config(text=self.languages[self.language]['change_password'])
        # 左侧面板
        for widget in self.root.winfo_children():
            for sub in widget.winfo_children():
                for subsub in sub.winfo_children():
                    if isinstance(subsub, ttk.Label):
                        txt = subsub.cget('text')
                        if '在线用户' in txt or 'Online Users' in txt:
                            subsub.config(text=self.languages[self.language]['online_users'])
                        elif '群组' in txt or 'Groups' in txt:
                            subsub.config(text=self.languages[self.language]['groups'])
                        elif '聊天会话' in txt or 'Chat Sessions' in txt:
                            subsub.config(text=self.languages[self.language]['chat_sessions'])
        # 聊天标题
        if hasattr(self, 'chat_title_label'):
            self.chat_title_label.config(text=self.languages[self.language]['chat'])
        # 其他弹窗、对话框等请在调用时用self.languages[self.language][...]

if __name__ == '__main__':
    server = ChatServer()
    server.start() 