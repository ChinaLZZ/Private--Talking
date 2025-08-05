import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import socket
import threading
import json
import base64
import os
import datetime
from tkinter import font as tkfont

# 1. 简易异或加密/解密工具

def xor_crypt(data, key=0x5A):
    if isinstance(data, str):
        data = data.encode('utf-8')
    return bytes([b ^ key for b in data]).decode('latin1')

def xor_decrypt(data, key=0x5A):
    if isinstance(data, str):
        data = data.encode('latin1')
    return bytes([b ^ key for b in data]).decode('utf-8')

class ChatClient:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Private Talking Chat")
        self.root.geometry("1000x700")
        self.root.configure(bg='#f0f0f0')
        
        # 客户端状态
        self.socket = None
        self.username = ""
        self.server_ip = ""
        self.language = "cn"
        self.is_connected = False
        self.is_private_mode = False
        
        # 聊天记录
        self.chat_history = {}  # {username: [messages]}
        
        # 在线用户和群组
        self.online_users = []
        self.groups = []
        
        # 语言支持
        self.languages = {
            'cn': {
                'title': 'Private Talking 聊天软件',
                'language_label': '选择语言 / Select Language:',
                'username_label': '用户名:',
                'server_ip_label': '服务器IP:',
                'connect_button': '连接',
                'disconnect_button': '断开',
                'send_button': '发送',
                'private_mode': '隐私模式',
                'create_group': '创建群组',
                'join_group': '加入群组',
                'leave_group': '离开群组',
                'online_users': '在线用户',
                'groups': '群组',
                'chat': '聊天',
                'message_placeholder': '输入消息...',
                'connection_success': '连接成功！',
                'connection_failed': '连接失败！',
                'username_exists': '用户名已存在！',
                'group_created': '群组 {} 创建成功！',
                'group_joined': '已加入群组 {}',
                'group_left': '已离开群组 {}',
                'user_online': '用户 {} 上线',
                'user_offline': '用户 {} 下线',
                'private_message': '阅后即焚消息',
                'select_file': '选择文件',
                'create_group_title': '创建群组',
                'group_name_label': '群组名称:',
                'join_group_title': '加入群组',
                'group_invitation': '群组邀请',
                'invitation_message': '用户 {} 邀请您加入群组 {}',
                'accept': '接受',
                'decline': '拒绝'
            },
            'en': {
                'title': 'Private Talking Chat',
                'language_label': 'Select Language / 选择语言:',
                'username_label': 'Username:',
                'server_ip_label': 'Server IP:',
                'connect_button': 'Connect',
                'disconnect_button': 'Disconnect',
                'send_button': 'Send',
                'private_mode': 'Private Mode',
                'create_group': 'Create Group',
                'join_group': 'Join Group',
                'leave_group': 'Leave Group',
                'online_users': 'Online Users',
                'groups': 'Groups',
                'chat': 'Chat',
                'message_placeholder': 'Type message...',
                'connection_success': 'Connected successfully!',
                'connection_failed': 'Connection failed!',
                'username_exists': 'Username already exists!',
                'group_created': 'Group {} created successfully!',
                'group_joined': 'Joined group {}',
                'group_left': 'Left group {}',
                'user_online': 'User {} is online',
                'user_offline': 'User {} is offline',
                'private_message': 'Self-destruct message',
                'select_file': 'Select File',
                'create_group_title': 'Create Group',
                'group_name_label': 'Group Name:',
                'join_group_title': 'Join Group',
                'group_invitation': 'Group Invitation',
                'invitation_message': 'User {} invited you to join group {}',
                'accept': 'Accept',
                'decline': 'Decline'
            }
        }
        
        self.setup_ui()
        self.update_language()
    
    def setup_ui(self):
        """设置用户界面"""
        # 主框架
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # 顶部连接区域
        top_frame = ttk.Frame(main_frame)
        top_frame.pack(fill=tk.X, pady=(0, 10))
        
        # 语言选择
        ttk.Label(top_frame, text="选择语言 / Select Language:").pack(side=tk.LEFT, padx=(0, 10))
        self.language_var = tk.StringVar(value="cn")
        language_combo = ttk.Combobox(top_frame, textvariable=self.language_var, 
                                     values=["cn", "en"], state="readonly", width=10)
        language_combo.pack(side=tk.LEFT, padx=(0, 20))
        language_combo.bind('<<ComboboxSelected>>', self.on_language_change)
        
        # 用户名输入
        ttk.Label(top_frame, text="用户名:").pack(side=tk.LEFT, padx=(0, 5))
        self.username_entry = ttk.Entry(top_frame, width=15)
        self.username_entry.pack(side=tk.LEFT, padx=(0, 10))
        
        # 服务器IP输入
        ttk.Label(top_frame, text="服务器IP:").pack(side=tk.LEFT, padx=(0, 5))
        self.server_ip_entry = ttk.Entry(top_frame, width=15)
        self.server_ip_entry.pack(side=tk.LEFT, padx=(0, 10))
        self.server_ip_entry.insert(0, "127.0.0.1")
        
        # 连接按钮
        self.connect_button = ttk.Button(top_frame, text="连接", command=self.connect_to_server)
        self.connect_button.pack(side=tk.LEFT, padx=(0, 5))
        
        # 断开连接按钮
        self.disconnect_button = ttk.Button(top_frame, text="断开", command=self.disconnect_from_server, state=tk.DISABLED)
        self.disconnect_button.pack(side=tk.LEFT, padx=(0, 10))
        
        # 隐私模式复选框
        self.private_mode_var = tk.BooleanVar()
        self.private_mode_check = ttk.Checkbutton(top_frame, text="隐私模式", 
                                                 variable=self.private_mode_var)
        self.private_mode_check.pack(side=tk.LEFT)
        
        # 主要内容区域
        content_frame = ttk.Frame(main_frame)
        content_frame.pack(fill=tk.BOTH, expand=True)
        
        # 左侧面板 - 只保留在线用户和公共聊天室按钮
        left_panel = ttk.Frame(content_frame, width=200)
        left_panel.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        left_panel.pack_propagate(False)

        # 在线用户列表
        ttk.Label(left_panel, text="在线用户", font=('Arial', 12, 'bold')).pack(anchor=tk.W, pady=(0, 5))
        self.users_listbox = tk.Listbox(left_panel, height=10)
        self.users_listbox.pack(fill=tk.X, pady=(0, 10))
        self.users_listbox.bind('<<ListboxSelect>>', self.on_user_select)

        # 右侧聊天区域
        chat_frame = ttk.Frame(content_frame)
        chat_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        # 聊天标题
        self.chat_title_label = ttk.Label(chat_frame, text="聊天", font=('Arial', 14, 'bold'))
        self.chat_title_label.pack(anchor=tk.W, pady=(0, 5))
        
        # 聊天记录显示区域
        self.chat_display = scrolledtext.ScrolledText(chat_frame, height=20, wrap=tk.WORD)
        self.chat_display.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        # 删除聊天窗口的“解密”按钮及相关UI、方法
        # 所有收到的消息（handle_private_message等）自动用xor_decrypt解密后显示，无需手动操作
        
        # 消息输入区域
        input_frame = ttk.Frame(chat_frame)
        input_frame.pack(fill=tk.X)

        self.message_entry = ttk.Entry(input_frame)
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        self.message_entry.bind('<Return>', lambda e: self.send_message())
        # 新增：占位文本自动消失/恢复
        self.message_entry.bind('<FocusIn>', self._clear_placeholder)
        self.message_entry.bind('<FocusOut>', self._restore_placeholder)
        self._placeholder_active = True
        self._set_placeholder()

        self.send_button = ttk.Button(input_frame, text="发送", command=self.send_message)
        self.send_button.pack(side=tk.LEFT, padx=(0, 5))

        # 删除所有 self.root.bell() 相关提示音代码
        # 删除 send_file、file_button、handle_file_transfer 及相关UI、调用、菜单等
    
    def _set_placeholder(self):
        placeholder = self.languages[self.language]['message_placeholder']
        self.message_entry.delete(0, tk.END)
        self.message_entry.insert(0, placeholder)
        self.message_entry.config(foreground='grey')
        self._placeholder_active = True

    def _clear_placeholder(self, event=None):
        if self._placeholder_active:
            self.message_entry.delete(0, tk.END)
            self.message_entry.config(foreground='black')
            self._placeholder_active = False

    def _restore_placeholder(self, event=None):
        if not self.message_entry.get():
            self._set_placeholder()

    def update_language(self):
        """更新界面语言"""
        lang = self.languages[self.language]
        
        self.root.title(lang['title'])
        
        # 更新按钮文本
        self.connect_button.config(text=lang['connect_button'])
        self.disconnect_button.config(text=lang['disconnect_button'])
        self.send_button.config(text=lang['send_button'])
        self.private_mode_check.config(text=lang['private_mode'])
        
        # 更新标签文本
        self.chat_title_label.config(text=lang['chat'])
        
        # 更新输入框占位符
        if not self.message_entry.get() or self._placeholder_active:
            self._set_placeholder()
        else:
            self.message_entry.config(foreground='black')
    
    def on_language_change(self, event=None):
        """语言改变事件"""
        self.language = self.language_var.get()
        self.update_language()
    
    def start_connectivity_check(self):
        def check():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(3)
                s.connect((self.server_ip, 5000))
                s.close()
            except Exception:
                messagebox.showerror("连接失败", "与服务器失去连接，程序将自动退出。")
                self.root.quit()
                return
            self.root.after(30000, check)
        self.root.after(30000, check)

    def connect_to_server(self):
        """连接到服务器"""
        self.username = self.username_entry.get().strip()
        self.server_ip = self.server_ip_entry.get().strip()
        
        if not self.username or not self.server_ip:
            messagebox.showerror("错误", "请输入用户名和服务器IP")
            return
        
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.server_ip, 5000))
            
            # 发送连接信息
            connection_info = {
                'username': self.username,
                'language': self.language
            }
            self.socket.send(json.dumps(connection_info).encode('utf-8'))
            
            # 接收服务器响应
            response = self.socket.recv(1024).decode('utf-8')
            response_data = json.loads(response)
            
            if response_data['type'] == 'connection_success':
                self.is_connected = True
                self.connect_button.config(state=tk.DISABLED)
                self.disconnect_button.config(state=tk.NORMAL)
                self.username_entry.config(state=tk.DISABLED)
                self.server_ip_entry.config(state=tk.DISABLED)
                
                # 更新在线用户和群组列表
                self.online_users = response_data.get('online_users', [])
                self.groups = response_data.get('groups', [])
                self.update_users_list()
                self.update_groups_list()
                
                # 启动接收消息的线程
                self.receive_thread = threading.Thread(target=self.receive_messages)
                self.receive_thread.daemon = True
                self.receive_thread.start()
                
                messagebox.showinfo("成功", self.languages[self.language]['connection_success'])
                self.start_connectivity_check()
                
            elif response_data['type'] == 'error':
                messagebox.showerror("错误", response_data['message'])
                self.socket.close()
                
        except Exception as e:
            messagebox.showerror("错误", f"连接失败: {str(e)}")
            if self.socket:
                self.socket.close()
    
    def disconnect_from_server(self):
        """断开服务器连接"""
        if self.socket:
            self.socket.close()
        
        self.is_connected = False
        self.connect_button.config(state=tk.NORMAL)
        self.disconnect_button.config(state=tk.DISABLED)
        self.username_entry.config(state=tk.NORMAL)
        self.server_ip_entry.config(state=tk.NORMAL)
        
        # 清空列表
        self.online_users = []
        self.groups = []
        self.update_users_list()
        self.update_groups_list()
        self.chat_display.delete(1.0, tk.END)
        # 断开连接长蜂鸣
        # self.root.after(100, self.root.bell); self.root.after(300, self.root.bell)
    
    def receive_messages(self):
        """接收服务器消息"""
        while self.is_connected:
            try:
                data = self.socket.recv(4096).decode('utf-8')
                if not data:
                    break
                
                message_data = json.loads(data)
                self.handle_server_message(message_data)
                
            except Exception as e:
                print(f"接收消息错误: {e}")
                break
        
        # 连接断开
        self.root.after(0, self.disconnect_from_server)
    
    def handle_server_message(self, message_data):
        """处理服务器消息"""
        msg_type = message_data.get('type')
        
        if msg_type == 'private_message':
            self.handle_private_message(message_data)
        elif msg_type == 'user_status':
            self.handle_user_status(message_data)
        elif msg_type == 'group_created':
            self.handle_group_created(message_data)
        elif msg_type == 'group_joined':
            self.handle_group_joined(message_data)
        elif msg_type == 'group_left':
            self.handle_group_left(message_data)
        elif msg_type == 'group_invitation':
            self.handle_group_invitation(message_data)
        elif msg_type == 'message_sent':
            self.handle_message_sent(message_data)
    
    def handle_private_message(self, message_data):
        """处理私聊消息"""
        sender = message_data['sender']
        # 自动解密消息内容
        message = xor_decrypt(message_data['message'])
        is_private = message_data.get('is_private', False)
        timestamp = message_data.get('timestamp', '')
        
        # 添加到聊天记录
        if sender not in self.chat_history:
            self.chat_history[sender] = []
        
        self.chat_history[sender].append({
            'sender': sender,
            'message': message,
            'timestamp': timestamp,
            'is_private': is_private
        })
        
        # 蜂鸣音和弹窗提醒
        if is_private:
            # 双蜂鸣
            # self.root.bell(); self.root.after(100, self.root.bell)
            messagebox.showinfo(self.languages[self.language]['private_message'],
                                self.languages[self.language]['private_message'] + "\n" + message)
        else:
            # 普通消息短蜂鸣
            # self.root.bell()
            pass # 移除蜂鸣音
        
        # 检查当前是否正在与发送者聊天
        current_user_selection = self.users_listbox.curselection()
        if current_user_selection:
            current_user = self.users_listbox.get(current_user_selection[0])
            if current_user == sender:
                # 显示消息
                display_message = f"[{timestamp}] {sender}: {message}"
                if is_private:
                    display_message += " (阅后即焚)"
                
                self.chat_display.insert(tk.END, display_message + "\n")
                self.chat_display.see(tk.END)
        
        # 如果是阅后即焚消息，5秒后删除
        if is_private:
            self.root.after(5000, lambda: self.delete_private_message(sender, len(self.chat_history[sender]) - 1))
    
    def handle_user_status(self, message_data):
        """处理用户状态变化"""
        username = message_data['username']
        status = message_data['status']
        
        if status == 'online':
            if username not in self.online_users:
                self.online_users.append(username)
        elif status == 'offline':
            if username in self.online_users:
                self.online_users.remove(username)
        
        self.update_users_list()
        
        # 显示状态消息
        status_msg = self.languages[self.language]['user_online' if status == 'online' else 'user_offline'].format(username)
        self.chat_display.insert(tk.END, f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {status_msg}\n")
        self.chat_display.see(tk.END)
    
    def handle_group_created(self, message_data):
        """处理群组创建"""
        group_name = message_data['group_name']
        if group_name not in self.groups:
            self.groups.append(group_name)
        self.update_groups_list()
    
    def handle_group_joined(self, message_data):
        """处理加入群组"""
        group_name = message_data['group_name']
        username = message_data['username']
        
        if group_name not in self.groups:
            self.groups.append(group_name)
        self.update_groups_list()
        
        # 显示加入消息
        join_msg = self.languages[self.language]['group_joined'].format(group_name)
        self.chat_display.insert(tk.END, f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {username}: {join_msg}\n")
        self.chat_display.see(tk.END)
    
    def handle_group_left(self, message_data):
        """处理离开群组"""
        group_name = message_data['group_name']
        username = message_data['username']
        
        # 显示离开消息
        leave_msg = self.languages[self.language]['group_left'].format(group_name)
        self.chat_display.insert(tk.END, f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {username}: {leave_msg}\n")
        self.chat_display.see(tk.END)
    
    def handle_group_invitation(self, message_data):
        """处理群组邀请"""
        group_name = message_data['group_name']
        admin = message_data['admin']
        # 三短蜂鸣
        # self.root.bell(); self.root.after(100, self.root.bell); self.root.after(200, self.root.bell)
        # 显示邀请对话框
        invite_msg = self.languages[self.language]['invitation_message'].format(admin, group_name)
        result = messagebox.askyesno(
            self.languages[self.language]['group_invitation'],
            invite_msg
        )
        # 发送响应
        response = {
            'type': 'group_request_response',
            'group_name': group_name,
            'accepted': result
        }
        self.socket.send(json.dumps(response).encode('utf-8'))
    
    def handle_message_sent(self, message_data):
        """处理消息发送确认"""
        receiver = message_data['receiver']
        message = message_data['message']
        
        # 显示发送确认
        confirm_msg = f"消息已发送给 {receiver}"
        self.chat_display.insert(tk.END, f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {confirm_msg}\n")
        self.chat_display.see(tk.END)
    
    def update_users_list(self):
        """更新在线用户列表"""
        self.users_listbox.delete(0, tk.END)
        for user in self.online_users:
            if user != self.username:
                self.users_listbox.insert(tk.END, user)
    
    def update_groups_list(self):
        """更新群组列表"""
        # 删除所有 self.groups_listbox 相关代码，包括：
        # - self.groups_listbox.delete(0, tk.END)
        # - self.groups_listbox.insert(tk.END, group)
        # - selection = self.groups_listbox.curselection()
        # - selected_group = self.groups_listbox.get(selection[0])
        # - group_selection = self.groups_listbox.curselection()
        # - group_name = self.groups_listbox.get(group_selection[0])
        # - 相关方法、事件绑定、UI等
    
    def on_user_select(self, event=None):
        """用户选择事件"""
        selection = self.users_listbox.curselection()
        if selection:
            selected_user = self.users_listbox.get(selection[0])
            self.chat_title_label.config(text=f"与 {selected_user} 聊天")
            
            # 显示聊天记录
            self.chat_display.delete(1.0, tk.END)
            if selected_user in self.chat_history:
                for msg in self.chat_history[selected_user]:
                    display_msg = f"[{msg['timestamp']}] {msg['sender']}: {msg['message']}"
                    if msg.get('is_private', False):
                        display_msg += " (阅后即焚)"
                    self.chat_display.insert(tk.END, display_msg + "\n")
    
    def on_group_select(self, event=None):
        """群组选择事件"""
        # 删除所有 self.groups_listbox 相关代码，包括：
        # - self.groups_listbox.delete(0, tk.END)
        # - self.groups_listbox.insert(tk.END, group)
        # - selection = self.groups_listbox.curselection()
        # - selected_group = self.groups_listbox.get(selection[0])
        # - group_selection = self.groups_listbox.curselection()
        # - group_name = self.groups_listbox.get(group_selection[0])
        # - 相关方法、事件绑定、UI等
    
    def send_message(self):
        """发送消息"""
        if not self.is_connected:
            return
        message = self.message_entry.get().strip()
        if not message:
            return
        user_selection = self.users_listbox.curselection()
        if user_selection:
            # 发送私聊消息
            receiver = self.users_listbox.get(user_selection[0])
            message_data = {
                'type': 'private_message',
                'receiver': receiver,
                'message': xor_crypt(message),
                'is_private': self.private_mode_var.get()
            }
            # 本地记录
            if receiver not in self.chat_history:
                self.chat_history[receiver] = []
            self.chat_history[receiver].append({
                'sender': self.username,
                'message': xor_crypt(message),
                'timestamp': datetime.datetime.now().isoformat(),
                'is_private': self.private_mode_var.get()
            })
        else:
            # 发送到公共聊天室
            message_data = {
                'type': 'group_message',
                'group_name': 'public',
                'message': xor_crypt(message)
            }
            # 本地记录
            if 'public' not in self.group_chat_history:
                self.group_chat_history['public'] = []
            self.group_chat_history['public'].append({
                'sender': self.username,
                'message': xor_crypt(message),
                'timestamp': datetime.datetime.now().isoformat()
            })
        try:
            self.socket.send(json.dumps(message_data).encode('utf-8'))
            self.message_entry.delete(0, tk.END)
            # 立即显示
            if user_selection:
                receiver = self.users_listbox.get(user_selection[0])
                display_message = f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {self.username}: {message}"
                if self.private_mode_var.get():
                    display_message += " (阅后即焚)"
                self.chat_display.insert(tk.END, display_message + "\n")
                self.chat_display.see(tk.END)
            else:
                display_message = f"[{datetime.datetime.now().strftime('%H:%M:%S')}] 公共聊天室 - {self.username}: {message}"
                self.chat_display.insert(tk.END, display_message + "\n")
                self.chat_display.see(tk.END)
        except Exception as e:
            messagebox.showerror("错误", f"发送消息失败: {str(e)}")
    
    # 删除所有 self.root.bell() 相关提示音代码
    # 删除 send_file、file_button、handle_file_transfer 及相关UI、调用、菜单等
    
    def create_group_dialog(self):
        """创建群组对话框"""
        if not self.is_connected:
            messagebox.showwarning("警告", "请先连接到服务器")
            return
        
        dialog = tk.Toplevel(self.root)
        dialog.title(self.languages[self.language]['create_group_title'])
        dialog.geometry("300x150")
        dialog.transient(self.root)
        dialog.grab_set()
        
        ttk.Label(dialog, text=self.languages[self.language]['group_name_label']).pack(pady=10)
        group_name_entry = ttk.Entry(dialog, width=30)
        group_name_entry.pack(pady=10)
        
        def create_group():
            group_name = group_name_entry.get().strip()
            if group_name:
                # 获取当前在线用户列表（不含自己）
                online_users_for_group = [u for u in self.online_users if u != self.username]
                
                message_data = {
                    'type': 'create_group',
                    'group_name': group_name,
                    'members': online_users_for_group # 发送成员列表
                }
                self.socket.send(json.dumps(message_data).encode('utf-8'))
                dialog.destroy()
            else:
                messagebox.showwarning("警告", "请输入群组名称")
        
        ttk.Button(dialog, text="创建", command=create_group).pack(pady=10)
    
    def join_group_dialog(self):
        """加入群组对话框"""
        if not self.is_connected:
            messagebox.showwarning("警告", "请先连接到服务器")
            return
        
        dialog = tk.Toplevel(self.root)
        dialog.title(self.languages[self.language]['join_group_title'])
        dialog.geometry("300x150")
        dialog.transient(self.root)
        dialog.grab_set()
        
        ttk.Label(dialog, text=self.languages[self.language]['group_name_label']).pack(pady=10)
        group_name_entry = ttk.Entry(dialog, width=30)
        group_name_entry.pack(pady=10)
        
        def join_group():
            group_name = group_name_entry.get().strip()
            if group_name:
                # 获取当前在线用户列表（不含自己）
                online_users_for_group = [u for u in self.online_users if u != self.username]
                
                message_data = {
                    'type': 'join_group',
                    'group_name': group_name,
                    'members': online_users_for_group # 发送成员列表
                }
                self.socket.send(json.dumps(message_data).encode('utf-8'))
                dialog.destroy()
            else:
                messagebox.showwarning("警告", "请输入群组名称")
        
        ttk.Button(dialog, text="加入", command=join_group).pack(pady=10)
    
    def leave_group(self):
        """离开群组"""
        if not self.is_connected:
            messagebox.showwarning("警告", "请先连接到服务器")
            return
        
        group_selection = self.groups_listbox.curselection() # This line will cause an error
        if not group_selection:
            messagebox.showwarning("警告", "请选择要离开的群组")
            return
        
        group_name = self.groups_listbox.get(group_selection[0]) # This line will cause an error
        
        if messagebox.askyesno("确认", f"确定要离开群组 {group_name} 吗？"):
            message_data = {
                'type': 'leave_group',
                'group_name': group_name
            }
            self.socket.send(json.dumps(message_data).encode('utf-8'))
    
    def delete_private_message(self, sender, message_index):
        """删除阅后即焚消息"""
        if sender in self.chat_history and message_index < len(self.chat_history[sender]):
            # 从聊天记录中删除
            del self.chat_history[sender][message_index]
            
            # 重新显示聊天记录
            self.chat_display.delete(1.0, tk.END)
            for msg in self.chat_history[sender]:
                display_msg = f"[{msg['timestamp']}] {msg['sender']}: {msg['message']}"
                if msg.get('is_private', False):
                    display_msg += " (阅后即焚)"
                self.chat_display.insert(tk.END, display_msg + "\n")
    
    def _delete_private_file(self, save_path, filename, sender):
        try:
            if os.path.exists(save_path):
                os.remove(save_path)
            # 清除界面记录
            lines = self.chat_display.get(1.0, tk.END).splitlines()
            new_lines = [line for line in lines if filename not in line or sender not in line]
            self.chat_display.delete(1.0, tk.END)
            for line in new_lines:
                self.chat_display.insert(tk.END, line + '\n')
        except Exception as e:
            print(f"阅后即焚文件删除失败: {e}")
    
    def decrypt_chat_display(self):
        """将当前聊天窗口所有密文内容批量解密并输出（带[解密]备注）"""
        lines = self.chat_display.get(1.0, tk.END).splitlines()
        for line in lines:
            # 尝试提取消息内容部分
            try:
                # 假设消息格式为：[时间] 用户: 消息
                parts = line.split(': ', 1)
                if len(parts) == 2:
                    prefix, enc = parts
                    dec = xor_decrypt(enc.strip())
                    self.chat_display.insert(tk.END, f"[解密]{prefix}: {dec}\n")
            except Exception:
                continue

    def enter_public_chat(self):
        """切换到公共聊天室窗口"""
        self.chat_title_label.config(text="公共聊天室")
        self.chat_display.delete(1.0, tk.END)
        # 显示公共聊天室历史
        if 'public' in self.group_chat_history:
            for msg in self.group_chat_history['public']:
                display_msg = f"[{msg['timestamp']}] {msg['sender']}: {msg['message']}"
                self.chat_display.insert(tk.END, display_msg + "\n")
        self.chat_display.see(tk.END)
    
    def run(self):
        """运行客户端"""
        self.root.mainloop()

if __name__ == '__main__':
    client = ChatClient()
    client.run() 