# Private Talking Chat - 快速启动指南

## 🚀 快速开始

### 1. 启动服务器
```bash
# 方法1：使用Python脚本
python start_server.py

# 方法2：Windows用户双击
start_server.bat

# 方法3：直接运行服务器
python server.py
```

### 2. 启动客户端
```bash
# 方法1：使用Python脚本
python start_client.py

# 方法2：Windows用户双击
start_client.bat

# 方法3：直接运行客户端
python client.py
```

### 3. 连接设置
- **服务器IP**: 127.0.0.1 (本地) 或服务器实际IP
- **端口**: 5000
- **用户名**: 任意唯一用户名

## 📋 功能测试

运行测试脚本验证功能：
```bash
python test_chat.py
```

## 🎯 基本使用流程

1. **启动服务器** → 运行 `start_server.py`
2. **启动客户端** → 运行 `start_client.py`
3. **选择语言** → 中文或英文
4. **输入信息** → 用户名和服务器IP
5. **连接服务器** → 点击"连接"按钮
6. **开始聊天** → 选择用户或群组开始聊天

## 🔧 故障排除

### 连接失败
- 确保服务器已启动
- 检查IP地址是否正确
- 确认端口5000未被占用

### 用户名已存在
- 选择其他用户名
- 等待其他用户断开连接

### 界面问题
- 确保Python 3.6+已安装
- 检查tkinter是否可用

## 📞 支持

如有问题，请查看 `README.md` 获取详细说明。 