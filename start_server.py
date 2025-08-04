#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Private Talking Chat Server
启动服务器脚本
"""

import sys
import os

# 添加当前目录到Python路径
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from server import ChatServer

def main():
    """主函数"""
    print("=" * 50)
    print("Private Talking Chat Server")
    print("=" * 50)
    print("正在启动服务器...")
    
    try:
        server = ChatServer()
        print(f"服务器已启动，监听端口: {server.port}")
        print("按 Ctrl+C 停止服务器")
        server.start()
    except KeyboardInterrupt:
        print("\n服务器已停止")
    except Exception as e:
        print(f"服务器启动失败: {e}")

if __name__ == '__main__':
    main() 