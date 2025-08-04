#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Private Talking Chat Client
启动客户端脚本
"""

import sys
import os

# 添加当前目录到Python路径
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from client import ChatClient

def main():
    """主函数"""
    print("=" * 50)
    print("Private Talking Chat Client")
    print("=" * 50)
    print("正在启动客户端...")
    
    try:
        client = ChatClient()
        client.run()
    except Exception as e:
        print(f"客户端启动失败: {e}")

if __name__ == '__main__':
    main() 