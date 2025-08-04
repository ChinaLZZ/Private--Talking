#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Private Talking Chat 测试脚本
用于测试聊天软件的基本功能
"""

import socket
import json
import threading
import time
import sys
import os

# 添加当前目录到Python路径
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def test_server_connection():
    """测试服务器连接"""
    print("测试服务器连接...")
    
    try:
        # 创建测试客户端
        test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        test_socket.settimeout(5)
        
        # 尝试连接服务器
        test_socket.connect(('127.0.0.1', 5000))
        
        # 发送测试连接信息
        connection_info = {
            'username': 'test_user',
            'language': 'cn'
        }
        test_socket.send(json.dumps(connection_info).encode('utf-8'))
        
        # 接收服务器响应
        response = test_socket.recv(1024).decode('utf-8')
        response_data = json.loads(response)
        
        if response_data['type'] == 'connection_success':
            print("✅ 服务器连接测试成功")
            test_socket.close()
            return True
        else:
            print("❌ 服务器连接测试失败")
            test_socket.close()
            return False
            
    except Exception as e:
        print(f"❌ 服务器连接测试失败: {e}")
        return False

def test_message_sending():
    """测试消息发送"""
    print("测试消息发送...")
    
    try:
        # 创建两个测试客户端
        client1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # 连接服务器
        client1.connect(('127.0.0.1', 5000))
        client2.connect(('127.0.0.1', 5000))
        
        # 发送连接信息
        client1_info = {'username': 'test_user1', 'language': 'cn'}
        client2_info = {'username': 'test_user2', 'language': 'cn'}
        
        client1.send(json.dumps(client1_info).encode('utf-8'))
        client2.send(json.dumps(client2_info).encode('utf-8'))
        
        # 接收连接确认
        client1.recv(1024)
        client2.recv(1024)
        
        # 发送测试消息
        test_message = {
            'type': 'private_message',
            'receiver': 'test_user2',
            'message': 'Hello, this is a test message!',
            'is_private': False
        }
        
        client1.send(json.dumps(test_message).encode('utf-8'))
        
        # 等待消息处理
        time.sleep(1)
        
        # 检查是否有消息接收
        client2.settimeout(2)
        try:
            received_data = client2.recv(4096).decode('utf-8')
            if received_data:
                print("✅ 消息发送测试成功")
                client1.close()
                client2.close()
                return True
        except socket.timeout:
            print("❌ 消息发送测试失败：未收到消息")
            client1.close()
            client2.close()
            return False
            
    except Exception as e:
        print(f"❌ 消息发送测试失败: {e}")
        return False

def test_file_transfer():
    """测试文件传输"""
    print("测试文件传输...")
    
    try:
        # 创建测试文件
        test_file_content = "This is a test file content for file transfer testing."
        with open('test_file.txt', 'w', encoding='utf-8') as f:
            f.write(test_file_content)
        
        # 创建两个测试客户端
        client1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # 连接服务器
        client1.connect(('127.0.0.1', 5000))
        client2.connect(('127.0.0.1', 5000))
        
        # 发送连接信息
        client1_info = {'username': 'file_user1', 'language': 'cn'}
        client2_info = {'username': 'file_user2', 'language': 'cn'}
        
        client1.send(json.dumps(client1_info).encode('utf-8'))
        client2.send(json.dumps(client2_info).encode('utf-8'))
        
        # 接收连接确认
        client1.recv(1024)
        client2.recv(1024)
        
        # 读取测试文件
        with open('test_file.txt', 'rb') as f:
            file_data = f.read()
        
        # 发送文件
        file_message = {
            'type': 'file_transfer',
            'receiver': 'file_user2',
            'filename': 'test_file.txt',
            'file_data': file_data.decode('utf-8'),
            'filesize': len(file_data)
        }
        
        client1.send(json.dumps(file_message).encode('utf-8'))
        
        # 等待文件处理
        time.sleep(1)
        
        # 检查是否有文件接收
        client2.settimeout(2)
        try:
            received_data = client2.recv(4096).decode('utf-8')
            if received_data:
                print("✅ 文件传输测试成功")
                client1.close()
                client2.close()
                
                # 清理测试文件
                if os.path.exists('test_file.txt'):
                    os.remove('test_file.txt')
                return True
        except socket.timeout:
            print("❌ 文件传输测试失败：未收到文件")
            client1.close()
            client2.close()
            
            # 清理测试文件
            if os.path.exists('test_file.txt'):
                os.remove('test_file.txt')
            return False
            
    except Exception as e:
        print(f"❌ 文件传输测试失败: {e}")
        
        # 清理测试文件
        if os.path.exists('test_file.txt'):
            os.remove('test_file.txt')
        return False

def test_group_creation():
    """测试群组创建"""
    print("测试群组创建...")
    
    try:
        # 创建测试客户端
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect(('127.0.0.1', 5000))
        
        # 发送连接信息
        client_info = {'username': 'group_test_user', 'language': 'cn'}
        client.send(json.dumps(client_info).encode('utf-8'))
        
        # 接收连接确认
        client.recv(1024)
        
        # 发送创建群组消息
        group_message = {
            'type': 'create_group',
            'group_name': 'test_group'
        }
        
        client.send(json.dumps(group_message).encode('utf-8'))
        
        # 等待群组创建
        time.sleep(1)
        
        print("✅ 群组创建测试成功")
        client.close()
        return True
        
    except Exception as e:
        print(f"❌ 群组创建测试失败: {e}")
        return False

def run_all_tests():
    """运行所有测试"""
    print("=" * 50)
    print("Private Talking Chat 功能测试")
    print("=" * 50)
    
    # 检查服务器是否运行
    print("请确保服务器已启动（运行 python start_server.py）")
    input("按回车键开始测试...")
    
    tests = [
        ("服务器连接", test_server_connection),
        ("消息发送", test_message_sending),
        ("文件传输", test_file_transfer),
        ("群组创建", test_group_creation)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n--- {test_name} ---")
        if test_func():
            passed += 1
        time.sleep(1)
    
    print("\n" + "=" * 50)
    print(f"测试完成: {passed}/{total} 通过")
    
    if passed == total:
        print("🎉 所有测试通过！聊天软件功能正常。")
    else:
        print("⚠️  部分测试失败，请检查服务器状态和网络连接。")
    
    print("=" * 50)

if __name__ == '__main__':
    run_all_tests() 