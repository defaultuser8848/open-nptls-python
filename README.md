# open-npTLS-python

一个基于 Python 的 npTLS（Notepad Transport Layer Security）实现。

## 项目简介
本项目实现了 npTLS 协议，旨在为 Notepad 等轻量级应用提供安全的传输层加密。项目采用 Python 编写，支持基本的密钥交换、加密通信等功能，适合学习、研究和二次开发。

## 主要特性
- 支持 ECDH 密钥交换
- 使用 PyCryptodome 进行加密操作
- 支持 SOCKS 代理（socksio）
- 高效的消息打包（msgpack）
- 基于 httpx 的网络通信

## 目录结构
```
open-npTLS-python/
├── config.py           # 配置文件
├── main2.py            # 主程序入口
├── nptls.py            # npTLS 协议核心实现
├── requirements.txt    # 依赖包列表
├── test_client2.py     # 测试客户端
└── utils/              # 工具模块
    ├── ecdh.py         # ECDH 密钥交换实现
    └── notepaper.py    # 其他工具函数
```

## 安装依赖
建议使用 Python 3.8 及以上版本。

```bash
pip install -r requirements.txt
```

## 快速开始
以测试客户端为例：

```bash
python test_client2.py
```

## 贡献指南
欢迎提交 issue 和 PR！如有建议或 bug，欢迎反馈。

## 许可证
MIT License
