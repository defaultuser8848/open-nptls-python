# open-npTLS-python

一个基于 Python 的 npTLS（NotePaper Transport Layer Security）实现。

## 项目简介
本项目实现了 npTLS 协议，旨在为 Notepad 等轻量级应用提供安全的传输层加密。项目采用 Python 编写，支持基本的密钥交换、加密通信等功能，适合学习、研究和二次开发。

## 主要特性
- 支持 ECDH 密钥交换
- 使用 PyCryptodome 进行加密操作
- 自定义二进制消息打包
- 基于 httpx 的网络通信

## 目录结构
```
src/
├── nptls.py            # npTLS 协议核心实现
├── __init__.py         # 标记为python包
└── utils/              # 工具模块
    ├── ecdh.py         # ECDH 密钥交换实现
    ├── pack.py         # 消息打包和解包
    └── notepaper.py    # Notepaper传输层接口
examples/
├── client_example.py   # 客户端实现
└── server_example.py   # 最简回响服务
```

## 安装依赖
我们采用pip管理项目依赖。

```bash
pip install git+https://github.com/defaultuser8848/open-nptls-python.git
```

```py
import nptls
```

## 快速开始
以测试客户端为例：

```bash
cd examples
python client_example.py
```

## 贡献指南
欢迎提交 issue 和 PR！如有建议或 bug，欢迎反馈。

## 许可证
GPL License
