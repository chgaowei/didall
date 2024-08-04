# 基于DID的跨平台身份认证和端到端加密通信技术

**作者**: 常高伟  
**邮箱**: chgaowei@gmail.com  
**官网**: [pi-unlimited.com](http://pi-unlimited.com)  

## 摘要

本项目是基于去中心化标识符（DID）和端到端加密通信技术的开源SDK实现，技术细节详见[技术白皮书：一种基于DID的跨平台身份认证和端到端加密通信技术](https://egp0uc2jnx.feishu.cn/wiki/JyaIwTwngiWi9qkJjjycI4XcnXe?from=from_copylink)。
借助didall开源项目，任意一个智能体或者服务端都可以连接到did server，注册自己的did，接收其他用户连接，也可以连接其他用户，并且相互之间进行端到端的加密通信。

## 特点

- **跨平台身份认证**：通过DID实现不同平台间的身份互操作性。
- **端到端加密通信**：使用ECDHE进行短期密钥协商，保证通信的安全性。
- **高效和安全**：简化身份验证过程，确保数据的保密性和完整性。

### 安装

最新版本已删除pypi，直接安装即可：

```bash
pip install didall
```

### 运行

在安装完didall库后，可以运行examples目录下的sample代码，可以生成alice和bob的did文件，并且将alice的did文件保存到did server，然后bob可以连接alice的did，进行端到端的加密通信。

1. 生成两个did文档alice.json和bob.json，保存到指定文件中，并注册到did server
```bash
python sample_did.py alice.json
python sample_did.py bob.json
```

2. 启动alice的demo
```bash
python sample_alice.py alice.json
```

3. 启动bob的demo
```bash
python sample_bob.py bob.json
```

可以通过日志看到，alice和bob成功连接，并且进行端到端的加密通信。

## 贡献

欢迎对本项目进行贡献。请在提交Pull Request之前阅读贡献指南。

## 许可证
    
本项目基于MIT许可证开源。详细信息请参阅LICENSE文件。


## 打包上传（先更改setup.py中版本号）

```bash
python setup.py sdist bdist_wheel 
twine upload dist/*        
```