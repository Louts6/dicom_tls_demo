# ============================================================
#  DICOM TLS 传输加密 Demo
#  基于 DCMTK + OpenSSL 的 DICOM TLS 加密传输完整示例
# ============================================================

## 📁 项目结构

```
dicom_tls_demo/
├── tls_scu.cpp           # TLS SCU（加密发送端）
├── tls_scp.cpp           # TLS SCP（加密接收端）
├── CMakeLists.txt        # CMake 构建配置
├── generate_certs.bat    # 证书生成脚本（Windows）
├── generate_certs.sh     # 证书生成脚本（Linux/macOS）
└── README.md             # 本文档
```

## 🔑 核心加密机制

本项目使用 **DCMTK dcmtls 模块** + **OpenSSL** 实现 DICOM 传输加密：

### 加密流程
```
SCU 端                              SCP 端
  │                                  │
  │  ① TCP 连接建立                  │
  ├─────────────────────────────────►│
  │                                  │
  │  ② TLS 握手（身份认证+密钥协商）  │
  │  Client Hello                    │
  ├─────────────────────────────────►│
  │                          Server Hello
  │                          Certificate
  │◄─────────────────────────────────┤
  │  Client Key Exchange             │
  │  Change Cipher Spec              │
  │  Finished                        │
  ├─────────────────────────────────►│
  │                     Change Cipher Spec
  │                            Finished
  │◄─────────────────────────────────┤
  │                                  │
  │  ③ DICOM Association (加密)      │
  │  A-ASSOCIATE-RQ                  │
  ├─────────────────────────────────►│
  │                     A-ASSOCIATE-AC
  │◄─────────────────────────────────┤
  │                                  │
  │  ④ C-STORE (TLS 加密传输)        │
  │  DICOM 数据 → TLS加密 → TCP发送   │
  ├─────────────────────────────────►│
  │                                  │
  │  ⑤ 释放连接                      │
  └─────────────────────────────────►┘
```

### 关键 API
```cpp
// 核心：只需一行代码，所有 DICOM 通信自动加密
DcmTLSTransportLayer* tlsLayer = new DcmTLSTransportLayer(NET_REQUESTOR, NULL);
tlsLayer->setPrivateKeyFile("client.key", SSL_FILETYPE_PEM);
tlsLayer->setCertificateFile("client.crt", SSL_FILETYPE_PEM);
tlsLayer->addTrustedCertFile("ca.crt", SSL_FILETYPE_PEM);
tlsLayer->setPeerVerification(DCV_requireCertificate);
tlsLayer->setCipherSuites(TLS12_AES256_SHA384);
ASC_setTransportLayer(net, tlsLayer);  // ← 关键：设置到网络层
```

设置完成后，`ASC_requestAssociation()`、`DIMSE_storeUser()` 等所有网络 API 的代码**完全不变**，DCMTK 内部自动完成 TLS 握手和加解密。

---

## 🚀 快速开始

### 前置条件

1. **DCMTK**（需包含 dcmtls 模块，编译时开启 OpenSSL 支持）
2. **OpenSSL**（1.1.x 或 3.x）
3. **CMake**（3.10+）
4. **C++ 编译器**（GCC / Clang / MSVC）

### 编译步骤

```bash
# 1. 创建构建目录
mkdir build && cd build

# 2. 配置 CMake（指定 DCMTK 路径）
cmake .. -DDCMTK_DIR=/path/to/dcmtk

# 3. 编译
make -j4
```

Windows 下使用 Visual Studio：
```powershell
mkdir build
cd build
cmake .. -DDCMTK_DIR="C:/dcmtk-3.6.7" -G "Visual Studio 17 2022"
cmake --build . --config Release
```

### 生成证书

Windows:
```cmd
generate_certs.bat
```

Linux/macOS:
```bash
chmod +x generate_certs.sh
./generate_certs.sh
```

生成的证书在 `certs/` 目录下：
- `ca.crt` - CA 根证书（双方都需要）
- `server.crt` / `server.key` - 服务端证书和私钥（SCP 端）
- `client.crt` / `client.key` - 客户端证书和私钥（SCU 端）

### 运行测试

**终端 1 - 启动 SCP（接收端）：**
```bash
# 创建接收目录
mkdir received

# 启动 SCP（默认端口 11112，AE Title = TLS_SCP）
./tls_scp 11112 TLS_SCP ./received
```

**终端 2 - 启动 SCU（发送端）：**
```bash
# 发送一个 DICOM 文件
./tls_scu 127.0.0.1 11112 TLS_SCU TLS_SCP sample.dcm
```

预期输出：
- SCP 端显示收到 C-STORE 请求，文件已保存到 `received/` 目录
- 两端的 TLS 日志显示"证书已加载"、"TLS 传输层初始化成功"

---

## 🔒 安全特性

| 特性 | 说明 |
|------|------|
| **双向认证** | 服务端和客户端互相验证对方证书（DCV_requireCertificate） |
| **强加密** | TLS 1.2 + AES-256 + SHA-384（TLS12_AES256_SHA384） |
| **机密性** | 所有 DICOM 数据（包括 Association、C-STORE、释放）全部加密 |
| **完整性** | MAC 消息认证码，防止数据篡改 |
| **不可否认性** | 证书身份认证，通信双方身份可追溯 |

---

## 🛠️ 代码架构

### tls_scu.cpp（发送端）
- `setupTLSTransportLayer()` - TLS 加密核心配置
- `establishAssociation()` - 在 TLS 通道上建立 DICOM 关联
- `sendCStore()` - 发送 C-STORE 请求（数据自动加密）
- `loadDICOMFile()` - 加载 DICOM 文件

### tls_scp.cpp（接收端）
- `setupTLSTransportLayer()` - TLS 加密核心配置（服务端模式）
- `checkAssociationRequest()` - 验证 AE Title、协商 Presentation Context
- `handleCStore()` - 处理 C-STORE 请求（数据自动解密）
- `saveDICOMFile()` - 保存接收到的 DICOM 文件

---

## ⚠️ 生产环境注意事项

1. **证书管理**
   - 不要使用自签名证书，应使用受信任的 CA 签发
   - 私钥文件必须严格保护（设置 600 权限，存入 HSM 等）
   - 设置合理的证书有效期（建议 1 年以内）

2. **加密强度**
   - 密钥长度：RSA 至少 2048 位，建议 4096 位
   - 优先使用 ECC 证书（性能更好，密钥更短）
   - 密码套件使用 TLS 1.3（如果 DCMTK 版本支持）

3. **验证策略**
   - 生产环境必须使用 `DCV_requireCertificate`
   - 禁止使用 `DCV_ignoreCertificate`（不验证对端证书）
   - 实现证书吊销列表（CRL）或 OCSP 检查

4. **其他安全措施**
   - 启用 TLS Session Resumption（会话复用，提升性能）
   - 配置 AE Title 白名单
   - 限制连接 IP 地址
   - 记录详细的访问日志

---

## 📚 相关参考

- DICOM 标准第 15 章（Security and System Management Profiles）
- DCMTK dcmtls 模块文档
- RFC 5246 (TLS 1.2) / RFC 8446 (TLS 1.3)
- OpenSSL 官方文档
