#!/bin/bash
# ============================================================
#  DICOM TLS Demo - 证书生成脚本 (Linux / macOS)
#  功能：生成 CA 根证书、服务端证书、客户端证书
#  依赖：openssl
# ============================================================

set -e

echo "================================================"
echo "  DICOM TLS 证书生成"
echo "================================================"
echo

# 创建证书目录
mkdir -p certs
cd certs

echo "[1/7] 生成 CA 私钥..."
openssl genrsa -out ca.key 2048
echo "      OK: ca.key"

echo
echo "[2/7] 生成 CA 自签名根证书..."
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt \
    -subj "/C=CN/ST=Beijing/L=Beijing/O=DICOM Demo/OU=CA/CN=DICOM Demo CA"
echo "      OK: ca.crt"

echo
echo "[3/7] 生成服务端私钥..."
openssl genrsa -out server.key 2048
echo "      OK: server.key"

echo
echo "[4/7] 生成服务端证书请求(CSR)..."
openssl req -new -key server.key -out server.csr \
    -subj "/C=CN/ST=Beijing/L=Beijing/O=DICOM Demo/OU=SCP/CN=localhost"
echo "      OK: server.csr"

echo
echo "[5/7] 用 CA 签发服务端证书..."
openssl x509 -req -days 3650 -in server.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out server.crt
echo "      OK: server.crt"

echo
echo "[6/7] 生成客户端私钥..."
openssl genrsa -out client.key 2048
echo "      OK: client.key"

echo
echo "[7/7] 生成客户端证书并用 CA 签发..."
openssl req -new -key client.key -out client.csr \
    -subj "/C=CN/ST=Beijing/L=Beijing/O=DICOM Demo/OU=SCU/CN=TLS_SCU"

openssl x509 -req -days 3650 -in client.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out client.crt
echo "      OK: client.crt"

echo
echo "================================================"
echo "  证书生成完成！"
echo "================================================"
echo
echo "  certs/"
echo "    +-- ca.crt       (CA 根证书 - 双方都需要)"
echo "    +-- ca.key       (CA 私钥 - 仅签发用，生产环境需保护)"
echo "    +-- server.crt   (服务端证书 - SCP 端使用)"
echo "    +-- server.key   (服务端私钥 - SCP 端使用)"
echo "    +-- client.crt   (客户端证书 - SCU 端使用)"
echo "    +-- client.key   (客户端私钥 - SCU 端使用)"
echo

# 清理 CSR 文件
rm -f server.csr client.csr ca.srl

cd ..
