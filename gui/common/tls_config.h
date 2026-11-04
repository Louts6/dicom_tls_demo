// ============================================================
//  TLS 配置参数（SCP 和 SCU 共用）
// ============================================================
#ifndef TLS_CONFIG_H
#define TLS_CONFIG_H

#include "dcmtk/config/osconfig.h"
#include "dcmtk/dcmnet/assoc.h"
#include "dcmtk/ofstd/ofstring.h"
#include <QString>

// SCP 端配置
struct SCPConfig {
    Uint16   listenPort;       // 监听端口
    OFString ourAETitle;       // 本地 AE Title
    OFString outputDir;        // 接收文件保存目录
    OFString certFile;         // 服务端证书
    OFString keyFile;          // 服务端私钥
    OFString caFile;           // CA 根证书
    OFString clientCertFile;   // 客户端证书（C-MOVE 子关联用）
    OFString clientKeyFile;    // 客户端私钥（C-MOVE 子关联用）
    Uint32   maxPDULength;     // 最大 PDU 长度
    bool     verbose;          // 详细输出
    Uint16   moveDestPort;     // C-MOVE 子关联目标端口

    SCPConfig()
        : listenPort(11112)
        , ourAETitle("TLS_SCP")
        , outputDir("./received")
        , maxPDULength(ASC_DEFAULTMAXPDU)
        , verbose(true)
        , moveDestPort(11113) {}
};

// SCU 端配置
struct SCUConfig {
    OFString peerHost;         // SCP 主机地址
    Uint16   peerPort;         // SCP 端口
    OFString ourAETitle;       // 本地 AE Title (SCU)
    OFString peerAETitle;      // 对端 AE Title (SCP)
    OFString certFile;         // 客户端证书
    OFString keyFile;          // 客户端私钥
    OFString caFile;           // CA 根证书
    Uint32   maxPDULength;     // 最大 PDU 长度
    QStringList dcmFiles;      // 要发送的 DICOM 文件列表（支持多文件）

    SCUConfig()
        : peerHost("127.0.0.1")
        , peerPort(11112)
        , ourAETitle("TLS_SCU")
        , peerAETitle("TLS_SCP")
        , maxPDULength(ASC_DEFAULTMAXPDU) {}
};

#endif // TLS_CONFIG_H
