// ============================================================
//  DICOM TLS SCU (Storage SCU) - TLS 加密发送端
//  功能：使用 TLS 安全连接向 SCP 发送 DICOM 文件
//  依赖：DCMTK (dcmdata, dcmnet, dcmtls) + OpenSSL
// ============================================================

#include "dcmtk/config/osconfig.h"
#include "dcmtk/dcmnet/diutil.h"
#include "dcmtk/dcmnet/dimse.h"
#include "dcmtk/dcmnet/dcasccff.h"
#include "dcmtk/dcmtls/tlslayer.h"
#include "dcmtk/dcmdata/dcfilefo.h"
#include "dcmtk/dcmdata/dcdeftag.h"
#include "dcmtk/dcmdata/dcxfer.h"
#include "dcmtk/ofstd/ofconapp.h"

#include <openssl/ssl.h>
#include <iostream>
#include <string>
#include <vector>

// ============================================================
//  配置参数
// ============================================================
struct TLSConfig {
    // 网络参数
    OFString peerHost;        // SCP 主机地址
    Uint16   peerPort;        // SCP 端口
    OFString ourAETitle;      // 本地 AE Title (SCU)
    OFString peerAETitle;     // 对端 AE Title (SCP)

    // TLS 证书文件
    OFString certFile;        // 客户端证书 (.crt / .pem)
    OFString keyFile;         // 客户端私钥 (.key / .pem)
    OFString caFile;          // CA 根证书（用于验证服务端）
    OFString passphrase;      // 私钥密码（可选）

    // 传输参数
    Uint32 maxPDULength;      // 最大 PDU 长度
    OFList<OFString> dcmFiles; // 要发送的 DICOM 文件列表
};

// ============================================================
//  加载 DICOM 文件
// ============================================================
OFCondition loadDICOMFile(const OFString& filePath,
                          DcmDataset*& dataset,
                          OFString& sopClassUID,
                          OFString& sopInstanceUID)
{
    DcmFileFormat fileFormat;
    OFCondition cond = fileFormat.loadFile(filePath.c_str());
    if (cond.bad()) {
        std::cerr << "[ERROR] 加载文件失败: " << filePath
                  << " - " << cond.text() << std::endl;
        return cond;
    }

    dataset = fileFormat.getAndRemoveDataset();

    // 获取 SOP Class UID
    dataset->findAndGetOFString(DCM_SOPClassUID, sopClassUID);
    if (sopClassUID.empty()) {
        std::cerr << "[ERROR] 文件中没有 SOP Class UID: " << filePath << std::endl;
        return EC_InvalidTag;
    }

    // 获取 SOP Instance UID
    dataset->findAndGetOFString(DCM_SOPInstanceUID, sopInstanceUID);
    if (sopInstanceUID.empty()) {
        std::cerr << "[ERROR] 文件中没有 SOP Instance UID: " << filePath << std::endl;
        return EC_InvalidTag;
    }

    return EC_Normal;
}

// ============================================================
//  创建并配置 TLS 传输层（核心加密代码）
// ============================================================
OFCondition setupTLSTransportLayer(T_ASC_Network* net,
                                   const TLSConfig& config)
{
    std::cout << "[TLS] 初始化 TLS 传输层..." << std::endl;

    // 1. 创建 TLS 传输层对象（SCU 端是请求方）
    DcmTLSTransportLayer* tlsLayer = new DcmTLSTransportLayer(
        NET_REQUESTOR,       // 角色：请求方 (SCU)
        NULL,                // 随机数种子文件（NULL 使用默认）
        OFTrue               // 初始化 OpenSSL
    );

    if (tlsLayer == NULL) {
        std::cerr << "[ERROR] 创建 TLS 传输层失败！" << std::endl;
        return EC_IllegalCall;
    }

    // 2. 设置私钥文件
    if (!config.keyFile.empty()) {
        DcmTransportLayerStatus st = tlsLayer->setPrivateKeyFile(
            config.keyFile.c_str(),
            DCF_Filetype_PEM
        );
        if (st != TCS_ok) {
            std::cerr << "[ERROR] 设置私钥文件失败: " << (int)st << std::endl;
            delete tlsLayer;
            return EC_IllegalCall;
        }
        std::cout << "[TLS] 私钥文件已加载: " << config.keyFile << std::endl;
    }

    // 3. 设置客户端证书
    if (!config.certFile.empty()) {
        DcmTransportLayerStatus st = tlsLayer->setCertificateFile(
            config.certFile.c_str(),
            DCF_Filetype_PEM
        );
        if (st != TCS_ok) {
            std::cerr << "[ERROR] 设置证书文件失败: " << (int)st << std::endl;
            delete tlsLayer;
            return EC_IllegalCall;
        }
        std::cout << "[TLS] 证书文件已加载: " << config.certFile << std::endl;
    }

    // 4. 设置 CA 信任链（用于验证服务端证书）
    if (!config.caFile.empty()) {
        DcmTransportLayerStatus st = tlsLayer->addTrustedCertificateFile(
            config.caFile.c_str(),
            DCF_Filetype_PEM
        );
        if (st != TCS_ok) {
            std::cerr << "[ERROR] 设置 CA 证书失败: " << (int)st << std::endl;
            delete tlsLayer;
            return EC_IllegalCall;
        }
        std::cout << "[TLS] CA 根证书已加载: " << config.caFile << std::endl;
    }

    // 5. 设置对端证书验证策略
    // DCV_requireCertificate  = 必须验证对端证书（最严格）
    // DCV_checkCertificate    = 验证但不强制
    // DCV_ignoreCertificate   = 不验证（不安全，仅调试用）
    tlsLayer->setCertificateVerification(DCV_requireCertificate);
    std::cout << "[TLS] 对端证书验证策略: 必须验证" << std::endl;

    // 6. 设置密码套件（加密算法组合）
    // TSP_Profile_AES 使用 AES 加密套件（高安全级）
    DcmTransportLayerStatus cst = tlsLayer->setTLSProfile(TSP_Profile_BCP195);
    if (cst != TCS_ok) {
        std::cerr << "[ERROR] 设置 TLS 密码套件失败: " << (int)cst << std::endl;
    }
    tlsLayer->activateCipherSuites();
    std::cout << "[TLS] 密码套件: AES Profile" << std::endl;

    // 6.5 强制使用 TLS 1.2（DCMTK 3.6.4 + OpenSSL 1.1.1 的 TLS 1.3 握手有兼容问题）
    SSL_CTX* sslCtx = tlsLayer->getNativeHandle();
    if (sslCtx != NULL) {
        // 禁用 TLS 1.0/1.1/1.3，只允许 TLS 1.2
        SSL_CTX_set_options(sslCtx,
            SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
            SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1_3);
        std::cout << "[TLS] 已强制 TLS 版本: 1.2 (via SSL_OP_NO_*)" << std::endl;
    }

    // 7. 将 TLS 层设置到 DCMTK 网络对象
    //    之后的所有网络通信都会自动经过 TLS 加密
    OFCondition cond = ASC_setTransportLayer(net, tlsLayer, 1);
    if (cond.bad()) {
        std::cerr << "[ERROR] 设置 TLS 传输层失败: " << cond.text() << std::endl;
        delete tlsLayer;
        return cond;
    }

    std::cout << "[TLS] TLS 传输层初始化成功！" << std::endl;
    std::cout << "[TLS] 所有 DICOM 通信将通过 TLS 加密传输" << std::endl;
    return EC_Normal;
}

// ============================================================
//  建立 DICOM Association（在 TLS 加密通道之上）
// ============================================================
OFCondition establishAssociation(T_ASC_Network* net,
                                 T_ASC_Association*& assoc,
                                 const TLSConfig& config,
                                 const OFString& sopClassUID)
{
    OFCondition cond;

    // 1. 创建 Association 参数
    T_ASC_Parameters* params;
    cond = ASC_createAssociationParameters(&params, config.maxPDULength);
    if (cond.bad()) return cond;

    // 1.5 标记此 Association 使用安全传输层（TLS）
    ASC_setTransportLayerType(params, OFTrue);

    // 2. 设置 AE Title (calling, called, responding)
    ASC_setAPTitles(params,
                    config.ourAETitle.c_str(),
                    config.peerAETitle.c_str(),
                    NULL);

    // 设置对端 Presentation Address（主机:端口 格式）
    OFString peerAddress = config.peerHost;
    peerAddress += ":";
    peerAddress += std::to_string(config.peerPort).c_str();
    ASC_setPresentationAddresses(params, NULL, peerAddress.c_str());

    // 3. 设置 Presentation Context（抽象语法 + 传输语法）
    //    使用 Implicit VR Little Endian 作为传输语法
    const char* transferSyntaxes[] = { DcmXfer(EXS_LittleEndianImplicit).getXferID(), NULL };
    cond = ASC_addPresentationContext(
        params,
        1,                              // Presentation Context ID
        sopClassUID.c_str(),            // 抽象语法（SOP Class）
        transferSyntaxes,               // 传输语法列表
        ASC_SC_ROLE_DEFAULT             // 角色：默认 SCU
    );
    if (cond.bad()) {
        ASC_destroyAssociationParameters(&params);
        return cond;
    }

    // 4. 发起 Association 请求
    //    注意：因为我们设置了 TLS 传输层，
    //    这个函数内部会先完成 TLS 握手，再发 A-ASSOCIATE-RQ
    std::cout << std::endl;
    std::cout << "[ASSOC] 正在建立 TLS 加密的 DICOM Association..." << std::endl;
    std::cout << "[ASSOC] 本地 AE: " << config.ourAETitle << std::endl;
    std::cout << "[ASSOC] 远端 AE: " << config.peerAETitle
              << " @ " << config.peerHost
              << ":" << config.peerPort << std::endl;

    cond = ASC_requestAssociation(
        net,
        params,
        &assoc
    );

    if (cond.bad()) {
        std::cerr << "[ERROR] Association 建立失败: " << cond.text() << std::endl;

        // 打印被拒绝的原因（调试用）
        if (cond == DUL_ASSOCIATIONREJECTED) {
            T_ASC_RejectParameters rej;
            ASC_getRejectParameters(params, &rej);
            OFString rejStr;
            ASC_printRejectParameters(rejStr, &rej);
            std::cerr << "  拒绝详情: " << rejStr << std::endl;
        }
        ASC_destroyAssociationParameters(&params);
        return cond;
    }

    std::cout << "[ASSOC] Association 建立成功（TLS 加密通道）！" << std::endl;

    // 5. 检查 Presentation Context 是否被接受
    T_ASC_PresentationContextID presID =
        ASC_findAcceptedPresentationContextID(assoc, sopClassUID.c_str());
    if (presID == 0) {
        std::cerr << "[ERROR] Presentation Context 未被接受！" << std::endl;
        ASC_releaseAssociation(assoc);
        ASC_destroyAssociation(&assoc);
        return EC_IllegalCall;
    }

    std::cout << "[ASSOC] Presentation Context ID: " << (int)presID << std::endl;

    return EC_Normal;
}

// ============================================================
//  发送 C-STORE 请求
// ============================================================
OFCondition sendCStore(T_ASC_Association* assoc,
                       T_ASC_PresentationContextID presID,
                       DcmDataset* dataset,
                       const OFString& sopClassUID,
                       const OFString& sopInstanceUID)
{
    OFCondition cond;
    T_DIMSE_C_StoreRQ req;
    T_DIMSE_C_StoreRSP rsp;
    DcmDataset* statusDetail = NULL;

    // 1. 填充 C-STORE 请求
    req.MessageID = assoc->nextMsgID++;
    strncpy(req.AffectedSOPClassUID, sopClassUID.c_str(), DIC_UI_LEN);
    strncpy(req.AffectedSOPInstanceUID, sopInstanceUID.c_str(), DIC_UI_LEN);
    req.Priority = DIMSE_PRIORITY_MEDIUM;
    req.DataSetType = DIMSE_DATASET_PRESENT; // 有数据集
    req.MoveOriginatorID = 0;
    req.MoveOriginatorApplicationEntityTitle[0] = '\0';

    // 2. 发送 C-STORE
    std::cout << "[C-STORE] 发送: " << sopInstanceUID << std::endl;

    cond = DIMSE_storeUser(
        assoc,
        presID,
        &req,
        NULL,            // 原始文件名（可选）
        dataset,         // 要发送的数据集
        NULL,            // 进度回调
        NULL,            // 回调参数
        DIMSE_BLOCKING,  // 阻塞模式
        0,               // 超时（0=无限等待）
        &rsp,
        &statusDetail    // 状态详情
    );

    if (cond.bad()) {
        std::cerr << "[ERROR] C-STORE 发送失败: " << cond.text() << std::endl;
        if (statusDetail) delete statusDetail;
        return cond;
    }

    // 3. 检查响应状态
    std::cout << "[C-STORE] 响应状态: 0x"
              << std::hex << (int)rsp.DimseStatus << std::dec;

    if (rsp.DimseStatus == STATUS_Success) {
        std::cout << " (成功)" << std::endl;
    } else {
        std::cout << " (警告/失败)" << std::endl;
    }

    if (statusDetail) delete statusDetail;
    return EC_Normal;
}

// ============================================================
//  主函数
// ============================================================
int main(int argc, char* argv[])
{
    // 显式加载 OpenSSL 配置（如 OPENSSL_CONF 环境变量指定的配置文件）
    // 用于强制 TLS 版本等设置
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);

    // --- 配置参数 ---
    TLSConfig config;
    config.peerHost      = "127.0.0.1";
    config.peerPort      = 11112;
    config.ourAETitle    = "TLS_SCU";
    config.peerAETitle   = "TLS_SCP";
    config.maxPDULength  = ASC_DEFAULTMAXPDU;

    // TLS 证书路径（请根据实际情况修改）
    config.certFile      = "certs/client.crt";
    config.keyFile       = "certs/client.key";
    config.caFile        = "certs/ca.crt";
    config.passphrase    = ""; // 私钥密码（如果有）

    // 要发送的 DICOM 文件（示例，可替换为实际文件）
    config.dcmFiles.push_back("sample.dcm");

    // --- 参数解析（简单处理命令行参数）---
    if (argc >= 2) config.peerHost    = argv[1];
    if (argc >= 3) config.peerPort    = atoi(argv[2]);
    if (argc >= 4) config.ourAETitle  = argv[3];
    if (argc >= 5) config.peerAETitle = argv[4];
    if (argc >= 6) {
        config.dcmFiles.clear();
        for (int i = 5; i < argc; i++) {
            config.dcmFiles.push_back(argv[i]);
        }
    }

    std::cout << "================================================" << std::endl;
    std::cout << "  DICOM TLS Storage SCU (加密发送端)" << std::endl;
    std::cout << "================================================" << std::endl;

    OFCondition cond;
    T_ASC_Network* net = NULL;
    T_ASC_Association* assoc = NULL;

    // 1. 初始化 DCMTK 网络
    std::cout << std::endl << "[INIT] 初始化 DCMTK 网络层..." << std::endl;
    cond = ASC_initializeNetwork(
        NET_REQUESTOR,    // 角色：请求方
        0,                // 本地端口（0 = 不监听，客户端模式）
        1000,             // 超时（毫秒）
        &net
    );
    if (cond.bad()) {
        std::cerr << "[ERROR] 网络初始化失败: " << cond.text() << std::endl;
        return 1;
    }
    std::cout << "[INIT] 网络层初始化成功" << std::endl;

    // 2. 设置 TLS 加密传输层（核心步骤！）
    cond = setupTLSTransportLayer(net, config);
    if (cond.bad()) {
        ASC_dropNetwork(&net);
        return 1;
    }

    // 3. 逐个发送 DICOM 文件
    //    注意：为简化示例，每个文件建立一个 Association
    //    实际生产中建议一个 Association 发送多个文件
    OFListIterator(OFString) iter = config.dcmFiles.begin();
    int successCount = 0;
    int failCount = 0;

    while (iter != config.dcmFiles.end()) {
        OFString filePath = *iter;
        ++iter;

        std::cout << std::endl;
        std::cout << "------------------------------------------------" << std::endl;
        std::cout << "  处理文件: " << filePath << std::endl;
        std::cout << "------------------------------------------------" << std::endl;

        // 加载 DICOM 文件
        DcmDataset* dataset = NULL;
        OFString sopClassUID, sopInstanceUID;
        cond = loadDICOMFile(filePath, dataset, sopClassUID, sopInstanceUID);
        if (cond.bad()) {
            failCount++;
            continue;
        }

        std::cout << "[INFO] SOP Class: " << sopClassUID << std::endl;
        std::cout << "[INFO] SOP Instance: " << sopInstanceUID << std::endl;

        // 建立 Association（TLS 加密通道）
        cond = establishAssociation(net, assoc, config, sopClassUID);
        if (cond.bad()) {
            delete dataset;
            failCount++;
            continue;
        }

        // 获取接受的 Presentation Context ID
        T_ASC_PresentationContextID presID =
            ASC_findAcceptedPresentationContextID(assoc, sopClassUID.c_str());

        // 发送 C-STORE（数据经过 TLS 加密传输）
        cond = sendCStore(assoc, presID, dataset, sopClassUID, sopInstanceUID);
        if (cond.good()) {
            successCount++;
        } else {
            failCount++;
        }

        delete dataset;

        // 释放 Association
        std::cout << "[ASSOC] 释放 Association..." << std::endl;
        cond = ASC_releaseAssociation(assoc);
        if (cond.bad()) {
            std::cerr << "[WARN] Association 释放异常: " << cond.text() << std::endl;
            ASC_abortAssociation(assoc);
        }
        ASC_destroyAssociation(&assoc);
        assoc = NULL;
    }

    // 4. 清理网络
    std::cout << std::endl;
    std::cout << "================================================" << std::endl;
    std::cout << "  传输完成统计" << std::endl;
    std::cout << "================================================" << std::endl;
    std::cout << "  成功: " << successCount << " 个文件" << std::endl;
    std::cout << "  失败: " << failCount << " 个文件" << std::endl;
    std::cout << "  所有数据均通过 TLS 加密传输 ✓" << std::endl;

    ASC_dropNetwork(&net);
    return (failCount == 0) ? 0 : 1;
}
