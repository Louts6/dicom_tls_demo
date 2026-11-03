// ============================================================
//  DICOM TLS SCP (Storage SCP) - TLS 加密接收端
//  功能：使用 TLS 安全连接接收 DICOM 文件并保存到本地
//  依赖：DCMTK (dcmdata, dcmnet, dcmtls) + OpenSSL
// ============================================================

#include "dcmtk/config/osconfig.h"
#include "dcmtk/dcmnet/diutil.h"
#include "dcmtk/dcmnet/dimse.h"
#include "dcmtk/dcmnet/dcasccff.h"
#include "dcmtk/dcmtls/tlslayer.h"
#include "dcmtk/dcmdata/dcfilefo.h"
#include "dcmtk/dcmdata/dcdeftag.h"
#include "dcmtk/ofstd/ofstring.h"

#include <openssl/ssl.h>
#include <iostream>
#include <string>
#include <cstdlib>

// ============================================================
//  配置参数
// ============================================================
struct TLSConfig {
    // 网络参数
    Uint16   listenPort;      // 监听端口
    OFString ourAETitle;      // 本地 AE Title (SCP)
    OFString outputDir;       // 接收文件保存目录

    // TLS 证书文件
    OFString certFile;        // 服务端证书
    OFString keyFile;         // 服务端私钥
    OFString caFile;          // CA 根证书（验证客户端）
    OFString passphrase;      // 私钥密码（可选）

    // 传输参数
    Uint32 maxPDULength;      // 最大 PDU 长度
    bool   verbose;           // 详细输出
};

// ============================================================
//  设置 TLS 传输层（SCP 服务端）
// ============================================================
OFCondition setupTLSTransportLayer(T_ASC_Network* net,
                                   const TLSConfig& config)
{
    std::cout << "[TLS] 初始化 TLS 传输层（服务端模式）..." << std::endl;

    // 1. 创建 TLS 传输层对象（SCP 端是接受方）
    DcmTLSTransportLayer* tlsLayer = new DcmTLSTransportLayer(
        NET_ACCEPTOR,        // 角色：接受方 (SCP)
        NULL,                // 随机数种子文件
        OFTrue               // 初始化 OpenSSL
    );

    if (tlsLayer == NULL) {
        std::cerr << "[ERROR] 创建 TLS 传输层失败！" << std::endl;
        return EC_IllegalCall;
    }

    // 2. 设置私钥
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

    // 3. 设置服务端证书
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
        std::cout << "[TLS] 服务端证书已加载: " << config.certFile << std::endl;
    }

    // 4. 设置 CA 信任链（验证客户端证书）
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

    // 5. 设置对端（客户端）证书验证策略
    // 双向认证：要求客户端也必须提供证书
    tlsLayer->setCertificateVerification(DCV_requireCertificate);
    std::cout << "[TLS] 客户端证书验证策略: 必须验证（双向认证）" << std::endl;

    // 6. 设置密码套件
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

    // 7. 设置到网络层
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
//  检查 Association 请求（白名单 + Presentation Context 协商）
// ============================================================
OFCondition checkAssociationRequest(T_ASC_Association* assoc,
                                    const TLSConfig& config)
{
    OFCondition cond;
    char callingAET[DIC_AE_LEN + 1] = {0};
    char calledAET[DIC_AE_LEN + 1] = {0};

    // 1. 获取对端 AE Title
    ASC_getAPTitles(assoc->params,
                    callingAET, sizeof(callingAET),
                    calledAET, sizeof(calledAET),
                    NULL, 0);

    std::cout << std::endl;
    std::cout << "[ASSOC] 收到 Association 请求（TLS 加密通道）" << std::endl;
    std::cout << "[ASSOC] 主叫 AE: " << callingAET << std::endl;
    std::cout << "[ASSOC] 被叫 AE: " << calledAET << std::endl;

    // 2. 验证被叫 AE Title（白名单检查）
    if (config.ourAETitle != calledAET) {
        std::cerr << "[WARN] 被叫 AE Title 不匹配: "
                  << calledAET << " != " << config.ourAETitle << std::endl;
        // 实际项目中可以在这里拒绝连接
        // 这里为了演示继续处理
    }

    // 3. 检查并接受 Presentation Context
    //    遍历所有请求的 PC，接受我们支持的
    int pcCount = ASC_countPresentationContexts(assoc->params);

    for (int i = 0; i < pcCount; i++) {
        T_ASC_PresentationContext pc;
        cond = ASC_getPresentationContext(assoc->params, i, &pc);
        if (cond.bad()) continue;

        T_ASC_PresentationContextID presID = pc.presentationContextID;
        const char* abstractSyntax = pc.abstractSyntax;
        // 使用第一个提议的传输语法
        const char* transferSyntax = (pc.transferSyntaxCount > 0)
                                         ? pc.proposedTransferSyntaxes[0]
                                         : NULL;

        if (config.verbose) {
            std::cout << "[PC] PC ID=" << (int)presID
                      << " 抽象语法: " << abstractSyntax
                      << " 传输语法: " << (transferSyntax ? transferSyntax : "(null)")
                      << std::endl;
        }

        if (transferSyntax == NULL) continue;

        // 接受这个 Presentation Context
        cond = ASC_acceptPresentationContext(
            assoc->params,
            presID,
            transferSyntax,           // 接受的传输语法
            ASC_SC_ROLE_DEFAULT       // 角色：默认 SCP
        );

        if (cond.good() && config.verbose) {
            std::cout << "[PC] 已接受 PC ID=" << (int)presID << std::endl;
        }
    }

    return EC_Normal;
}

// ============================================================
//  保存接收到的 DICOM 文件
// ============================================================
OFCondition saveDICOMFile(DcmDataset* dataset,
                          const OFString& outputDir,
                          OFString& savedFilePath)
{
    OFString sopInstanceUID;
    dataset->findAndGetOFString(DCM_SOPInstanceUID, sopInstanceUID);

    if (sopInstanceUID.empty()) {
        std::cerr << "[ERROR] 数据集中没有 SOP Instance UID" << std::endl;
        return EC_InvalidTag;
    }

    // 构造保存路径：outputDir/SOPInstanceUID.dcm
    char fileName[1024];
    snprintf(fileName, sizeof(fileName), "%s/%s.dcm",
             outputDir.c_str(), sopInstanceUID.c_str());
    savedFilePath = fileName;

    // 保存为 DICOM 文件
    DcmFileFormat fileFormat(dataset);
    OFCondition cond = fileFormat.saveFile(
        fileName,
        EXS_LittleEndianImplicit
    );

    if (cond.bad()) {
        std::cerr << "[ERROR] 保存文件失败: " << fileName
                  << " - " << cond.text() << std::endl;
        return cond;
    }

    return EC_Normal;
}

// ============================================================
//  处理 C-STORE 请求
// ============================================================
OFCondition handleCStore(T_ASC_Association* assoc,
                         const TLSConfig& config)
{
    OFCondition cond;
    T_DIMSE_Message msg;
    T_ASC_PresentationContextID presID;

    // 循环接收 DIMSE 消息
    while (true) {
        // 1. 接收 DIMSE 命令
        DcmDataset* statusDetail = NULL;
        cond = DIMSE_receiveCommand(
            assoc,
            DIMSE_BLOCKING,     // 阻塞模式
            0,                   // 超时（0=无限等待）
            &presID,
            &msg,
            &statusDetail
        );

        if (cond.bad()) {
            if (cond == DUL_PEERREQUESTEDRELEASE) {
                std::cout << std::endl << "[ASSOC] 对端请求释放连接" << std::endl;
                // DIMSE_receiveCommand 内部已处理 A-RELEASE-RP，无需再次确认
            } else if (cond == DUL_PEERABORTEDASSOCIATION) {
                std::cout << std::endl << "[ASSOC] 对端中止连接" << std::endl;
            } else {
                std::cerr << "[ERROR] 接收命令失败: " << cond.text() << std::endl;
            }
            if (statusDetail) delete statusDetail;
            break;
        }

        // 2. 根据消息类型处理
        switch (msg.CommandField) {
            case DIMSE_C_STORE_RQ: {
                // --- 处理 C-STORE 请求 ---
                T_DIMSE_C_StoreRQ* rq = &msg.msg.CStoreRQ;

                std::cout << std::endl;
                std::cout << "[C-STORE] 收到存储请求" << std::endl;
                std::cout << "[C-STORE] SOP Class:    " << rq->AffectedSOPClassUID << std::endl;
                std::cout << "[C-STORE] SOP Instance: " << rq->AffectedSOPInstanceUID << std::endl;
                std::cout << "[C-STORE] Priority:     " << rq->Priority << std::endl;
                std::cout << "[C-STORE] 数据通过 TLS 加密接收 ✓" << std::endl;

                // 接收数据集
                DcmDataset* dataset = NULL;

                cond = DIMSE_storeProvider(
                    assoc,
                    presID,
                    rq,
                    NULL,            // imageFileName (不写文件)
                    0,               // writeMetaheader
                    &dataset,        // 接收到的数据集
                    NULL,            // 回调
                    NULL,            // 回调参数
                    DIMSE_BLOCKING,  // 阻塞模式
                    0                // 超时
                );

                if (cond.bad()) {
                    std::cerr << "[ERROR] 接收数据集失败: " << cond.text() << std::endl;
                    // 发送失败响应
                    T_DIMSE_C_StoreRSP rsp;
                    memset(&rsp, 0, sizeof(rsp));
                    rsp.DimseStatus = STATUS_STORE_Refused_OutOfResources;
                    DIMSE_sendStoreResponse(assoc, presID, rq, &rsp, NULL);
                    break;
                }

                if (dataset == NULL) {
                    std::cerr << "[ERROR] 接收到的对象不是 Dataset" << std::endl;
                    T_DIMSE_C_StoreRSP rsp;
                    memset(&rsp, 0, sizeof(rsp));
                    rsp.DimseStatus = STATUS_STORE_Refused_OutOfResources;
                    DIMSE_sendStoreResponse(assoc, presID, rq, &rsp, NULL);
                    break;
                }

                // 保存文件
                OFString savedPath;
                cond = saveDICOMFile(dataset, config.outputDir, savedPath);

                // 发送 C-STORE 响应
                T_DIMSE_C_StoreRSP rsp;
                memset(&rsp, 0, sizeof(rsp));
                rsp.MessageIDBeingRespondedTo = rq->MessageID;
                rsp.DimseStatus = (cond.good())
                                    ? STATUS_Success
                                    : STATUS_STORE_Refused_OutOfResources;
                strcpy(rsp.AffectedSOPClassUID, rq->AffectedSOPClassUID);
                strcpy(rsp.AffectedSOPInstanceUID, rq->AffectedSOPInstanceUID);
                rsp.DataSetType = DIMSE_DATASET_NULL;

                cond = DIMSE_sendStoreResponse(assoc, presID, rq, &rsp, NULL);

                if (cond.good()) {
                    std::cout << "[C-STORE] 已保存: " << savedPath << std::endl;
                    std::cout << "[C-STORE] 响应: 成功 (0x0000)" << std::endl;
                } else {
                    std::cerr << "[ERROR] 发送响应失败: " << cond.text() << std::endl;
                }

                break;
            }

            case DIMSE_C_ECHO_RQ: {
                // --- 处理 C-ECHO 请求（DICOM ping） ---
                std::cout << std::endl << "[C-ECHO] 收到 Echo 请求" << std::endl;

                DIMSE_sendEchoResponse(assoc, presID, &msg.msg.CEchoRQ,
                                       STATUS_Success, NULL);
                std::cout << "[C-ECHO] 已响应成功" << std::endl;
                break;
            }

            default:
                std::cerr << "[WARN] 收到未知命令: 0x"
                          << std::hex << msg.CommandField << std::dec << std::endl;
                break;
        }

        if (statusDetail) delete statusDetail;
    }

    return cond;
}

// ============================================================
//  主函数
// ============================================================
int main(int argc, char* argv[])
{
    // 显式加载 OpenSSL 配置（如 OPENSSL_CONF 环境变量指定的配置文件）
    // 用于强制 TLS 版本等设置
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);

    TLSConfig config;
    config.listenPort    = 11112;
    config.ourAETitle    = "TLS_SCP";
    config.outputDir     = "./received";
    config.maxPDULength  = ASC_DEFAULTMAXPDU;
    config.verbose       = true;

    // TLS 证书路径
    config.certFile      = "certs/server.crt";
    config.keyFile       = "certs/server.key";
    config.caFile        = "certs/ca.crt";
    config.passphrase    = "";

    // 命令行参数
    if (argc >= 2) config.listenPort = atoi(argv[1]);
    if (argc >= 3) config.ourAETitle = argv[2];
    if (argc >= 4) config.outputDir  = argv[3];

    std::cout << "================================================" << std::endl;
    std::cout << "  DICOM TLS Storage SCP (加密接收端)" << std::endl;
    std::cout << "================================================" << std::endl;

    OFCondition cond;
    T_ASC_Network* net = NULL;
    T_ASC_Association* assoc = NULL;

    // 1. 初始化 DCMTK 网络
    std::cout << std::endl << "[INIT] 初始化 DCMTK 网络层..." << std::endl;
    cond = ASC_initializeNetwork(
        NET_ACCEPTOR,       // 角色：接受方（服务端）
        config.listenPort,  // 监听端口
        1000,               // 超时（毫秒）
        &net
    );
    if (cond.bad()) {
        std::cerr << "[ERROR] 网络初始化失败: " << cond.text() << std::endl;
        return 1;
    }
    std::cout << "[INIT] 网络层初始化成功，监听端口: " << config.listenPort << std::endl;

    // 2. 设置 TLS 加密传输层（核心步骤！）
    cond = setupTLSTransportLayer(net, config);
    if (cond.bad()) {
        ASC_dropNetwork(&net);
        return 1;
    }

    // 3. 主循环：等待并接受连接
    std::cout << std::endl;
    std::cout << "[SCP] 等待 TLS 加密的 DICOM 连接..." << std::endl;
    std::cout << "[SCP] AE Title: " << config.ourAETitle << std::endl;
    std::cout << "[SCP] 端口: " << config.listenPort << std::endl;
    std::cout << "[SCP] 按 Ctrl+C 退出" << std::endl;

    while (true) {
        // 等待 TCP 连接 → TLS 握手 → DICOM Association
        // 第 6 个参数 useSecureLayer=OFTrue 表示使用 TLS 安全传输层
        cond = ASC_receiveAssociation(net, &assoc, config.maxPDULength,
                                      NULL, NULL, OFTrue);

        if (cond.bad()) {
            if (cond == DUL_NETWORKCLOSED) {
                std::cout << "[SCP] 网络已关闭" << std::endl;
                break;
            }
            std::cerr << "[ERROR] 接受 Association 失败: "
                      << cond.text() << std::endl;
            continue;
        }

        // 检查并协商 Presentation Context
        checkAssociationRequest(assoc, config);

        // 确认 Association（发送 A-ASSOCIATE-AC）
        cond = ASC_acknowledgeAssociation(assoc);
        if (cond.bad()) {
            std::cerr << "[ERROR] 确认 Association 失败: "
                      << cond.text() << std::endl;
            ASC_destroyAssociation(&assoc);
            continue;
        }

        std::cout << "[ASSOC] Association 已建立（TLS 加密通道）✓" << std::endl;

        // 处理 DIMSE 消息（C-STORE / C-ECHO 等）
        OFCondition handleCond = handleCStore(assoc, config);

        // 释放/销毁 Association
        // 如果对端已请求释放或中止，则无需再调用 ASC_releaseAssociation
        if (handleCond == DUL_PEERREQUESTEDRELEASE) {
            std::cout << "[ASSOC] 对端已请求释放，直接关闭连接" << std::endl;
        } else if (handleCond == DUL_PEERABORTEDASSOCIATION) {
            std::cout << "[ASSOC] 对端已中止连接" << std::endl;
        } else {
            OFCondition relCond = ASC_releaseAssociation(assoc);
            if (relCond.bad()) {
                std::cerr << "[WARN] Association 释放异常: " << relCond.text() << std::endl;
                ASC_abortAssociation(assoc);
            }
        }
        ASC_destroyAssociation(&assoc);
        assoc = NULL;

        std::cout << std::endl;
        std::cout << "[SCP] 连接已关闭，等待下一个连接..." << std::endl;
    }

    // 4. 清理
    ASC_dropNetwork(&net);
    std::cout << "[SCP] 服务已停止" << std::endl;
    return 0;
}
