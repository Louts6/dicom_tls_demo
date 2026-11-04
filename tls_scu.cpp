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
#include "dcmtk/dcmdata/dcrleerg.h"
#include "dcmtk/dcmdata/dcrledrg.h"
#include "dcmtk/dcmjpeg/djencode.h"
#include "dcmtk/dcmjpeg/djdecode.h"
#include "dcmtk/dcmjpls/djencode.h"
#include "dcmtk/dcmjpls/djdecode.h"
#include "dcmtk/ofstd/ofconapp.h"
#include "dcmtk/dcmdata/dcuid.h"

#include <openssl/ssl.h>
#include <iostream>
#include <string>
#include <vector>

// ============================================================
//  C-FIND 查询结果结构体
// ============================================================
struct FindResultRecord {
    std::string patientID;
    std::string patientName;
    std::string studyInstanceUID;
    std::string studyDate;
    std::string modalitiesInStudy;
    std::string studyDescription;
    std::string seriesInstanceUID;
    std::string seriesNumber;
    std::string modality;
    std::string seriesDescription;
    std::string sopInstanceUID;
    std::string sopClassUID;
    std::string instanceNumber;
};

// C-FIND User 回调：收集每个 Pending 响应的标识符
static void findUserCallback(
    void* callbackData,
    T_DIMSE_C_FindRQ* /*request*/,
    int /*responseCount*/,
    T_DIMSE_C_FindRSP* response,
    DcmDataset* responseIdentifiers)
{
    if (response->DimseStatus != STATUS_Pending || responseIdentifiers == NULL)
        return;

    std::vector<FindResultRecord>* results =
        static_cast<std::vector<FindResultRecord>*>(callbackData);

    FindResultRecord rec;
    OFString val;
    if (responseIdentifiers->findAndGetOFString(DCM_PatientID, val).good())
        rec.patientID = val.c_str();
    if (responseIdentifiers->findAndGetOFString(DCM_PatientName, val).good())
        rec.patientName = val.c_str();
    if (responseIdentifiers->findAndGetOFString(DCM_StudyInstanceUID, val).good())
        rec.studyInstanceUID = val.c_str();
    if (responseIdentifiers->findAndGetOFString(DCM_StudyDate, val).good())
        rec.studyDate = val.c_str();
    if (responseIdentifiers->findAndGetOFString(DCM_ModalitiesInStudy, val).good())
        rec.modalitiesInStudy = val.c_str();
    if (responseIdentifiers->findAndGetOFString(DCM_StudyDescription, val).good())
        rec.studyDescription = val.c_str();
    if (responseIdentifiers->findAndGetOFString(DCM_SeriesInstanceUID, val).good())
        rec.seriesInstanceUID = val.c_str();
    if (responseIdentifiers->findAndGetOFString(DCM_SeriesNumber, val).good())
        rec.seriesNumber = val.c_str();
    if (responseIdentifiers->findAndGetOFString(DCM_Modality, val).good())
        rec.modality = val.c_str();
    if (responseIdentifiers->findAndGetOFString(DCM_SeriesDescription, val).good())
        rec.seriesDescription = val.c_str();
    if (responseIdentifiers->findAndGetOFString(DCM_SOPInstanceUID, val).good())
        rec.sopInstanceUID = val.c_str();
    if (responseIdentifiers->findAndGetOFString(DCM_SOPClassUID, val).good())
        rec.sopClassUID = val.c_str();
    if (responseIdentifiers->findAndGetOFString(DCM_InstanceNumber, val).good())
        rec.instanceNumber = val.c_str();

    results->push_back(rec);
}

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
//  设置 TLS 传输层（服务端模式，用于 C-MOVE 子关联监听器）
// ============================================================
OFCondition setupTLSServerTransportLayer(T_ASC_Network* net,
                                         const TLSConfig& config)
{
    std::cout << "[TLS] 初始化子关联 TLS 传输层（服务端模式）..." << std::endl;

    DcmTLSTransportLayer* tlsLayer = new DcmTLSTransportLayer(
        NET_ACCEPTOR, NULL, OFTrue);

    if (tlsLayer == NULL) {
        std::cerr << "[ERROR] 创建服务端 TLS 传输层失败" << std::endl;
        return EC_IllegalCall;
    }

    if (!config.keyFile.empty()) {
        if (tlsLayer->setPrivateKeyFile(config.keyFile.c_str(), DCF_Filetype_PEM) != TCS_ok) {
            delete tlsLayer;
            return EC_IllegalCall;
        }
    }
    if (!config.certFile.empty()) {
        if (tlsLayer->setCertificateFile(config.certFile.c_str(), DCF_Filetype_PEM) != TCS_ok) {
            delete tlsLayer;
            return EC_IllegalCall;
        }
    }
    if (!config.caFile.empty()) {
        tlsLayer->addTrustedCertificateFile(config.caFile.c_str(), DCF_Filetype_PEM);
    }

    tlsLayer->setCertificateVerification(DCV_requireCertificate);
    tlsLayer->setTLSProfile(TSP_Profile_BCP195);
    tlsLayer->activateCipherSuites();

    SSL_CTX* sslCtx = tlsLayer->getNativeHandle();
    if (sslCtx != NULL) {
        SSL_CTX_set_options(sslCtx,
            SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
            SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1_3);
    }

    OFCondition cond = ASC_setTransportLayer(net, tlsLayer, 1);
    if (cond.bad()) {
        delete tlsLayer;
        return cond;
    }
    std::cout << "[TLS] 子关联服务端 TLS 初始化成功" << std::endl;
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
    //    按优先级提议多个传输语法，对端选择第一个支持的
    const char* transferSyntaxes[] = {
        DcmXfer(EXS_LittleEndianExplicit).getXferID(),   // 1.2.840.10008.1.2.1 首选
        DcmXfer(EXS_LittleEndianImplicit).getXferID(),   // 1.2.840.10008.1.2   兼容
        DcmXfer(EXS_BigEndianExplicit).getXferID(),      // 1.2.840.10008.1.2.2 大端
        DcmXfer(EXS_RLELossless).getXferID(),            // 1.2.840.10008.1.2.5 RLE 无损
        DcmXfer(EXS_JPEGProcess14).getXferID(),          // 1.2.840.10008.1.2.4.57 JPEG 无损
        DcmXfer(EXS_JPEGLSLossless).getXferID(),         // 1.2.840.10008.1.2.4.80 JPEG-LS 无损
        DcmXfer(EXS_JPEGProcess1).getXferID(),           // 1.2.840.10008.1.2.4.50 JPEG 有损 8bit
        DcmXfer(EXS_JPEGProcess2_4).getXferID(),         // 1.2.840.10008.1.2.4.51 JPEG 有损 12bit
        DcmXfer(EXS_JPEGLSLossy).getXferID(),            // 1.2.840.10008.1.2.4.81 JPEG-LS 有损
        NULL
    };
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
//  执行 C-FIND 查询（Study Root）
// ============================================================
// queryLevel: "PATIENT" / "STUDY" / "SERIES" / "IMAGE"
// patientID, studyDate, modality 为空字符串表示不限制
int performCFind(const TLSConfig& config,
                 const std::string& queryLevel,
                 const std::string& patientID,
                 const std::string& studyDate,
                 const std::string& modality)
{
    OFCondition cond;
    T_ASC_Network* net = NULL;
    T_ASC_Association* assoc = NULL;

    // 1. 初始化网络
    cond = ASC_initializeNetwork(NET_REQUESTOR, 0, 1000, &net);
    if (cond.bad()) {
        std::cerr << "[ERROR] 网络初始化失败: " << cond.text() << std::endl;
        return 1;
    }

    // 2. 设置 TLS
    cond = setupTLSTransportLayer(net, config);
    if (cond.bad()) {
        ASC_dropNetwork(&net);
        return 1;
    }

    // 3. 提议 FIND Study Root Presentation Context
    T_ASC_Parameters* params;
    cond = ASC_createAssociationParameters(&params, config.maxPDULength);
    if (cond.bad()) {
        ASC_dropNetwork(&net);
        return 1;
    }

    ASC_setTransportLayerType(params, OFTrue);
    ASC_setAPTitles(params, config.ourAETitle.c_str(), config.peerAETitle.c_str(), NULL);

    OFString peerAddress = config.peerHost;
    peerAddress += ":";
    peerAddress += OFString(std::to_string(config.peerPort).c_str());
    ASC_setPresentationAddresses(params, NULL, peerAddress.c_str());

    // FIND 只需要 Implicit VR Little Endian 传输语法
    const char* findTransferSyntaxes[] = {
        DcmXfer(EXS_LittleEndianImplicit).getXferID(),
        NULL
    };

    cond = ASC_addPresentationContext(
        params, 1,
        UID_FINDStudyRootQueryRetrieveInformationModel,
        findTransferSyntaxes, ASC_SC_ROLE_DEFAULT);
    if (cond.bad()) {
        ASC_destroyAssociationParameters(&params);
        ASC_dropNetwork(&net);
        std::cerr << "[ERROR] 添加 Presentation Context 失败: " << cond.text() << std::endl;
        return 1;
    }

    std::cout << "[C-FIND] 正在建立 Association..." << std::endl;
    cond = ASC_requestAssociation(net, params, &assoc);
    if (cond.bad()) {
        std::cerr << "[ERROR] Association 建立失败: " << cond.text() << std::endl;
        ASC_destroyAssociationParameters(&params);
        ASC_dropNetwork(&net);
        return 1;
    }

    T_ASC_PresentationContextID presID =
        ASC_findAcceptedPresentationContextID(assoc, UID_FINDStudyRootQueryRetrieveInformationModel);
    if (presID == 0) {
        std::cerr << "[ERROR] FIND Study Root Presentation Context 未被接受" << std::endl;
        ASC_releaseAssociation(assoc);
        ASC_destroyAssociation(&assoc);
        ASC_dropNetwork(&net);
        return 1;
    }

    // 4. 构建查询标识符数据集
    DcmDataset* reqIds = new DcmDataset();
    reqIds->putAndInsertString(DCM_QueryRetrieveLevel, queryLevel.c_str());
    if (!patientID.empty())
        reqIds->putAndInsertString(DCM_PatientID, patientID.c_str());
    if (!studyDate.empty())
        reqIds->putAndInsertString(DCM_StudyDate, studyDate.c_str());
    if (!modality.empty())
        reqIds->putAndInsertString(DCM_Modality, modality.c_str());

    // 5. 填充 C-FIND 请求
    T_DIMSE_C_FindRQ rq;
    memset(&rq, 0, sizeof(rq));
    rq.MessageID = assoc->nextMsgID++;
    strncpy(rq.AffectedSOPClassUID, UID_FINDStudyRootQueryRetrieveInformationModel, DIC_UI_LEN);
    rq.Priority = DIMSE_PRIORITY_MEDIUM;
    rq.DataSetType = DIMSE_DATASET_PRESENT;

    // 6. 执行 C-FIND
    std::vector<FindResultRecord> results;
    int responseCount = 0;
    T_DIMSE_C_FindRSP rsp;
    DcmDataset* statusDetail = NULL;

    std::cout << "[C-FIND] 发送查询 (Level=" << queryLevel
              << ", PatientID=" << (patientID.empty() ? "*" : patientID)
              << ", StudyDate=" << (studyDate.empty() ? "*" : studyDate)
              << ", Modality=" << (modality.empty() ? "*" : modality) << ")" << std::endl;

    cond = DIMSE_findUser(
        assoc, presID, &rq, reqIds,
        responseCount,
        findUserCallback, &results,
        DIMSE_BLOCKING, 0,
        &rsp, &statusDetail);

    delete reqIds;

    if (cond.bad()) {
        std::cerr << "[ERROR] C-FIND 失败: " << cond.text() << std::endl;
        if (statusDetail) delete statusDetail;
        ASC_releaseAssociation(assoc);
        ASC_destroyAssociation(&assoc);
        ASC_dropNetwork(&net);
        return 1;
    }

    std::cout << "[C-FIND] 查询完成，响应状态: 0x"
              << std::hex << (int)rsp.DimseStatus << std::dec
              << "，匹配记录数: " << results.size() << std::endl;

    // 7. 打印结果
    for (size_t i = 0; i < results.size(); i++) {
        const FindResultRecord& r = results[i];
        std::cout << std::endl;
        std::cout << "  --- 记录 " << (i + 1) << " ---" << std::endl;
        std::cout << "  PatientID:        " << r.patientID << std::endl;
        std::cout << "  PatientName:      " << r.patientName << std::endl;
        if (!r.studyInstanceUID.empty())
            std::cout << "  StudyInstanceUID: " << r.studyInstanceUID << std::endl;
        if (!r.studyDate.empty())
            std::cout << "  StudyDate:        " << r.studyDate << std::endl;
        if (!r.modalitiesInStudy.empty())
            std::cout << "  Modalities:       " << r.modalitiesInStudy << std::endl;
        if (!r.studyDescription.empty())
            std::cout << "  StudyDesc:        " << r.studyDescription << std::endl;
        if (!r.seriesInstanceUID.empty())
            std::cout << "  SeriesInstanceUID:" << r.seriesInstanceUID << std::endl;
        if (!r.seriesNumber.empty())
            std::cout << "  SeriesNumber:     " << r.seriesNumber << std::endl;
        if (!r.modality.empty())
            std::cout << "  Modality:         " << r.modality << std::endl;
        if (!r.sopInstanceUID.empty())
            std::cout << "  SOPInstanceUID:   " << r.sopInstanceUID << std::endl;
    }

    if (statusDetail) delete statusDetail;

    // 8. 释放 Association
    ASC_releaseAssociation(assoc);
    ASC_destroyAssociation(&assoc);
    ASC_dropNetwork(&net);
    return 0;
}

// ============================================================
//  C-MOVE User：子关联接收回调数据 + 子关联 C-STORE 处理
// ============================================================
struct SubOpCallbackData {
    OFString outputDir;       // 接收文件保存目录
    int receivedCount;        // 已接收文件数
};

// 子关联回调：SCP 回连后，SCU 作为存储 SCP 接收 C-STORE
static void subOpProviderCallback(void* subOpCallbackData,
                                  T_ASC_Network* net,
                                  T_ASC_Association** subOpAssoc)
{
    SubOpCallbackData* data = static_cast<SubOpCallbackData*>(subOpCallbackData);

    // 1. 接收子关联
    OFCondition cond = ASC_receiveAssociation(net, subOpAssoc, ASC_DEFAULTMAXPDU,
                                              NULL, NULL, OFTrue);
    if (cond.bad()) {
        std::cerr << "[C-MOVE] 子关联接收失败: " << cond.text() << std::endl;
        return;
    }

    // 2. 接受所有 Presentation Context（用 Implicit/Explicit LE）
    static const char* acceptedTS[] = {
        UID_LittleEndianExplicitTransferSyntax,
        UID_LittleEndianImplicitTransferSyntax,
        NULL
    };
    int pcCount = ASC_countPresentationContexts((*subOpAssoc)->params);
    for (int i = 0; i < pcCount; i++) {
        T_ASC_PresentationContext pc;
        if (ASC_getPresentationContext((*subOpAssoc)->params, i, &pc).bad()) continue;
        const char* acceptTS = NULL;
        for (int j = 0; j < pc.transferSyntaxCount; j++) {
            for (int k = 0; acceptedTS[k] != NULL; k++) {
                if (strcmp(pc.proposedTransferSyntaxes[j], acceptedTS[k]) == 0) {
                    acceptTS = pc.proposedTransferSyntaxes[j];
                    break;
                }
            }
            if (acceptTS) break;
        }
        if (acceptTS) {
            ASC_acceptPresentationContext((*subOpAssoc)->params, pc.presentationContextID,
                                          acceptTS, ASC_SC_ROLE_DEFAULT);
        }
    }

    cond = ASC_acknowledgeAssociation(*subOpAssoc);
    if (cond.bad()) {
        std::cerr << "[C-MOVE] 子关联确认失败: " << cond.text() << std::endl;
        ASC_destroyAssociation(subOpAssoc);
        return;
    }
    std::cout << "[C-MOVE] 子关联已建立，开始接收 C-STORE..." << std::endl;

    // 3. 循环接收 C-STORE
    while (true) {
        DcmDataset* statusDetail = NULL;
        T_DIMSE_Message msg;
        T_ASC_PresentationContextID presID;
        memset(&msg, 0, sizeof(msg));

        cond = DIMSE_receiveCommand(*subOpAssoc, DIMSE_BLOCKING, 0,
                                    &presID, &msg, &statusDetail);
        if (cond.bad()) {
            if (cond == DUL_PEERREQUESTEDRELEASE) {
                ASC_acknowledgeRelease(*subOpAssoc);
            }
            if (statusDetail) delete statusDetail;
            break;
        }

        if (msg.CommandField == DIMSE_C_STORE_RQ) {
            T_DIMSE_C_StoreRQ* rq = &msg.msg.CStoreRQ;
            DcmDataset* dataset = NULL;

            // 使用默认回调保存文件
            struct StoreCb {
                OFString outputDir;
                OFString savedPath;
            } cbdata;
            cbdata.outputDir = data->outputDir;

            cond = DIMSE_storeProvider(*subOpAssoc, presID, rq, NULL, 0,
                                       &dataset,
                                       [](void* cbd, T_DIMSE_StoreProgress* prog,
                                          T_DIMSE_C_StoreRQ*, char*, DcmDataset** ds,
                                          T_DIMSE_C_StoreRSP* rsp, DcmDataset**) {
                if (prog->state != DIMSE_StoreEnd) return;
                StoreCb* c = static_cast<StoreCb*>(cbd);
                if (!ds || !*ds) { rsp->DimseStatus = STATUS_STORE_Refused_OutOfResources; return; }
                OFString uid;
                (*ds)->findAndGetOFString(DCM_SOPInstanceUID, uid);
                std::string path = std::string(c->outputDir.c_str()) + "/" + uid.c_str() + ".dcm";
                DcmFileFormat ff(*ds);
                if (ff.saveFile(path.c_str(), (*ds)->getCurrentXfer()).good()) {
                    c->savedPath = path.c_str();
                    rsp->DimseStatus = STATUS_Success;
                } else {
                    rsp->DimseStatus = STATUS_STORE_Refused_OutOfResources;
                }
            }, &cbdata, DIMSE_BLOCKING, 0);

            if (cond.good() && !cbdata.savedPath.empty()) {
                data->receivedCount++;
                std::cout << "[C-MOVE] 已接收: " << cbdata.savedPath << std::endl;
            }
            if (dataset) delete dataset;
        }

        if (statusDetail) delete statusDetail;
    }

    ASC_destroyAssociation(subOpAssoc);
    *subOpAssoc = NULL;
}

// C-MOVE User 回调：跟踪响应计数
static void moveUserCallback(void* callbackData,
                             T_DIMSE_C_MoveRQ* /*request*/,
                             int responseCount,
                             T_DIMSE_C_MoveRSP* response)
{
    (void)callbackData;
    std::cout << "[C-MOVE] 响应 #" << responseCount
              << ": completed=" << response->NumberOfCompletedSubOperations
              << ", failed=" << response->NumberOfFailedSubOperations
              << ", warning=" << response->NumberOfWarningSubOperations
              << ", remaining=" << response->NumberOfRemainingSubOperations
              << std::endl;
}

// ============================================================
//  执行 C-MOVE 检索（Study Root）
// ============================================================
int performCMove(const TLSConfig& config,
                 const std::string& moveDestination,
                 Uint16 listenPort,
                 const std::string& outputDir,
                 const std::string& patientID,
                 const std::string& studyInstanceUID)
{
    OFCondition cond;
    T_ASC_Network* net = NULL;
    T_ASC_Association* assoc = NULL;

    // 1. 初始化主网络（用于发送 C-MOVE）
    cond = ASC_initializeNetwork(NET_REQUESTOR, 0, 1000, &net);
    if (cond.bad()) {
        std::cerr << "[ERROR] 网络初始化失败: " << cond.text() << std::endl;
        return 1;
    }

    // 2. 设置 TLS
    cond = setupTLSTransportLayer(net, config);
    if (cond.bad()) {
        ASC_dropNetwork(&net);
        return 1;
    }

    // 3. 提议 MOVE Study Root Presentation Context
    T_ASC_Parameters* params;
    cond = ASC_createAssociationParameters(&params, config.maxPDULength);
    if (cond.bad()) { ASC_dropNetwork(&net); return 1; }

    ASC_setTransportLayerType(params, OFTrue);
    ASC_setAPTitles(params, config.ourAETitle.c_str(), config.peerAETitle.c_str(), NULL);

    OFString peerAddress = config.peerHost;
    peerAddress += ":";
    peerAddress += OFString(std::to_string(config.peerPort).c_str());
    ASC_setPresentationAddresses(params, NULL, peerAddress.c_str());

    const char* moveTransferSyntaxes[] = {
        DcmXfer(EXS_LittleEndianImplicit).getXferID(),
        NULL
    };
    cond = ASC_addPresentationContext(params, 1,
        UID_MOVEStudyRootQueryRetrieveInformationModel,
        moveTransferSyntaxes, ASC_SC_ROLE_DEFAULT);
    if (cond.bad()) { ASC_destroyAssociationParameters(&params); ASC_dropNetwork(&net); return 1; }

    std::cout << "[C-MOVE] 建立主关联..." << std::endl;
    cond = ASC_requestAssociation(net, params, &assoc);
    if (cond.bad()) {
        std::cerr << "[ERROR] Association 建立失败: " << cond.text() << std::endl;
        ASC_destroyAssociationParameters(&params); ASC_dropNetwork(&net); return 1;
    }

    T_ASC_PresentationContextID presID =
        ASC_findAcceptedPresentationContextID(assoc, UID_MOVEStudyRootQueryRetrieveInformationModel);
    if (presID == 0) {
        std::cerr << "[ERROR] MOVE Study Root PC 未被接受" << std::endl;
        ASC_releaseAssociation(assoc); ASC_destroyAssociation(&assoc); ASC_dropNetwork(&net);
        return 1;
    }

    // 4. 构建查询标识符
    DcmDataset* reqIds = new DcmDataset();
    reqIds->putAndInsertString(DCM_QueryRetrieveLevel, "STUDY");
    if (!patientID.empty())
        reqIds->putAndInsertString(DCM_PatientID, patientID.c_str());
    if (!studyInstanceUID.empty())
        reqIds->putAndInsertString(DCM_StudyInstanceUID, studyInstanceUID.c_str());

    // 5. 填充 C-MOVE 请求
    T_DIMSE_C_MoveRQ rq;
    memset(&rq, 0, sizeof(rq));
    rq.MessageID = assoc->nextMsgID++;
    strncpy(rq.AffectedSOPClassUID, UID_MOVEStudyRootQueryRetrieveInformationModel, DIC_UI_LEN);
    strncpy(rq.MoveDestination, moveDestination.c_str(), DIC_AE_LEN);
    rq.Priority = DIMSE_PRIORITY_MEDIUM;
    rq.DataSetType = DIMSE_DATASET_PRESENT;

    // 6. 启动子关联监听网络（SCU 作为存储 SCP 接收 C-STORE）
    T_ASC_Network* subNet = NULL;
    cond = ASC_initializeNetwork(NET_ACCEPTOR, listenPort, 1000, &subNet);
    if (cond.bad()) {
        std::cerr << "[ERROR] 子关联监听网络初始化失败: " << cond.text() << std::endl;
        delete reqIds;
        ASC_releaseAssociation(assoc); ASC_destroyAssociation(&assoc); ASC_dropNetwork(&net);
        return 1;
    }
    // 子关联监听器使用服务端 TLS（SCU 作为存储 SCP 接收 C-STORE）
    cond = setupTLSServerTransportLayer(subNet, config);
    if (cond.bad()) {
        ASC_dropNetwork(&subNet);
        delete reqIds;
        ASC_releaseAssociation(assoc); ASC_destroyAssociation(&assoc); ASC_dropNetwork(&net);
        return 1;
    }

    SubOpCallbackData subData;
    subData.outputDir = outputDir.c_str();
    subData.receivedCount = 0;

    std::cout << "[C-MOVE] 子关联监听端口: " << listenPort
              << ", MoveDestination=" << moveDestination << std::endl;

    // 7. 执行 C-MOVE
    T_DIMSE_C_MoveRSP rsp;
    DcmDataset* statusDetail = NULL;
    DcmDataset* rspIds = NULL;

    cond = DIMSE_moveUser(
        assoc, presID, &rq, reqIds,
        moveUserCallback, NULL,
        DIMSE_BLOCKING, 0,
        subNet, subOpProviderCallback, &subData,
        &rsp, &statusDetail, &rspIds);

    delete reqIds;
    if (rspIds) delete rspIds;
    if (statusDetail) delete statusDetail;

    if (cond.bad()) {
        std::cerr << "[ERROR] C-MOVE 失败: " << cond.text() << std::endl;
    } else {
        std::cout << "[C-MOVE] 检索完成: completed=" << rsp.NumberOfCompletedSubOperations
                  << ", failed=" << rsp.NumberOfFailedSubOperations
                  << ", warning=" << rsp.NumberOfWarningSubOperations << std::endl;
        std::cout << "[C-MOVE] 实际接收文件数: " << subData.receivedCount << std::endl;
    }

    ASC_dropNetwork(&subNet);
    ASC_releaseAssociation(assoc);
    ASC_destroyAssociation(&assoc);
    ASC_dropNetwork(&net);
    return (cond.good() && rsp.NumberOfFailedSubOperations == 0) ? 0 : 1;
}

// ============================================================
//  主函数
// ============================================================
int main(int argc, char* argv[])
{
    // 显式加载 OpenSSL 配置（如 OPENSSL_CONF 环境变量指定的配置文件）
    // 用于强制 TLS 版本等设置
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);

    // 注册 DICOM 压缩传输语法编解码器（RLE / JPEG / JPEG-LS）
    DcmRLEEncoderRegistration::registerCodecs();
    DcmRLEDecoderRegistration::registerCodecs();
    DJEncoderRegistration::registerCodecs();
    DJDecoderRegistration::registerCodecs();
    DJLSEncoderRegistration::registerCodecs();
    DJLSDecoderRegistration::registerCodecs();

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

    // --- 参数解析 ---
    // 模式 1: C-FIND 查询
    //   tls_scu --find [host] [port] [ourAE] [peerAE] [level] [patientID] [studyDate] [modality]
    // 模式 2: C-MOVE 检索
    //   tls_scu --move [host] [port] [ourAE] [peerAE] [moveDestAE] [listenPort] [outputDir] [patientID] [studyUID]
    // 模式 3: C-STORE 发送（默认）
    //   tls_scu [host] [port] [ourAE] [peerAE] [file1] [file2] ...
    bool findMode = false;
    bool moveMode = false;
    std::string findLevel = "STUDY";
    std::string findPatientID;
    std::string findStudyDate;
    std::string findModality;

    // C-MOVE 参数
    std::string moveDestAE = "TLS_SCU";
    Uint16 moveListenPort = 11113;
    std::string moveOutputDir = "./retrieved";
    std::string movePatientID;
    std::string moveStudyUID;

    if (argc >= 2 && std::string(argv[1]) == "--find") {
        findMode = true;
        if (argc >= 3) config.peerHost    = argv[2];
        if (argc >= 4) config.peerPort    = atoi(argv[3]);
        if (argc >= 5) config.ourAETitle  = argv[4];
        if (argc >= 6) config.peerAETitle = argv[5];
        if (argc >= 7) findLevel          = argv[6];
        if (argc >= 8) findPatientID      = argv[7];
        if (argc >= 9) findStudyDate      = argv[8];
        if (argc >= 10) findModality      = argv[9];
    } else if (argc >= 2 && std::string(argv[1]) == "--move") {
        moveMode = true;
        if (argc >= 3) config.peerHost    = argv[2];
        if (argc >= 4) config.peerPort    = atoi(argv[3]);
        if (argc >= 5) config.ourAETitle  = argv[4];
        if (argc >= 6) config.peerAETitle = argv[5];
        if (argc >= 7) moveDestAE         = argv[6];
        if (argc >= 8) moveListenPort     = atoi(argv[7]);
        if (argc >= 9) moveOutputDir      = argv[8];
        if (argc >= 10) movePatientID     = argv[9];
        if (argc >= 11) moveStudyUID      = argv[10];
    } else {
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
    }

    // --- C-FIND 模式：执行查询后直接退出 ---
    if (findMode) {
        std::cout << "================================================" << std::endl;
        std::cout << "  DICOM TLS C-FIND SCU (加密查询端)" << std::endl;
        std::cout << "================================================" << std::endl;
        int rc = performCFind(config, findLevel, findPatientID, findStudyDate, findModality);
        return rc;
    }

    // --- C-MOVE 模式：执行检索后直接退出 ---
    if (moveMode) {
        // 确保输出目录存在
        std::string mkdirCmd = "mkdir -p " + moveOutputDir;
        system(mkdirCmd.c_str());

        std::cout << "================================================" << std::endl;
        std::cout << "  DICOM TLS C-MOVE SCU (加密检索端)" << std::endl;
        std::cout << "================================================" << std::endl;
        int rc = performCMove(config, moveDestAE, moveListenPort,
                              moveOutputDir, movePatientID, moveStudyUID);
        return rc;
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
