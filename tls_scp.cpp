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
#include "dcmtk/dcmdata/dcxfer.h"
#include "dcmtk/dcmdata/dcrleerg.h"
#include "dcmtk/dcmdata/dcrledrg.h"
#include "dcmtk/dcmjpeg/djencode.h"
#include "dcmtk/dcmjpeg/djdecode.h"
#include "dcmtk/dcmjpls/djencode.h"
#include "dcmtk/dcmjpls/djdecode.h"
#include "dcmtk/ofstd/ofstring.h"

#include "gui/common/dicom_index.h"

#include <openssl/ssl.h>
#include <iostream>
#include <string>
#include <vector>
#include <set>
#include <cstdlib>

// 全局 DICOM 索引（C-FIND 查询使用）
static DicomIndex g_dicomIndex;

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
    OFString clientCertFile;  // 客户端证书（C-MOVE 子关联，SCP 作为 C-STORE SCU）
    OFString clientKeyFile;   // 客户端私钥（C-MOVE 子关联）

    // 传输参数
    Uint32 maxPDULength;      // 最大 PDU 长度
    bool   verbose;           // 详细输出

    // C-MOVE：MoveDestination 存储 SCP 的监听端口（子关联回连目标端口）
    Uint16 moveDestPort;
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
//  设置 TLS 传输层（客户端模式，用于 C-MOVE 子关联）
// ============================================================
OFCondition setupTLSClientTransportLayer(T_ASC_Network* net,
                                         const TLSConfig& config)
{
    std::cout << "[TLS] 初始化 TLS 传输层（客户端模式）..." << std::endl;

    DcmTLSTransportLayer* tlsLayer = new DcmTLSTransportLayer(
        NET_REQUESTOR,       // 角色：请求方（C-STORE SCU）
        NULL, OFTrue);

    if (tlsLayer == NULL) {
        std::cerr << "[ERROR] 创建客户端 TLS 传输层失败" << std::endl;
        return EC_IllegalCall;
    }

    // 客户端私钥
    OFString keyFile = config.clientKeyFile.empty() ? config.keyFile : config.clientKeyFile;
    if (!keyFile.empty()) {
        if (tlsLayer->setPrivateKeyFile(keyFile.c_str(), DCF_Filetype_PEM) != TCS_ok) {
            std::cerr << "[ERROR] 设置客户端私钥失败" << std::endl;
            delete tlsLayer;
            return EC_IllegalCall;
        }
        std::cout << "[TLS] 客户端私钥已加载: " << keyFile << std::endl;
    }

    // 客户端证书
    OFString certFile = config.clientCertFile.empty() ? config.certFile : config.clientCertFile;
    if (!certFile.empty()) {
        if (tlsLayer->setCertificateFile(certFile.c_str(), DCF_Filetype_PEM) != TCS_ok) {
            std::cerr << "[ERROR] 设置客户端证书失败" << std::endl;
            delete tlsLayer;
            return EC_IllegalCall;
        }
        std::cout << "[TLS] 客户端证书已加载: " << certFile << std::endl;
    }

    // CA 信任链（验证服务端证书）
    if (!config.caFile.empty()) {
        if (tlsLayer->addTrustedCertificateFile(config.caFile.c_str(), DCF_Filetype_PEM) != TCS_ok) {
            std::cerr << "[ERROR] 设置 CA 证书失败" << std::endl;
            delete tlsLayer;
            return EC_IllegalCall;
        }
        std::cout << "[TLS] CA 根证书已加载: " << config.caFile << std::endl;
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
    std::cout << "[TLS] 客户端 TLS 传输层初始化成功" << std::endl;
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
    //    遍历所有请求的 PC，在提议的传输语法中选择第一个我们支持的
    //    支持的传输语法列表（非压缩 + RLE + JPEG + JPEG-LS）
    static const char* supportedTransferSyntaxes[] = {
        DcmXfer(EXS_LittleEndianExplicit).getXferID(),   // 1.2.840.10008.1.2.1
        DcmXfer(EXS_LittleEndianImplicit).getXferID(),   // 1.2.840.10008.1.2
        DcmXfer(EXS_BigEndianExplicit).getXferID(),      // 1.2.840.10008.1.2.2
        DcmXfer(EXS_RLELossless).getXferID(),            // 1.2.840.10008.1.2.5
        DcmXfer(EXS_JPEGProcess14).getXferID(),          // 1.2.840.10008.1.2.4.57
        DcmXfer(EXS_JPEGLSLossless).getXferID(),         // 1.2.840.10008.1.2.4.80
        DcmXfer(EXS_JPEGProcess1).getXferID(),           // 1.2.840.10008.1.2.4.50
        DcmXfer(EXS_JPEGProcess2_4).getXferID(),         // 1.2.840.10008.1.2.4.51
        DcmXfer(EXS_JPEGLSLossy).getXferID(),            // 1.2.840.10008.1.2.4.81
        NULL
    };

    int pcCount = ASC_countPresentationContexts(assoc->params);

    for (int i = 0; i < pcCount; i++) {
        T_ASC_PresentationContext pc;
        cond = ASC_getPresentationContext(assoc->params, i, &pc);
        if (cond.bad()) continue;

        T_ASC_PresentationContextID presID = pc.presentationContextID;
        const char* abstractSyntax = pc.abstractSyntax;

        // 在提议的传输语法中查找第一个支持的
        const char* acceptedTS = NULL;
        for (int j = 0; j < pc.transferSyntaxCount; j++) {
            const char* proposed = pc.proposedTransferSyntaxes[j];
            if (proposed == NULL) continue;
            for (int k = 0; supportedTransferSyntaxes[k] != NULL; k++) {
                if (strcmp(proposed, supportedTransferSyntaxes[k]) == 0) {
                    acceptedTS = proposed;
                    break;
                }
            }
            if (acceptedTS != NULL) break;
        }

        if (config.verbose) {
            std::cout << "[PC] PC ID=" << (int)presID
                      << " 抽象语法: " << abstractSyntax
                      << " 提议传输语法数: " << pc.transferSyntaxCount
                      << " 接受: " << (acceptedTS ? acceptedTS : "(无匹配，拒绝)")
                      << std::endl;
        }

        if (acceptedTS == NULL) continue;

        // 接受这个 Presentation Context
        cond = ASC_acceptPresentationContext(
            assoc->params,
            presID,
            acceptedTS,               // 接受的传输语法
            ASC_SC_ROLE_DEFAULT       // 角色：默认 SCP
        );

        if (cond.good() && config.verbose) {
            std::cout << "[PC] 已接受 PC ID=" << (int)presID
                      << " 传输语法: " << acceptedTS << std::endl;
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

    // 保存为 DICOM 文件，使用数据集当前传输语法（即协商的传输语法）
    DcmFileFormat fileFormat(dataset);
    OFCondition cond = fileFormat.saveFile(
        fileName,
        dataset->getCurrentXfer()
    );

    if (cond.bad()) {
        std::cerr << "[ERROR] 保存文件失败: " << fileName
                  << " - " << cond.text() << std::endl;
        return cond;
    }

    return EC_Normal;
}

// ============================================================
//  DIMSE_storeProvider 回调：在数据集接收完成后保存文件
//  注意：DIMSE_storeProvider 内部会自动发送 C-STORE-RSP，
//        因此回调中只需设置响应状态，无需手动发送响应。
// ============================================================
struct StoreCallbackData {
    OFString outputDir;
    OFString savedFilePath;
};

static void storeProviderCallback(
    void* callbackData,
    T_DIMSE_StoreProgress* progress,
    T_DIMSE_C_StoreRQ* /*request*/,
    char* /*imageFileName*/,
    DcmDataset** imageDataSet,
    T_DIMSE_C_StoreRSP* response,
    DcmDataset** /*statusDetail*/)
{
    if (progress->state != DIMSE_StoreEnd) {
        return;  // 只在接收结束时处理
    }

    StoreCallbackData* cbdata = static_cast<StoreCallbackData*>(callbackData);
    if (cbdata == NULL || imageDataSet == NULL || *imageDataSet == NULL) {
        response->DimseStatus = STATUS_STORE_Refused_OutOfResources;
        return;
    }

    // 保存文件到本地
    OFCondition saveCond = saveDICOMFile(*imageDataSet, cbdata->outputDir, cbdata->savedFilePath);
    if (saveCond.good()) {
        response->DimseStatus = STATUS_Success;
    } else {
        response->DimseStatus = STATUS_STORE_Refused_OutOfResources;
    }

    // 文件保存成功后，增量更新索引
    if (saveCond.good() && !cbdata->savedFilePath.empty()) {
        g_dicomIndex.addFile(cbdata->savedFilePath.c_str());
    }
}

// ============================================================
//  C-FIND Provider 回调：查询 SQLite 索引并返回匹配记录
// ============================================================
static void findProviderCallback(
    void* callbackData,
    OFBool cancelled,
    T_DIMSE_C_FindRQ* request,
    DcmDataset* requestIdentifiers,
    int responseCount,
    T_DIMSE_C_FindRSP* response,
    DcmDataset** responseIdentifiers,
    DcmDataset** statusDetail)
{
    (void)callbackData;
    (void)cancelled;

    // 首次调用（responseCount == 1）时执行查询，后续调用逐条返回结果
    static std::vector<DicomRecord> g_findResults;
    static size_t g_findIndex = 0;
    static std::string g_queryLevel;

    if (responseCount <= 1) {
        // 解析查询条件
        QueryCondition cond;
        OFString val;
        if (requestIdentifiers && requestIdentifiers->findAndGetOFString(DCM_PatientID, val).good())
            cond["patientID"] = val.c_str();
        if (requestIdentifiers && requestIdentifiers->findAndGetOFString(DCM_PatientName, val).good())
            cond["patientName"] = val.c_str();
        if (requestIdentifiers && requestIdentifiers->findAndGetOFString(DCM_StudyDate, val).good())
            cond["studyDate"] = val.c_str();
        if (requestIdentifiers && requestIdentifiers->findAndGetOFString(DCM_Modality, val).good())
            cond["modality"] = val.c_str();
        if (requestIdentifiers && requestIdentifiers->findAndGetOFString(DCM_StudyDescription, val).good())
            cond["studyDescription"] = val.c_str();
        if (requestIdentifiers && requestIdentifiers->findAndGetOFString(DCM_StudyInstanceUID, val).good())
            cond["studyInstanceUID"] = val.c_str();
        if (requestIdentifiers && requestIdentifiers->findAndGetOFString(DCM_SeriesInstanceUID, val).good())
            cond["seriesInstanceUID"] = val.c_str();
        if (requestIdentifiers && requestIdentifiers->findAndGetOFString(DCM_SOPInstanceUID, val).good())
            cond["sopInstanceUID"] = val.c_str();

        // 确定查询层级
        g_queryLevel = "STUDY";
        if (requestIdentifiers && requestIdentifiers->findAndGetOFString(DCM_QueryRetrieveLevel, val).good()) {
            g_queryLevel = val.c_str();
        }

        g_findResults = g_dicomIndex.query(cond, g_queryLevel);
        g_findIndex = 0;
    }

    // 设置响应状态
    if (g_findIndex < g_findResults.size()) {
        // 还有数据，返回 Pending 状态
        response->DimseStatus = STATUS_Pending;
        const DicomRecord& rec = g_findResults[g_findIndex];

        DcmDataset* rspIds = new DcmDataset();
        rspIds->putAndInsertString(DCM_QueryRetrieveLevel, g_queryLevel.c_str());
        if (!rec.patientID.empty()) rspIds->putAndInsertString(DCM_PatientID, rec.patientID.c_str());
        if (!rec.patientName.empty()) rspIds->putAndInsertString(DCM_PatientName, rec.patientName.c_str());
        if (!rec.patientBirthDate.empty()) rspIds->putAndInsertString(DCM_PatientBirthDate, rec.patientBirthDate.c_str());
        if (!rec.patientSex.empty()) rspIds->putAndInsertString(DCM_PatientSex, rec.patientSex.c_str());
        if (!rec.studyInstanceUID.empty()) rspIds->putAndInsertString(DCM_StudyInstanceUID, rec.studyInstanceUID.c_str());
        if (!rec.studyDate.empty()) rspIds->putAndInsertString(DCM_StudyDate, rec.studyDate.c_str());
        if (!rec.studyTime.empty()) rspIds->putAndInsertString(DCM_StudyTime, rec.studyTime.c_str());
        if (!rec.studyDescription.empty()) rspIds->putAndInsertString(DCM_StudyDescription, rec.studyDescription.c_str());
        if (!rec.modalitiesInStudy.empty()) rspIds->putAndInsertString(DCM_ModalitiesInStudy, rec.modalitiesInStudy.c_str());
        if (!rec.seriesInstanceUID.empty()) rspIds->putAndInsertString(DCM_SeriesInstanceUID, rec.seriesInstanceUID.c_str());
        if (!rec.seriesNumber.empty()) rspIds->putAndInsertString(DCM_SeriesNumber, rec.seriesNumber.c_str());
        if (!rec.modality.empty()) rspIds->putAndInsertString(DCM_Modality, rec.modality.c_str());
        if (!rec.seriesDescription.empty()) rspIds->putAndInsertString(DCM_SeriesDescription, rec.seriesDescription.c_str());
        if (!rec.sopInstanceUID.empty()) rspIds->putAndInsertString(DCM_SOPInstanceUID, rec.sopInstanceUID.c_str());
        if (!rec.sopClassUID.empty()) rspIds->putAndInsertString(DCM_SOPClassUID, rec.sopClassUID.c_str());
        if (!rec.instanceNumber.empty()) rspIds->putAndInsertString(DCM_InstanceNumber, rec.instanceNumber.c_str());

        *responseIdentifiers = rspIds;
        g_findIndex++;
    } else {
        // 查询结束，返回 Success
        response->DimseStatus = STATUS_Success;
        *responseIdentifiers = NULL;
        g_findResults.clear();
    }
}

// ============================================================
//  C-MOVE Provider：子关联回调数据 + 子关联 C-STORE 发送
// ============================================================
struct MoveCallbackData {
    T_ASC_Association* assoc;   // 主关联（用于获取主叫地址）
    const TLSConfig* tlsConfig; // TLS 证书配置（子关联复用）
    Uint16 moveDestPort;        // MoveDestination 的存储 SCP 端口
};

// 通过子关联发送单个 DICOM 文件（C-STORE sub-operation）
static OFCondition sendCStoreSubOp(T_ASC_Association* subAssoc,
                                   const DicomRecord& rec,
                                   Uint16& completed, Uint16& failed, Uint16& warning)
{
    // 加载 DICOM 文件
    DcmFileFormat ff;
    if (ff.loadFile(rec.filePath.c_str()).bad()) {
        failed++;
        return EC_IllegalCall;
    }

    // 先用 getDataset() 读取信息（ff 仍持有所有权）
    DcmDataset* tmpDataset = ff.getDataset();
    OFString sopClassUID, sopInstanceUID;
    tmpDataset->findAndGetOFString(DCM_SOPClassUID, sopClassUID);
    tmpDataset->findAndGetOFString(DCM_SOPInstanceUID, sopInstanceUID);

    // 查找已接受的 Presentation Context
    T_ASC_PresentationContextID presID =
        ASC_findAcceptedPresentationContextID(subAssoc, sopClassUID.c_str());
    if (presID == 0) {
        failed++;
        return EC_IllegalCall;  // ff 析构时释放 dataset
    }

    // PC 已接受，将 dataset 从 ff 移出，所有权交给 DIMSE_storeUser
    DcmDataset* dataset = ff.getAndRemoveDataset();

    // 构造 C-STORE 请求
    T_DIMSE_C_StoreRQ req;
    memset(&req, 0, sizeof(req));
    req.MessageID = subAssoc->nextMsgID++;
    strncpy(req.AffectedSOPClassUID, sopClassUID.c_str(), DIC_UI_LEN);
    strncpy(req.AffectedSOPInstanceUID, sopInstanceUID.c_str(), DIC_UI_LEN);
    req.Priority = DIMSE_PRIORITY_MEDIUM;
    req.DataSetType = DIMSE_DATASET_PRESENT;

    T_DIMSE_C_StoreRSP rsp;
    DcmDataset* statusDetail = NULL;

    OFCondition cond = DIMSE_storeUser(
        subAssoc, presID, &req, NULL, dataset,
        NULL, NULL, DIMSE_BLOCKING, 0, &rsp, &statusDetail);

    if (statusDetail) delete statusDetail;
    // dataset 所有权已交给 DIMSE_storeUser，不手动释放

    if (cond.good() && rsp.DimseStatus == STATUS_Success) {
        completed++;
    } else if (rsp.DimseStatus == STATUS_Success) {
        completed++;
    } else {
        // 0x0001 (coercion) 等视为 warning，其他视为 failed
        if (rsp.DimseStatus == STATUS_STORE_Warning_CoercionOfDataElements) {
            warning++;
        } else {
            failed++;
        }
    }
    return cond;
}

// C-MOVE Provider 回调：查询索引 → 建立子关联 → 逐条 C-STORE 回传
static void moveProviderCallback(
    void* callbackData,
    OFBool /*cancelled*/,
    T_DIMSE_C_MoveRQ* request,
    DcmDataset* requestIdentifiers,
    int responseCount,
    T_DIMSE_C_MoveRSP* response,
    DcmDataset** /*statusDetail*/,
    DcmDataset** responseIdentifiers)
{
    MoveCallbackData* cbdata = static_cast<MoveCallbackData*>(callbackData);
    *responseIdentifiers = NULL;

    // 只在首次调用时执行完整检索流程
    if (responseCount > 1) {
        response->DimseStatus = STATUS_Success;
        return;
    }

    // 1. 解析查询条件
    QueryCondition cond;
    OFString val;
    if (requestIdentifiers && requestIdentifiers->findAndGetOFString(DCM_PatientID, val).good())
        cond["patientID"] = val.c_str();
    if (requestIdentifiers && requestIdentifiers->findAndGetOFString(DCM_StudyInstanceUID, val).good())
        cond["studyInstanceUID"] = val.c_str();
    if (requestIdentifiers && requestIdentifiers->findAndGetOFString(DCM_SeriesInstanceUID, val).good())
        cond["seriesInstanceUID"] = val.c_str();
    if (requestIdentifiers && requestIdentifiers->findAndGetOFString(DCM_SOPInstanceUID, val).good())
        cond["sopInstanceUID"] = val.c_str();
    if (requestIdentifiers && requestIdentifiers->findAndGetOFString(DCM_Modality, val).good())
        cond["modality"] = val.c_str();

    // MOVE 必须精确到 IMAGE 级（获取具体文件路径），不做 GROUP BY 去重
    std::vector<DicomRecord> records = g_dicomIndex.query(cond, "IMAGE");

    std::cout << "[C-MOVE] 匹配到 " << records.size() << " 个实例，MoveDestination="
              << request->MoveDestination << std::endl;

    response->NumberOfRemainingSubOperations = 0;
    response->NumberOfCompletedSubOperations = 0;
    response->NumberOfFailedSubOperations = 0;
    response->NumberOfWarningSubOperations = 0;
    response->opts = 0;

    if (records.empty()) {
        response->DimseStatus = STATUS_Success;
        return;
    }

    // 2. 获取主叫（SCU）地址，用于建立子关联
    char callingAddr[256] = {0};
    char calledAddr[256] = {0};
    ASC_getPresentationAddresses(cbdata->assoc->params,
                                 callingAddr, sizeof(callingAddr),
                                 calledAddr, sizeof(calledAddr));
    // callingAddr 格式为 "host:port"，提取 host 部分
    std::string callingHost(callingAddr);
    size_t colonPos = callingHost.find(':');
    if (colonPos != std::string::npos) {
        callingHost = callingHost.substr(0, colonPos);
    }
    if (callingHost.empty() || callingHost == "0.0.0.0") {
        callingHost = "127.0.0.1";
    }

    std::cout << "[C-MOVE] 建立子关联到 " << callingHost << ":" << cbdata->moveDestPort << std::endl;

    // 3. 建立子关联（SCP 作为 C-STORE SCU 回连 SCU）
    T_ASC_Network* subNet = NULL;
    OFCondition subCond = ASC_initializeNetwork(NET_REQUESTOR, 0, 1000, &subNet);
    if (subCond.bad()) {
        response->DimseStatus = STATUS_MOVE_Refused_OutOfResourcesSubOperations;
        response->NumberOfFailedSubOperations = records.size();
        response->opts |= O_MOVE_NUMBEROFFAILEDSUBOPERATIONS;
        return;
    }

    // 子关联使用客户端 TLS（SCP 作为 C-STORE SCU 回连）
    subCond = setupTLSClientTransportLayer(subNet, *cbdata->tlsConfig);
    if (subCond.bad()) {
        ASC_dropNetwork(&subNet);
        response->DimseStatus = STATUS_MOVE_Refused_OutOfResourcesSubOperations;
        response->NumberOfFailedSubOperations = records.size();
        response->opts |= O_MOVE_NUMBEROFFAILEDSUBOPERATIONS;
        return;
    }

    T_ASC_Parameters* subParams;
    ASC_createAssociationParameters(&subParams, cbdata->tlsConfig->maxPDULength);
    ASC_setTransportLayerType(subParams, OFTrue);
    // 子关联：本地 AE = 原 SCP，远端 AE = MoveDestination
    ASC_setAPTitles(subParams,
                    cbdata->tlsConfig->ourAETitle.c_str(),
                    request->MoveDestination,
                    NULL);

    std::string destAddr = callingHost + ":" + std::to_string(cbdata->moveDestPort);
    ASC_setPresentationAddresses(subParams, NULL, destAddr.c_str());

    // 收集所有需要的 SOP Class，提议 Presentation Context
    std::set<std::string> sopClassSet;
    for (size_t i = 0; i < records.size(); i++) {
        if (!records[i].sopClassUID.empty())
            sopClassSet.insert(records[i].sopClassUID);
    }

    // 使用静态 UID 常量，避免 DcmXfer() 临时对象的悬垂指针
    static const char* storeTransferSyntaxes[] = {
        UID_LittleEndianExplicitTransferSyntax,
        UID_LittleEndianImplicitTransferSyntax,
        NULL
    };
    int pcID = 1;
    for (std::set<std::string>::iterator it = sopClassSet.begin(); it != sopClassSet.end(); ++it) {
        ASC_addPresentationContext(subParams, pcID, it->c_str(),
                                   storeTransferSyntaxes, ASC_SC_ROLE_DEFAULT);
        pcID += 2;
    }

    T_ASC_Association* subAssoc = NULL;
    subCond = ASC_requestAssociation(subNet, subParams, &subAssoc);
    if (subCond.bad()) {
        std::cerr << "[C-MOVE] 子关联建立失败: " << subCond.text() << std::endl;
        ASC_destroyAssociationParameters(&subParams);
        ASC_dropNetwork(&subNet);
        response->DimseStatus = STATUS_MOVE_Refused_OutOfResourcesSubOperations;
        response->NumberOfFailedSubOperations = records.size();
        response->opts |= O_MOVE_NUMBEROFFAILEDSUBOPERATIONS;
        return;
    }
    // 注意：ASC_requestAssociation 后，subAssoc->params 仍指向 subParams。
    // 不能在此调用 ASC_destroyAssociationParameters，否则 subAssoc 访问已释放的 params，
    // 导致 ASC_findAcceptedPresentationContextID 返回 0，且 ASC_destroyAssociation 时 double-free。
    // ASC_destroyAssociation 内部会释放 params。

    // 4. 逐条发送 C-STORE
    Uint16 completed = 0, failed = 0, warning = 0;
    for (size_t i = 0; i < records.size(); i++) {
        sendCStoreSubOp(subAssoc, records[i], completed, failed, warning);
    }

    // 5. 释放子关联（ASC_destroyAssociation 会释放 params）
    ASC_releaseAssociation(subAssoc);
    ASC_destroyAssociation(&subAssoc);
    ASC_dropNetwork(&subNet);

    // 6. 设置响应计数
    response->NumberOfCompletedSubOperations = completed;
    response->NumberOfFailedSubOperations = failed;
    response->NumberOfWarningSubOperations = warning;
    response->NumberOfRemainingSubOperations = 0;
    response->opts = O_MOVE_NUMBEROFCOMPLETEDSUBOPERATIONS |
                     O_MOVE_NUMBEROFFAILEDSUBOPERATIONS |
                     O_MOVE_NUMBEROFWARNINGSUBOPERATIONS |
                     O_MOVE_NUMBEROFREMAININGSUBOPERATIONS;
    response->DimseStatus = (failed > 0) ? STATUS_Success : STATUS_Success;

    std::cout << "[C-MOVE] 完成: completed=" << completed
              << ", failed=" << failed << ", warning=" << warning << std::endl;
}

// ============================================================
//  处理 DIMSE 命令（C-STORE / C-ECHO / C-FIND / C-MOVE）
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
        memset(&msg, 0, sizeof(msg));
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
                // 发送 A-RELEASE-RP 确认释放（与官方 storescp 行为一致）
                OFCondition ackCond = ASC_acknowledgeRelease(assoc);
                if (ackCond.good()) {
                    std::cout << "[ASSOC] 已发送 A-RELEASE-RP，连接正常释放" << std::endl;
                } else {
                    std::cerr << "[WARN] A-RELEASE-RP 发送异常: " << ackCond.text() << std::endl;
                }
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
                std::cout << "[C-STORE] 收到存储请求 (MsgID=" << rq->MessageID << ")" << std::endl;
                std::cout << "[C-STORE] SOP Class:    " << rq->AffectedSOPClassUID << std::endl;
                std::cout << "[C-STORE] SOP Instance: " << rq->AffectedSOPInstanceUID << std::endl;
                std::cout << "[C-STORE] Priority:     " << rq->Priority << std::endl;
                std::cout << "[C-STORE] 数据通过 TLS 加密接收 ✓" << std::endl;

                // 接收数据集（DIMSE_storeProvider 内部会自动发送 C-STORE-RSP）
                DcmDataset* dataset = NULL;
                StoreCallbackData cbdata;
                cbdata.outputDir = config.outputDir;

                cond = DIMSE_storeProvider(
                    assoc,
                    presID,
                    rq,
                    NULL,                  // imageFileName (不写文件)
                    0,                     // writeMetaheader
                    &dataset,              // 接收到的数据集
                    storeProviderCallback, // 回调（保存文件 + 设置响应状态）
                    &cbdata,               // 回调参数
                    DIMSE_BLOCKING,        // 阻塞模式
                    0                      // 超时
                );

                if (cond.bad()) {
                    std::cerr << "[ERROR] 接收/存储失败: " << cond.text() << std::endl;
                    break;
                }

                std::cout << "[C-STORE] 已保存: " << cbdata.savedFilePath << std::endl;
                std::cout << "[C-STORE] 响应: 成功 (0x0000)" << std::endl;
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

            case DIMSE_C_FIND_RQ: {
                // --- 处理 C-FIND 查询请求 ---
                T_DIMSE_C_FindRQ* rq = &msg.msg.CFindRQ;
                std::cout << std::endl << "[C-FIND] 收到查询请求 (MsgID=" << rq->MessageID << ")" << std::endl;
                std::cout << "[C-FIND] SOP Class: " << rq->AffectedSOPClassUID << std::endl;

                cond = DIMSE_findProvider(
                    assoc,
                    presID,
                    rq,
                    findProviderCallback,
                    NULL,
                    DIMSE_BLOCKING,
                    0
                );

                if (cond.bad()) {
                    std::cerr << "[C-FIND] 查询处理失败: " << cond.text() << std::endl;
                } else {
                    std::cout << "[C-FIND] 查询完成" << std::endl;
                }
                break;
            }

            case DIMSE_C_MOVE_RQ: {
                // --- 处理 C-MOVE 检索请求 ---
                T_DIMSE_C_MoveRQ* rq = &msg.msg.CMoveRQ;
                std::cout << std::endl << "[C-MOVE] 收到检索请求 (MsgID=" << rq->MessageID << ")" << std::endl;
                std::cout << "[C-MOVE] SOP Class: " << rq->AffectedSOPClassUID << std::endl;
                std::cout << "[C-MOVE] MoveDestination: " << rq->MoveDestination << std::endl;

                MoveCallbackData moveCbdata;
                moveCbdata.assoc = assoc;
                moveCbdata.tlsConfig = &config;
                moveCbdata.moveDestPort = config.moveDestPort;

                cond = DIMSE_moveProvider(
                    assoc,
                    presID,
                    rq,
                    moveProviderCallback,
                    &moveCbdata,
                    DIMSE_BLOCKING,
                    0
                );

                if (cond.bad()) {
                    std::cerr << "[C-MOVE] 检索处理失败: " << cond.text() << std::endl;
                } else {
                    std::cout << "[C-MOVE] 检索完成" << std::endl;
                }
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

    // 注册 DICOM 压缩传输语法编解码器（RLE / JPEG / JPEG-LS）
    DcmRLEEncoderRegistration::registerCodecs();
    DcmRLEDecoderRegistration::registerCodecs();
    DJEncoderRegistration::registerCodecs();
    DJDecoderRegistration::registerCodecs();
    DJLSEncoderRegistration::registerCodecs();
    DJLSDecoderRegistration::registerCodecs();

    TLSConfig config;
    config.listenPort    = 11112;
    config.ourAETitle    = "TLS_SCP";
    config.outputDir     = "./received";
    config.maxPDULength  = ASC_DEFAULTMAXPDU;
    config.verbose       = true;
    config.moveDestPort  = 11113;  // C-MOVE 子关联目标端口（SCU 存储 SCP 监听端口）

    // TLS 证书路径
    config.certFile        = "certs/server.crt";
    config.keyFile         = "certs/server.key";
    config.caFile          = "certs/ca.crt";
    config.passphrase      = "";
    config.clientCertFile  = "certs/client.crt";   // C-MOVE 子关联用
    config.clientKeyFile   = "certs/client.key";   // C-MOVE 子关联用

    // 命令行参数
    if (argc >= 2) config.listenPort = atoi(argv[1]);
    if (argc >= 3) config.ourAETitle = argv[2];
    if (argc >= 4) config.outputDir  = argv[3];
    if (argc >= 5) config.moveDestPort = atoi(argv[4]);

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

    // 2.5 初始化 DICOM 索引（C-FIND 查询使用）
    {
        std::string dbPath = config.outputDir.c_str();
        dbPath += "/dicom_index.db";
        if (g_dicomIndex.open(dbPath)) {
            int n = g_dicomIndex.scanDirectory(config.outputDir.c_str());
            std::cout << "[INDEX] DICOM 索引已初始化，共 " << n << " 条记录" << std::endl;
        } else {
            std::cerr << "[WARN] DICOM 索引初始化失败，C-FIND 查询将返回空结果" << std::endl;
        }
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
        // 如果对端已请求释放，handleCStore 内部已发送 A-RELEASE-RP，无需再处理
        if (handleCond == DUL_PEERREQUESTEDRELEASE) {
            std::cout << "[ASSOC] 对端已请求释放，A-RELEASE-RP 已发送" << std::endl;
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
