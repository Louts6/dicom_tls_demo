// ============================================================
//  SCP Worker 实现
// ============================================================
#include "scp_worker.h"
#include "../common/tls_helper.h"
#include "../common/dicom_index.h"

#include "dcmtk/dcmnet/diutil.h"
#include "dcmtk/dcmnet/dimse.h"
#include "dcmtk/dcmnet/dcasccff.h"
#include "dcmtk/dcmdata/dcfilefo.h"
#include "dcmtk/dcmdata/dcdeftag.h"
#include "dcmtk/dcmdata/dcxfer.h"

#include <QDir>
#include <sstream>
#include <set>
#include <string>

// ============================================================
//  DIMSE_storeProvider 回调：在数据集接收完成后保存文件
//  注意：DIMSE_storeProvider 内部会自动发送 C-STORE-RSP，
//        因此回调中只需设置响应状态，无需手动发送响应。
// ============================================================
struct StoreCallbackData {
    OFString outputDir;
    OFString savedFilePath;
    bool saveSuccess;
    DicomIndex* index;      // 指向 SCPWorker 的索引（用于增量更新）
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
        return;
    }

    StoreCallbackData* cbdata = static_cast<StoreCallbackData*>(callbackData);
    if (cbdata == NULL || imageDataSet == NULL || *imageDataSet == NULL) {
        response->DimseStatus = STATUS_STORE_Refused_OutOfResources;
        return;
    }

    OFString sopInstanceUID;
    (*imageDataSet)->findAndGetOFString(DCM_SOPInstanceUID, sopInstanceUID);
    QString fileName = QString("%1/%2.dcm")
        .arg(cbdata->outputDir.c_str())
        .arg(sopInstanceUID.c_str());

    DcmFileFormat ff(*imageDataSet);
    OFCondition saveCond = ff.saveFile(
        fileName.toLocal8Bit().constData(), (*imageDataSet)->getCurrentXfer());

    if (saveCond.good()) {
        cbdata->savedFilePath = fileName.toUtf8().constData();
        cbdata->saveSuccess = true;
        response->DimseStatus = STATUS_Success;
        // 增量更新索引
        if (cbdata->index != NULL) {
            cbdata->index->addFile(cbdata->savedFilePath.c_str());
        }
    } else {
        cbdata->saveSuccess = false;
        response->DimseStatus = STATUS_STORE_Refused_OutOfResources;
    }
}

// ============================================================
//  C-MOVE Provider：子关联回调数据 + 子关联 C-STORE 发送
// ============================================================
struct GuiMoveCallbackData {
    T_ASC_Association* assoc;   // 主关联
    const SCPConfig* config;    // SCP 配置（证书、端口等）
    DicomIndex* index;          // DICOM 索引
};

// 通过子关联发送单个 DICOM 文件（C-STORE sub-operation）
static OFCondition guiSendCStoreSubOp(T_ASC_Association* subAssoc,
                                      const DicomRecord& rec,
                                      Uint16& completed, Uint16& failed, Uint16& warning)
{
    DcmFileFormat ff;
    if (ff.loadFile(rec.filePath.c_str()).bad()) {
        failed++;
        return EC_IllegalCall;
    }

    DcmDataset* tmpDataset = ff.getDataset();
    OFString sopClassUID, sopInstanceUID;
    tmpDataset->findAndGetOFString(DCM_SOPClassUID, sopClassUID);
    tmpDataset->findAndGetOFString(DCM_SOPInstanceUID, sopInstanceUID);

    T_ASC_PresentationContextID presID =
        ASC_findAcceptedPresentationContextID(subAssoc, sopClassUID.c_str());
    if (presID == 0) {
        failed++;
        return EC_IllegalCall;
    }

    DcmDataset* dataset = ff.getAndRemoveDataset();

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
        NULL, NULL, DIMSE_BLOCKING, 30, &rsp, &statusDetail);

    if (statusDetail) delete statusDetail;

    if (cond.good() && rsp.DimseStatus == STATUS_Success) {
        completed++;
    } else if (rsp.DimseStatus == STATUS_STORE_Warning_CoercionOfDataElements) {
        warning++;
    } else {
        failed++;
    }
    return cond;
}

// C-MOVE Provider 回调：查询索引 → 建立子关联 → 逐条 C-STORE 回传
static void guiMoveProviderCallback(
    void* callbackData,
    OFBool /*cancelled*/,
    T_DIMSE_C_MoveRQ* request,
    DcmDataset* requestIdentifiers,
    int responseCount,
    T_DIMSE_C_MoveRSP* response,
    DcmDataset** /*statusDetail*/,
    DcmDataset** responseIdentifiers)
{
    GuiMoveCallbackData* cbdata = static_cast<GuiMoveCallbackData*>(callbackData);
    *responseIdentifiers = NULL;

    if (responseCount > 1) {
        response->DimseStatus = STATUS_Success;
        return;
    }

    // 解析查询条件
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

    std::vector<DicomRecord> records = cbdata->index->query(cond, "IMAGE");

    response->NumberOfRemainingSubOperations = 0;
    response->NumberOfCompletedSubOperations = 0;
    response->NumberOfFailedSubOperations = 0;
    response->NumberOfWarningSubOperations = 0;
    response->opts = 0;

    if (records.empty()) {
        response->DimseStatus = STATUS_Success;
        return;
    }

    // 获取主叫地址
    char callingAddr[256] = {0};
    char calledAddr[256] = {0};
    ASC_getPresentationAddresses(cbdata->assoc->params,
                                 callingAddr, sizeof(callingAddr),
                                 calledAddr, sizeof(calledAddr));
    std::string callingHost(callingAddr);
    size_t colonPos = callingHost.find(':');
    if (colonPos != std::string::npos) {
        callingHost = callingHost.substr(0, colonPos);
    }
    if (callingHost.empty() || callingHost == "0.0.0.0") {
        callingHost = "127.0.0.1";
    }

    // 建立子关联（SCP 作为 C-STORE SCU 回连 SCU）
    T_ASC_Network* subNet = NULL;
    OFCondition subCond = ASC_initializeNetwork(NET_REQUESTOR, 0, 1000, &subNet);
    if (subCond.bad()) {
        response->DimseStatus = STATUS_MOVE_Refused_OutOfResourcesSubOperations;
        response->NumberOfFailedSubOperations = records.size();
        response->opts |= O_MOVE_NUMBEROFFAILEDSUBOPERATIONS;
        return;
    }

    // 子关联使用客户端 TLS
    std::string clientCert = cbdata->config->clientCertFile.empty()
        ? cbdata->config->certFile.c_str() : cbdata->config->clientCertFile.c_str();
    std::string clientKey = cbdata->config->clientKeyFile.empty()
        ? cbdata->config->keyFile.c_str() : cbdata->config->clientKeyFile.c_str();
    subCond = TlsHelper::setupTLS(subNet, NET_REQUESTOR,
                                  clientCert, clientKey,
                                  cbdata->config->caFile.c_str(), true);
    if (subCond.bad()) {
        ASC_dropNetwork(&subNet);
        response->DimseStatus = STATUS_MOVE_Refused_OutOfResourcesSubOperations;
        response->NumberOfFailedSubOperations = records.size();
        response->opts |= O_MOVE_NUMBEROFFAILEDSUBOPERATIONS;
        return;
    }

    T_ASC_Parameters* subParams;
    ASC_createAssociationParameters(&subParams, cbdata->config->maxPDULength);
    ASC_setTransportLayerType(subParams, OFTrue);
    ASC_setAPTitles(subParams,
                    cbdata->config->ourAETitle.c_str(),
                    request->MoveDestination,
                    NULL);

    std::string destAddr = callingHost + ":" + std::to_string(cbdata->config->moveDestPort);
    ASC_setPresentationAddresses(subParams, NULL, destAddr.c_str());

    // 收集 SOP Class 并提议 PC
    std::set<std::string> sopClassSet;
    for (size_t i = 0; i < records.size(); i++) {
        if (!records[i].sopClassUID.empty())
            sopClassSet.insert(records[i].sopClassUID);
    }

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
        ASC_destroyAssociationParameters(&subParams);
        ASC_dropNetwork(&subNet);
        response->DimseStatus = STATUS_MOVE_Refused_OutOfResourcesSubOperations;
        response->NumberOfFailedSubOperations = records.size();
        response->opts |= O_MOVE_NUMBEROFFAILEDSUBOPERATIONS;
        return;
    }
    // 注意：ASC_requestAssociation 后 subAssoc->params 仍指向 subParams，
    // 不能提前销毁，由 ASC_destroyAssociation 统一清理。

    // 逐条发送 C-STORE
    Uint16 completed = 0, failed = 0, warning = 0;
    for (size_t i = 0; i < records.size(); i++) {
        guiSendCStoreSubOp(subAssoc, records[i], completed, failed, warning);
    }

    // 释放子关联
    ASC_releaseAssociation(subAssoc);
    ASC_destroyAssociation(&subAssoc);
    ASC_dropNetwork(&subNet);

    response->NumberOfCompletedSubOperations = completed;
    response->NumberOfFailedSubOperations = failed;
    response->NumberOfWarningSubOperations = warning;
    response->NumberOfRemainingSubOperations = 0;
    response->opts = O_MOVE_NUMBEROFCOMPLETEDSUBOPERATIONS |
                     O_MOVE_NUMBEROFFAILEDSUBOPERATIONS |
                     O_MOVE_NUMBEROFWARNINGSUBOPERATIONS |
                     O_MOVE_NUMBEROFREMAININGSUBOPERATIONS;
    response->DimseStatus = STATUS_Success;
}

// ============================================================
//  C-FIND Provider 回调：查询 SQLite 索引并返回匹配记录
// ============================================================
static void guiFindProviderCallback(
    void* callbackData,
    OFBool /*cancelled*/,
    T_DIMSE_C_FindRQ* /*request*/,
    DcmDataset* requestIdentifiers,
    int responseCount,
    T_DIMSE_C_FindRSP* response,
    DcmDataset** responseIdentifiers,
    DcmDataset** /*statusDetail*/)
{
    DicomIndex* index = static_cast<DicomIndex*>(callbackData);

    static std::vector<DicomRecord> g_findResults;
    static size_t g_findIndex = 0;
    static std::string g_queryLevel;

    if (responseCount <= 1) {
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

        g_queryLevel = "STUDY";
        if (requestIdentifiers && requestIdentifiers->findAndGetOFString(DCM_QueryRetrieveLevel, val).good()) {
            g_queryLevel = val.c_str();
        }

        g_findResults = index->query(cond, g_queryLevel);
        g_findIndex = 0;
    }

    if (g_findIndex < g_findResults.size()) {
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
        response->DimseStatus = STATUS_Success;
        *responseIdentifiers = NULL;
        g_findResults.clear();
    }
}

SCPWorker::SCPWorker(QObject* parent)
    : QObject(parent)
    , m_running(false)
{
}

SCPWorker::~SCPWorker()
{
    stopServer();
}

void SCPWorker::stopServer()
{
    m_running = false;
}

void SCPWorker::startServer(const SCPConfig& config)
{
    m_running = true;
    emit serverStarted();

    emit logMessage(QString("启动 DICOM TLS SCP 服务..."));
    emit logMessage(QString("  监听端口: %1").arg(config.listenPort));
    emit logMessage(QString("  AE Title: %1").arg(config.ourAETitle.c_str()));
    emit logMessage(QString("  保存目录: %1").arg(config.outputDir.c_str()));

    // 确保输出目录存在
    QDir().mkpath(QString::fromUtf8(config.outputDir.c_str()));

    T_ASC_Network* net = NULL;
    T_ASC_Association* assoc = NULL;

    // 1. 初始化 DCMTK 网络
    OFCondition cond = ASC_initializeNetwork(
        NET_ACCEPTOR, config.listenPort, 1000, &net);
    if (cond.bad()) {
        emit logMessage(QString("[ERROR] 网络初始化失败: %1").arg(cond.text()));
        emit serverError(QString::fromUtf8(cond.text()));
        emit serverStopped();
        return;
    }
    emit logMessage("[OK] 网络层初始化成功");

    // 2. 设置 TLS
    cond = TlsHelper::setupTLS(net, NET_ACCEPTOR,
                               config.certFile.c_str(),
                               config.keyFile.c_str(),
                               config.caFile.c_str(),
                               true);
    if (cond.bad()) {
        emit logMessage(QString("[ERROR] TLS 初始化失败: %1").arg(cond.text()));
        emit serverError(QString::fromUtf8(cond.text()));
        ASC_dropNetwork(&net);
        emit serverStopped();
        return;
    }
    emit logMessage("[OK] TLS 加密传输层初始化成功（双向认证）");
    emit logMessage("[INFO] 所有 DICOM 通信将通过 TLS 1.2 加密传输");

    // 初始化 DICOM 文件索引（用于 C-FIND 查询）
    QString dbPath = QString("%1/dicom_index.db").arg(QString::fromUtf8(config.outputDir.c_str()));
    if (m_index.open(dbPath.toLocal8Bit().constData())) {
        int n = m_index.scanDirectory(config.outputDir.c_str());
        emit logMessage(QString("[INDEX] 已建立索引，共 %1 条记录").arg(n));
    } else {
        emit logMessage("[WARN] 索引初始化失败，C-FIND 查询功能不可用");
    }

    emit logMessage("等待 TLS 加密的 DICOM 连接...");

    // 3. 主循环
    while (m_running) {
        assoc = NULL;
        cond = ASC_receiveAssociation(net, &assoc, config.maxPDULength,
                                      NULL, NULL, OFTrue);
        if (cond.bad()) {
            if (cond == DUL_NETWORKCLOSED) break;
            // 超时或其他错误，继续循环
            if (m_running) continue;
            break;
        }

        // 获取 AE Title
        char callingAET[DIC_AE_LEN + 1] = {0};
        char calledAET[DIC_AE_LEN + 1] = {0};
        ASC_getAPTitles(assoc->params,
                        callingAET, sizeof(callingAET),
                        calledAET, sizeof(calledAET),
                        NULL, 0);

        emit logMessage(QString("\n[ASSOC] 收到连接请求 (TLS)"));
        emit logMessage(QString("  主叫 AE: %1").arg(callingAET));
        emit logMessage(QString("  被叫 AE: %1").arg(calledAET));

        // 接受 Presentation Context：在提议的传输语法中选择第一个支持的
        static const char* supportedTS[] = {
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
            if (ASC_getPresentationContext(assoc->params, i, &pc).bad()) continue;

            const char* acceptedTS = NULL;
            for (int j = 0; j < pc.transferSyntaxCount; j++) {
                const char* proposed = pc.proposedTransferSyntaxes[j];
                if (proposed == NULL) continue;
                for (int k = 0; supportedTS[k] != NULL; k++) {
                    if (strcmp(proposed, supportedTS[k]) == 0) {
                        acceptedTS = proposed;
                        break;
                    }
                }
                if (acceptedTS) break;
            }

            if (acceptedTS) {
                ASC_acceptPresentationContext(
                    assoc->params, pc.presentationContextID,
                    acceptedTS, ASC_SC_ROLE_DEFAULT);
            }
        }

        // 确认 Association
        cond = ASC_acknowledgeAssociation(assoc);
        if (cond.bad()) {
            emit logMessage(QString("[ERROR] 确认 Association 失败: %1").arg(cond.text()));
            ASC_destroyAssociation(&assoc);
            continue;
        }
        emit logMessage("[ASSOC] Association 已建立（TLS 加密通道）");

        // 处理 DIMSE 消息
        while (m_running) {
            DcmDataset* statusDetail = NULL;
            T_DIMSE_Message msg;
            T_ASC_PresentationContextID presID;
            memset(&msg, 0, sizeof(msg));

            cond = DIMSE_receiveCommand(assoc, DIMSE_BLOCKING, 0,
                                        &presID, &msg, &statusDetail);
            if (cond.bad()) {
                if (cond == DUL_PEERREQUESTEDRELEASE) {
                    emit logMessage("[ASSOC] 对端请求释放连接");
                    // 发送 A-RELEASE-RP 确认释放（与官方 storescp 行为一致）
                    OFCondition ackCond = ASC_acknowledgeRelease(assoc);
                    if (ackCond.good()) {
                        emit logMessage("[ASSOC] 已发送 A-RELEASE-RP，连接正常释放");
                    } else {
                        emit logMessage(QString("[WARN] A-RELEASE-RP 发送异常: %1")
                                        .arg(ackCond.text()));
                    }
                } else if (cond == DUL_PEERABORTEDASSOCIATION) {
                    emit logMessage("[ASSOC] 对端中止连接");
                }
                if (statusDetail) delete statusDetail;
                break;
            }

            if (msg.CommandField == DIMSE_C_STORE_RQ) {
                T_DIMSE_C_StoreRQ* rq = &msg.msg.CStoreRQ;
                emit logMessage(QString("\n[C-STORE] 收到存储请求 (MsgID=%1)").arg(rq->MessageID));
                emit logMessage(QString("  SOP Class: %1").arg(rq->AffectedSOPClassUID));
                emit logMessage(QString("  SOP Instance: %1").arg(rq->AffectedSOPInstanceUID));

                // 接收数据集（DIMSE_storeProvider 内部会自动发送 C-STORE-RSP）
                DcmDataset* dataset = NULL;
                StoreCallbackData cbdata;
                cbdata.outputDir = config.outputDir;
                cbdata.saveSuccess = false;
                cbdata.index = &m_index;

                cond = DIMSE_storeProvider(assoc, presID, rq, NULL, 0,
                                           &dataset, storeProviderCallback,
                                           &cbdata, DIMSE_BLOCKING, 30);

                if (cond.good() && cbdata.saveSuccess) {
                    emit logMessage(QString("[C-STORE] 已保存: %1")
                                    .arg(cbdata.savedFilePath.c_str()));
                    emit logMessage("[C-STORE] 响应: 成功 (0x0000)");
                    emit fileReceived(QString::fromUtf8(cbdata.savedFilePath.c_str()));
                } else {
                    emit logMessage(QString("[ERROR] 接收/存储失败: %1").arg(cond.text()));
                }

            } else if (msg.CommandField == DIMSE_C_ECHO_RQ) {
                DIMSE_sendEchoResponse(assoc, presID, &msg.msg.CEchoRQ,
                                       STATUS_Success, NULL);
                emit logMessage("[C-ECHO] 响应成功");

            } else if (msg.CommandField == DIMSE_C_FIND_RQ) {
                T_DIMSE_C_FindRQ* rq = &msg.msg.CFindRQ;
                emit logMessage(QString("\n[C-FIND] 收到查询请求 (MsgID=%1)").arg(rq->MessageID));
                emit logMessage(QString("  SOP Class: %1").arg(rq->AffectedSOPClassUID));

                cond = DIMSE_findProvider(
                    assoc, presID, rq,
                    guiFindProviderCallback, &m_index,
                    DIMSE_BLOCKING, 30);

                if (cond.bad()) {
                    emit logMessage(QString("[C-FIND] 查询处理失败: %1").arg(cond.text()));
                } else {
                    emit logMessage("[C-FIND] 查询完成");
                }

            } else if (msg.CommandField == DIMSE_C_MOVE_RQ) {
                T_DIMSE_C_MoveRQ* rq = &msg.msg.CMoveRQ;
                emit logMessage(QString("\n[C-MOVE] 收到检索请求 (MsgID=%1)").arg(rq->MessageID));
                emit logMessage(QString("  SOP Class: %1").arg(rq->AffectedSOPClassUID));
                emit logMessage(QString("  MoveDestination: %1").arg(rq->MoveDestination));

                GuiMoveCallbackData moveCbdata;
                moveCbdata.assoc = assoc;
                moveCbdata.config = &config;
                moveCbdata.index = &m_index;

                cond = DIMSE_moveProvider(
                    assoc, presID, rq,
                    guiMoveProviderCallback, &moveCbdata,
                    DIMSE_BLOCKING, 60);

                if (cond.bad()) {
                    emit logMessage(QString("[C-MOVE] 检索处理失败: %1").arg(cond.text()));
                } else {
                    emit logMessage("[C-MOVE] 检索完成");
                }
            }

            if (statusDetail) delete statusDetail;
        }

        ASC_destroyAssociation(&assoc);
        assoc = NULL;
        emit logMessage("[SCP] 连接已关闭，等待下一个连接...");
    }

    ASC_dropNetwork(&net);
    emit logMessage("\n[SCP] 服务已停止");
    emit serverStopped();
}
