// ============================================================
//  SCU Worker 实现 - 支持多文件批量发送
// ============================================================
#include "scu_worker.h"
#include "../common/tls_helper.h"

#include "dcmtk/dcmnet/diutil.h"
#include "dcmtk/dcmnet/dimse.h"
#include "dcmtk/dcmnet/dcasccff.h"
#include "dcmtk/dcmdata/dcfilefo.h"
#include "dcmtk/dcmdata/dcdeftag.h"
#include "dcmtk/dcmdata/dcxfer.h"
#include "dcmtk/dcmdata/dcuid.h"
#include <QSet>
#include <QFileInfo>
#include <QDir>
#include <vector>
#include <cstring>

SCUWorker::SCUWorker(QObject* parent)
    : QObject(parent)
{
}

void SCUWorker::sendFile(const SCUConfig& config)
{
    int totalFiles = config.dcmFiles.size();
    if (totalFiles == 0) {
        emit sendFinished(false, "未选择任何 DICOM 文件");
        return;
    }

    emit logMessage(QString("初始化 DCMTK 网络层...（共 %1 个文件）").arg(totalFiles));

    T_ASC_Network* net = NULL;
    T_ASC_Association* assoc = NULL;

    // 1. 初始化网络
    OFCondition cond = ASC_initializeNetwork(NET_REQUESTOR, 0, 1000, &net);
    if (cond.bad()) {
        emit sendFinished(false, QString("网络初始化失败: %1").arg(cond.text()));
        return;
    }
    emit logMessage("[OK] 网络层初始化成功");

    // 2. 设置 TLS
    cond = TlsHelper::setupTLS(net, NET_REQUESTOR,
                               config.certFile.c_str(),
                               config.keyFile.c_str(),
                               config.caFile.c_str(),
                               true);
    if (cond.bad()) {
        emit sendFinished(false, QString("TLS 初始化失败: %1").arg(cond.text()));
        ASC_dropNetwork(&net);
        return;
    }
    emit logMessage("[OK] TLS 加密传输层初始化成功（双向认证）");

    // 3. 预扫描所有文件，收集 SOP Class UID（用于提议 Presentation Context）
    emit sendProgress(QString("扫描 %1 个 DICOM 文件...").arg(totalFiles));
    struct FileInfo {
        QString   path;
        OFString  sopClassUID;
        OFString  sopInstanceUID;
        bool      loaded;
    };
    QList<FileInfo> fileInfos;
    QSet<QString> sopClassSet;

    for (int i = 0; i < totalFiles; i++) {
        FileInfo fi;
        fi.path = config.dcmFiles[i];
        fi.loaded = false;

        DcmFileFormat ff;
        if (ff.loadFile(fi.path.toLocal8Bit().constData()).good()) {
            DcmDataset* ds = ff.getDataset();
            ds->findAndGetOFString(DCM_SOPClassUID, fi.sopClassUID);
            ds->findAndGetOFString(DCM_SOPInstanceUID, fi.sopInstanceUID);
            fi.loaded = true;
            sopClassSet.insert(QString::fromUtf8(fi.sopClassUID.c_str()));
        } else {
            emit logMessage(QString("[WARN] 跳过无法加载的文件: %1").arg(fi.path));
        }
        fileInfos.append(fi);
    }

    int loadableCount = sopClassSet.size();
    if (loadableCount == 0) {
        emit sendFinished(false, "没有可发送的有效 DICOM 文件");
        ASC_dropNetwork(&net);
        return;
    }

    // 4. 建立 Association（一次性提议所有 SOP Class 的 Presentation Context）
    emit sendProgress("建立 TLS 加密的 DICOM Association...");
    T_ASC_Parameters* params;
    cond = ASC_createAssociationParameters(&params, config.maxPDULength);
    if (cond.bad()) {
        ASC_dropNetwork(&net);
        emit sendFinished(false, QString("创建参数失败: %1").arg(cond.text()));
        return;
    }

    ASC_setTransportLayerType(params, OFTrue);
    ASC_setAPTitles(params, config.ourAETitle.c_str(), config.peerAETitle.c_str(), NULL);

    OFString peerAddress = config.peerHost;
    peerAddress += ":";
    peerAddress += OFString(std::to_string(config.peerPort).c_str());
    ASC_setPresentationAddresses(params, NULL, peerAddress.c_str());

    // 按优先级提议多个传输语法，对端选择第一个支持的
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
    int pcID = 1;
    for (const QString& uid : sopClassSet) {
        ASC_addPresentationContext(params, pcID, uid.toUtf8().constData(),
                                   transferSyntaxes, ASC_SC_ROLE_DEFAULT);
        pcID += 2; // Presentation Context ID 必须为奇数
    }

    emit logMessage(QString("连接 %1:%2 (本地 AE: %3, 远端 AE: %4)")
        .arg(config.peerHost.c_str()).arg(config.peerPort)
        .arg(config.ourAETitle.c_str()).arg(config.peerAETitle.c_str()));

    cond = ASC_requestAssociation(net, params, &assoc);
    if (cond.bad()) {
        QString err = QString("Association 建立失败: %1").arg(cond.text());
        if (cond == DUL_ASSOCIATIONREJECTED) {
            T_ASC_RejectParameters rej;
            ASC_getRejectParameters(params, &rej);
            OFString rejStr;
            ASC_printRejectParameters(rejStr, &rej);
            err += "\n" + QString::fromUtf8(rejStr.c_str());
        }
        ASC_destroyAssociationParameters(&params);
        ASC_dropNetwork(&net);
        emit sendFinished(false, err);
        return;
    }
    emit logMessage("[OK] Association 建立成功（TLS 加密通道）");

    // 5. 循环发送每个文件（复用同一 Association）
    int successCount = 0;
    int failCount = 0;

    for (int i = 0; i < fileInfos.size(); i++) {
        FileInfo& fi = fileInfos[i];
        emit fileProgress(i + 1, totalFiles);
        emit sendProgress(QString("发送 %1/%2: %3").arg(i + 1).arg(totalFiles)
                              .arg(QFileInfo(fi.path).fileName()));

        if (!fi.loaded) {
            failCount++;
            continue;
        }

        // 找到该 SOP Class 对应的 Presentation Context ID
        T_ASC_PresentationContextID presID =
            ASC_findAcceptedPresentationContextID(assoc, fi.sopClassUID.c_str());
        if (presID == 0) {
            emit logMessage(QString("[WARN] 文件 %1 的 SOP Class 未被接受，跳过")
                .arg(QFileInfo(fi.path).fileName()));
            failCount++;
            continue;
        }

        // 重新加载文件获取 dataset
        DcmFileFormat ff;
        if (ff.loadFile(fi.path.toLocal8Bit().constData()).bad()) {
            failCount++;
            continue;
        }
        DcmDataset* dataset = ff.getAndRemoveDataset();

        // 构造 C-STORE 请求
        T_DIMSE_C_StoreRQ req;
        memset(&req, 0, sizeof(req));
        req.MessageID = assoc->nextMsgID++;
        strncpy(req.AffectedSOPClassUID, fi.sopClassUID.c_str(), DIC_UI_LEN);
        strncpy(req.AffectedSOPInstanceUID, fi.sopInstanceUID.c_str(), DIC_UI_LEN);
        req.Priority = DIMSE_PRIORITY_MEDIUM;
        req.DataSetType = DIMSE_DATASET_PRESENT;

        emit logMessage(QString("  [%1/%2] MsgID=%3, SOP Instance: %4")
            .arg(i + 1).arg(totalFiles).arg(req.MessageID).arg(fi.sopInstanceUID.c_str()));

        T_DIMSE_C_StoreRSP rsp;
        DcmDataset* statusDetail = NULL;

        cond = DIMSE_storeUser(assoc, presID, &req, NULL, dataset, NULL, NULL,
                               DIMSE_BLOCKING, 30, &rsp, &statusDetail);

        if (cond.good() && rsp.DimseStatus == STATUS_Success) {
            successCount++;
            emit logMessage(QString("  [OK] 响应: 0x%1 (成功), rspMsgId=%2")
                .arg((int)rsp.DimseStatus, 0, 16).arg(rsp.MessageIDBeingRespondedTo));
        } else {
            failCount++;
            if (cond.bad()) {
                emit logMessage(QString("  [ERROR] 发送失败: %1 (reqMsgId=%2, rspMsgId=%3)")
                    .arg(cond.text()).arg(req.MessageID).arg(rsp.MessageIDBeingRespondedTo));
            } else {
                emit logMessage(QString("  [WARN] 响应: 0x%1 (rspMsgId=%2)")
                    .arg((int)rsp.DimseStatus, 0, 16).arg(rsp.MessageIDBeingRespondedTo));
            }
        }

        if (statusDetail) delete statusDetail;
        delete dataset;
    }

    // 6. 释放 Association（所有文件发送完毕后统一释放）
    emit sendProgress("释放 Association...");
    cond = ASC_releaseAssociation(assoc);
    if (cond.bad()) {
        ASC_abortAssociation(assoc);
    }
    ASC_destroyAssociation(&assoc);
    ASC_dropNetwork(&net);

    // 7. 返回汇总结果
    QString result = QString("完成: 成功 %1 个, 失败 %2 个 (共 %3 个)")
        .arg(successCount).arg(failCount).arg(totalFiles);
    if (failCount == 0) {
        emit sendFinished(true, result);
    } else if (successCount > 0) {
        emit sendFinished(true, result + "（部分成功）");
    } else {
        emit sendFinished(false, result);
    }
}

// ============================================================
//  C-FIND User 回调：收集 Pending 响应到 results 向量
// ============================================================
static void guiFindUserCallback(
    void* callbackData,
    T_DIMSE_C_FindRQ* /*request*/,
    int /*responseCount*/,
    T_DIMSE_C_FindRSP* response,
    DcmDataset* responseIdentifiers)
{
    if (response->DimseStatus != STATUS_Pending || responseIdentifiers == NULL)
        return;

    QList<FindResult>* results = static_cast<QList<FindResult>*>(callbackData);

    FindResult rec;
    OFString val;
    if (responseIdentifiers->findAndGetOFString(DCM_PatientID, val).good())
        rec.patientID = QString::fromUtf8(val.c_str());
    if (responseIdentifiers->findAndGetOFString(DCM_PatientName, val).good())
        rec.patientName = QString::fromUtf8(val.c_str());
    if (responseIdentifiers->findAndGetOFString(DCM_StudyInstanceUID, val).good())
        rec.studyInstanceUID = QString::fromUtf8(val.c_str());
    if (responseIdentifiers->findAndGetOFString(DCM_StudyDate, val).good())
        rec.studyDate = QString::fromUtf8(val.c_str());
    if (responseIdentifiers->findAndGetOFString(DCM_ModalitiesInStudy, val).good())
        rec.modalitiesInStudy = QString::fromUtf8(val.c_str());
    if (responseIdentifiers->findAndGetOFString(DCM_StudyDescription, val).good())
        rec.studyDescription = QString::fromUtf8(val.c_str());
    if (responseIdentifiers->findAndGetOFString(DCM_SeriesInstanceUID, val).good())
        rec.seriesInstanceUID = QString::fromUtf8(val.c_str());
    if (responseIdentifiers->findAndGetOFString(DCM_SeriesNumber, val).good())
        rec.seriesNumber = QString::fromUtf8(val.c_str());
    if (responseIdentifiers->findAndGetOFString(DCM_Modality, val).good())
        rec.modality = QString::fromUtf8(val.c_str());
    if (responseIdentifiers->findAndGetOFString(DCM_SeriesDescription, val).good())
        rec.seriesDescription = QString::fromUtf8(val.c_str());
    if (responseIdentifiers->findAndGetOFString(DCM_SOPInstanceUID, val).good())
        rec.sopInstanceUID = QString::fromUtf8(val.c_str());
    if (responseIdentifiers->findAndGetOFString(DCM_SOPClassUID, val).good())
        rec.sopClassUID = QString::fromUtf8(val.c_str());
    if (responseIdentifiers->findAndGetOFString(DCM_InstanceNumber, val).good())
        rec.instanceNumber = QString::fromUtf8(val.c_str());

    results->append(rec);
}

// ============================================================
//  C-FIND 查询实现
// ============================================================
void SCUWorker::findStudies(const SCUConfig& config,
                            const QString& queryLevel,
                            const QString& patientID,
                            const QString& studyDate,
                            const QString& modality)
{
    emit logMessage(QString("[C-FIND] 开始查询 (Level=%1, PatientID=%2, StudyDate=%3, Modality=%4)")
        .arg(queryLevel)
        .arg(patientID.isEmpty() ? "*" : patientID)
        .arg(studyDate.isEmpty() ? "*" : studyDate)
        .arg(modality.isEmpty() ? "*" : modality));

    T_ASC_Network* net = NULL;
    T_ASC_Association* assoc = NULL;

    // 1. 初始化网络
    OFCondition cond = ASC_initializeNetwork(NET_REQUESTOR, 0, 1000, &net);
    if (cond.bad()) {
        emit findFinished(false, QString("网络初始化失败: %1").arg(cond.text()), QList<FindResult>());
        return;
    }

    // 2. 设置 TLS
    cond = TlsHelper::setupTLS(net, NET_REQUESTOR,
                               config.certFile.c_str(),
                               config.keyFile.c_str(),
                               config.caFile.c_str(),
                               true);
    if (cond.bad()) {
        ASC_dropNetwork(&net);
        emit findFinished(false, QString("TLS 初始化失败: %1").arg(cond.text()), QList<FindResult>());
        return;
    }

    // 3. 提议 FIND Study Root Presentation Context
    T_ASC_Parameters* params;
    cond = ASC_createAssociationParameters(&params, config.maxPDULength);
    if (cond.bad()) {
        ASC_dropNetwork(&net);
        emit findFinished(false, QString("创建参数失败: %1").arg(cond.text()), QList<FindResult>());
        return;
    }

    ASC_setTransportLayerType(params, OFTrue);
    ASC_setAPTitles(params, config.ourAETitle.c_str(), config.peerAETitle.c_str(), NULL);

    OFString peerAddress = config.peerHost;
    peerAddress += ":";
    peerAddress += OFString(std::to_string(config.peerPort).c_str());
    ASC_setPresentationAddresses(params, NULL, peerAddress.c_str());

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
        emit findFinished(false, QString("添加 PC 失败: %1").arg(cond.text()), QList<FindResult>());
        return;
    }

    emit logMessage(QString("[C-FIND] 连接 %1:%2 (本地 AE: %3, 远端 AE: %4)")
        .arg(config.peerHost.c_str()).arg(config.peerPort)
        .arg(config.ourAETitle.c_str()).arg(config.peerAETitle.c_str()));

    cond = ASC_requestAssociation(net, params, &assoc);
    if (cond.bad()) {
        ASC_destroyAssociationParameters(&params);
        ASC_dropNetwork(&net);
        emit findFinished(false, QString("Association 建立失败: %1").arg(cond.text()), QList<FindResult>());
        return;
    }

    T_ASC_PresentationContextID presID =
        ASC_findAcceptedPresentationContextID(assoc, UID_FINDStudyRootQueryRetrieveInformationModel);
    if (presID == 0) {
        ASC_releaseAssociation(assoc);
        ASC_destroyAssociation(&assoc);
        ASC_dropNetwork(&net);
        emit findFinished(false, "FIND Study Root PC 未被接受", QList<FindResult>());
        return;
    }

    // 4. 构建查询标识符
    DcmDataset* reqIds = new DcmDataset();
    reqIds->putAndInsertString(DCM_QueryRetrieveLevel, queryLevel.toUtf8().constData());
    if (!patientID.isEmpty())
        reqIds->putAndInsertString(DCM_PatientID, patientID.toUtf8().constData());
    if (!studyDate.isEmpty())
        reqIds->putAndInsertString(DCM_StudyDate, studyDate.toUtf8().constData());
    if (!modality.isEmpty())
        reqIds->putAndInsertString(DCM_Modality, modality.toUtf8().constData());

    // 5. 填充 C-FIND 请求
    T_DIMSE_C_FindRQ rq;
    memset(&rq, 0, sizeof(rq));
    rq.MessageID = assoc->nextMsgID++;
    strncpy(rq.AffectedSOPClassUID, UID_FINDStudyRootQueryRetrieveInformationModel, DIC_UI_LEN);
    rq.Priority = DIMSE_PRIORITY_MEDIUM;
    rq.DataSetType = DIMSE_DATASET_PRESENT;

    // 6. 执行 C-FIND
    QList<FindResult> results;
    int responseCount = 0;
    T_DIMSE_C_FindRSP rsp;
    DcmDataset* statusDetail = NULL;

    cond = DIMSE_findUser(
        assoc, presID, &rq, reqIds,
        responseCount,
        guiFindUserCallback, &results,
        DIMSE_BLOCKING, 30,
        &rsp, &statusDetail);

    delete reqIds;

    if (cond.bad()) {
        if (statusDetail) delete statusDetail;
        ASC_releaseAssociation(assoc);
        ASC_destroyAssociation(&assoc);
        ASC_dropNetwork(&net);
        emit findFinished(false, QString("C-FIND 失败: %1").arg(cond.text()), results);
        return;
    }

    QString msg = QString("查询完成，匹配 %1 条记录").arg(results.size());
    emit logMessage(QString("[C-FIND] %1").arg(msg));

    if (statusDetail) delete statusDetail;

    // 7. 释放 Association
    ASC_releaseAssociation(assoc);
    ASC_destroyAssociation(&assoc);
    ASC_dropNetwork(&net);

    emit findFinished(true, msg, results);
}

// ============================================================
//  C-MOVE User：子关联接收回调数据
// ============================================================
struct GuiSubOpCallbackData {
    OFString outputDir;
    int receivedCount;
};

// 子关联回调：接受子关联并接收 C-STORE 子操作
static void guiSubOpProviderCallback(
    void* subOpCallbackData,
    T_ASC_Network* net,
    T_ASC_Association** subOpAssoc)
{
    GuiSubOpCallbackData* cbdata = static_cast<GuiSubOpCallbackData*>(subOpCallbackData);

    OFCondition cond = ASC_receiveAssociation(net, subOpAssoc, ASC_DEFAULTMAXPDU,
                                              NULL, NULL, OFTrue);
    if (cond.bad()) {
        return;
    }

    // 接受所有提议的 Presentation Context
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
        ASC_destroyAssociation(subOpAssoc);
        return;
    }

    // 循环接收 C-STORE 命令
    while (true) {
        T_DIMSE_Message msg;
        T_ASC_PresentationContextID presID = 0;
        cond = DIMSE_receiveCommand(*subOpAssoc, DIMSE_BLOCKING, 30, &presID, &msg, NULL);
        if (cond.bad()) break;

        if (msg.CommandField != DIMSE_C_STORE_RQ) break;

        T_DIMSE_C_StoreRQ* rq = &msg.msg.CStoreRQ;
        DcmDataset* dataset = NULL;

        cond = DIMSE_storeProvider(*subOpAssoc, presID, rq, NULL, 0, &dataset,
            [](void* cbd, T_DIMSE_StoreProgress* prog,
               T_DIMSE_C_StoreRQ*, char*, DcmDataset** ds,
               T_DIMSE_C_StoreRSP* rsp, DcmDataset**) {
            if (prog->state != DIMSE_StoreEnd) return;
            GuiSubOpCallbackData* c = static_cast<GuiSubOpCallbackData*>(cbd);
            if (!ds || !*ds) {
                rsp->DimseStatus = STATUS_STORE_Refused_OutOfResources;
                return;
            }
            OFString uid;
            (*ds)->findAndGetOFString(DCM_SOPInstanceUID, uid);
            std::string path = std::string(c->outputDir.c_str()) + "/" + uid.c_str() + ".dcm";
            DcmFileFormat ff(*ds);
            if (ff.saveFile(path.c_str(), (*ds)->getCurrentXfer()).good()) {
                rsp->DimseStatus = STATUS_Success;
            } else {
                rsp->DimseStatus = STATUS_STORE_Refused_OutOfResources;
            }
        }, cbdata, DIMSE_BLOCKING, 30);

        if (cond.good()) {
            cbdata->receivedCount++;
        }

        if (dataset) delete dataset;
    }

    ASC_releaseAssociation(*subOpAssoc);
    ASC_destroyAssociation(subOpAssoc);
}

// C-MOVE User 回调：跟踪响应计数
static void guiMoveUserCallback(
    void* /*callbackData*/,
    T_DIMSE_C_MoveRQ* /*request*/,
    int /*responseCount*/,
    T_DIMSE_C_MoveRSP* /*response*/)
{
    // pending 响应，不做处理（最终响应由 DIMSE_moveUser 返回的 rsp 提供）
}

// ============================================================
//  C-MOVE 检索实现
// ============================================================
void SCUWorker::moveStudies(const SCUConfig& config,
                            const QString& moveDestinationAE,
                            quint16 listenPort,
                            const QString& outputDir,
                            const QString& patientID,
                            const QString& studyInstanceUID)
{
    emit logMessage(QString("[C-MOVE] 开始检索 (MoveDest=%1, ListenPort=%2, OutputDir=%3)")
        .arg(moveDestinationAE).arg(listenPort).arg(outputDir));

    // 确保输出目录存在
    QDir dir;
    if (!dir.mkpath(outputDir)) {
        emit moveFinished(false, QString("无法创建输出目录: %1").arg(outputDir), 0);
        return;
    }

    T_ASC_Network* net = NULL;          // 主关联网络（SCU 角色）
    T_ASC_Association* assoc = NULL;

    // 1. 初始化主网络
    OFCondition cond = ASC_initializeNetwork(NET_REQUESTOR, 0, 1000, &net);
    if (cond.bad()) {
        emit moveFinished(false, QString("网络初始化失败: %1").arg(cond.text()), 0);
        return;
    }

    // 2. 设置主关联 TLS（客户端模式）
    cond = TlsHelper::setupTLS(net, NET_REQUESTOR,
                               config.certFile.c_str(),
                               config.keyFile.c_str(),
                               config.caFile.c_str(),
                               true);
    if (cond.bad()) {
        ASC_dropNetwork(&net);
        emit moveFinished(false, QString("TLS 初始化失败: %1").arg(cond.text()), 0);
        return;
    }

    // 3. 建立主关联
    T_ASC_Parameters* params;
    cond = ASC_createAssociationParameters(&params, config.maxPDULength);
    if (cond.bad()) {
        ASC_dropNetwork(&net);
        emit moveFinished(false, QString("创建参数失败: %1").arg(cond.text()), 0);
        return;
    }

    ASC_setTransportLayerType(params, OFTrue);
    ASC_setAPTitles(params, config.ourAETitle.c_str(), config.peerAETitle.c_str(), NULL);

    OFString peerAddress = config.peerHost;
    peerAddress += ":";
    peerAddress += OFString(std::to_string(config.peerPort).c_str());
    ASC_setPresentationAddresses(params, NULL, peerAddress.c_str());

    const char* moveTransferSyntaxes[] = {
        UID_LittleEndianImplicitTransferSyntax,
        NULL
    };

    cond = ASC_addPresentationContext(
        params, 1,
        UID_MOVEStudyRootQueryRetrieveInformationModel,
        moveTransferSyntaxes, ASC_SC_ROLE_DEFAULT);
    if (cond.bad()) {
        ASC_destroyAssociationParameters(&params);
        ASC_dropNetwork(&net);
        emit moveFinished(false, QString("添加 PC 失败: %1").arg(cond.text()), 0);
        return;
    }

    emit logMessage(QString("[C-MOVE] 连接 %1:%2").arg(config.peerHost.c_str()).arg(config.peerPort));

    cond = ASC_requestAssociation(net, params, &assoc);
    if (cond.bad()) {
        ASC_destroyAssociationParameters(&params);
        ASC_dropNetwork(&net);
        emit moveFinished(false, QString("Association 建立失败: %1").arg(cond.text()), 0);
        return;
    }

    T_ASC_PresentationContextID presID =
        ASC_findAcceptedPresentationContextID(assoc, UID_MOVEStudyRootQueryRetrieveInformationModel);
    if (presID == 0) {
        ASC_releaseAssociation(assoc);
        ASC_destroyAssociation(&assoc);
        ASC_dropNetwork(&net);
        emit moveFinished(false, "MOVE Study Root PC 未被接受", 0);
        return;
    }

    // 4. 初始化子关联监听网络（SCU 作为存储 SCP 接收回传）
    T_ASC_Network* subNet = NULL;
    cond = ASC_initializeNetwork(NET_ACCEPTOR, listenPort, 1000, &subNet);
    if (cond.bad()) {
        ASC_releaseAssociation(assoc);
        ASC_destroyAssociation(&assoc);
        ASC_dropNetwork(&net);
        emit moveFinished(false, QString("子监听网络初始化失败: %1").arg(cond.text()), 0);
        return;
    }

    // 子关联使用服务端 TLS（接收 SCP 回连）
    cond = TlsHelper::setupTLS(subNet, NET_ACCEPTOR,
                               config.certFile.c_str(),
                               config.keyFile.c_str(),
                               config.caFile.c_str(),
                               true);
    if (cond.bad()) {
        ASC_dropNetwork(&subNet);
        ASC_releaseAssociation(assoc);
        ASC_destroyAssociation(&assoc);
        ASC_dropNetwork(&net);
        emit moveFinished(false, QString("子关联 TLS 初始化失败: %1").arg(cond.text()), 0);
        return;
    }

    // 5. 构建 C-MOVE 请求标识符
    DcmDataset* reqIds = new DcmDataset();
    reqIds->putAndInsertString(DCM_QueryRetrieveLevel, "STUDY");
    if (!patientID.isEmpty())
        reqIds->putAndInsertString(DCM_PatientID, patientID.toUtf8().constData());
    if (!studyInstanceUID.isEmpty())
        reqIds->putAndInsertString(DCM_StudyInstanceUID, studyInstanceUID.toUtf8().constData());

    T_DIMSE_C_MoveRQ rq;
    memset(&rq, 0, sizeof(rq));
    rq.MessageID = assoc->nextMsgID++;
    strncpy(rq.AffectedSOPClassUID, UID_MOVEStudyRootQueryRetrieveInformationModel, DIC_UI_LEN);
    strncpy(rq.MoveDestination, moveDestinationAE.toUtf8().constData(), DIC_AE_LEN);
    rq.Priority = DIMSE_PRIORITY_MEDIUM;
    rq.DataSetType = DIMSE_DATASET_PRESENT;

    // 6. 执行 C-MOVE
    GuiSubOpCallbackData subOpData;
    subOpData.outputDir = outputDir.toUtf8().constData();
    subOpData.receivedCount = 0;

    int responseCount = 0;
    T_DIMSE_C_MoveRSP rsp;
    DcmDataset* statusDetail = NULL;
    DcmDataset* responseIds = NULL;

    cond = DIMSE_moveUser(
        assoc, presID, &rq, reqIds,
        guiMoveUserCallback, NULL,
        DIMSE_BLOCKING, 60,
        subNet,
        guiSubOpProviderCallback, &subOpData,
        &rsp, &statusDetail, &responseIds);

    delete reqIds;
    if (statusDetail) delete statusDetail;
    if (responseIds) delete responseIds;

    // 7. 释放子关联网络
    ASC_dropNetwork(&subNet);

    // 8. 释放主关联
    ASC_releaseAssociation(assoc);
    ASC_destroyAssociation(&assoc);
    ASC_dropNetwork(&net);

    // 9. 返回结果
    if (cond.bad()) {
        emit moveFinished(false, QString("C-MOVE 失败: %1").arg(cond.text()), subOpData.receivedCount);
    } else {
        QString msg = QString("检索完成: completed=%1, failed=%2, warning=%3, 实际接收 %4 个文件")
            .arg(rsp.NumberOfCompletedSubOperations)
            .arg(rsp.NumberOfFailedSubOperations)
            .arg(rsp.NumberOfWarningSubOperations)
            .arg(subOpData.receivedCount);
        emit logMessage(QString("[C-MOVE] %1").arg(msg));
        emit moveFinished(true, msg, subOpData.receivedCount);
    }
}
