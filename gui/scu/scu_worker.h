// ============================================================
//  SCU Worker - 在后台线程执行 DICOM TLS C-STORE 发送 / C-FIND 查询
// ============================================================
#ifndef SCU_WORKER_H
#define SCU_WORKER_H

#include <QObject>
#include <QString>
#include <QList>
#include <QMetaType>
#include "dcmtk/config/osconfig.h"
#include "../common/tls_config.h"

// C-FIND 查询结果（单条记录）
struct FindResult {
    QString patientID;
    QString patientName;
    QString studyInstanceUID;
    QString studyDate;
    QString modalitiesInStudy;
    QString studyDescription;
    QString seriesInstanceUID;
    QString seriesNumber;
    QString modality;
    QString seriesDescription;
    QString sopInstanceUID;
    QString sopClassUID;
    QString instanceNumber;
};

Q_DECLARE_METATYPE(FindResult)
Q_DECLARE_METATYPE(QList<FindResult>)

class SCUWorker : public QObject
{
    Q_OBJECT

public:
    explicit SCUWorker(QObject* parent = nullptr);

public slots:
    void sendFile(const SCUConfig& config);

    // C-FIND 查询（Study Root）
    void findStudies(const SCUConfig& config,
                     const QString& queryLevel,    // "PATIENT"/"STUDY"/"SERIES"/"IMAGE"
                     const QString& patientID,
                     const QString& studyDate,
                     const QString& modality);

    // C-MOVE 检索（Study Root）
    void moveStudies(const SCUConfig& config,
                     const QString& moveDestinationAE,
                     quint16 listenPort,
                     const QString& outputDir,
                     const QString& patientID,
                     const QString& studyInstanceUID);

signals:
    void logMessage(const QString& msg);
    void sendFinished(bool success, const QString& message);
    void sendProgress(const QString& step);
    // 文件级进度：当前文件序号 / 总文件数
    void fileProgress(int current, int total);

    // C-FIND 查询完成（返回匹配记录列表）
    void findFinished(bool success, const QString& message, const QList<FindResult>& results);

    // C-MOVE 检索完成
    void moveFinished(bool success, const QString& message, int receivedCount);
};

#endif // SCU_WORKER_H
