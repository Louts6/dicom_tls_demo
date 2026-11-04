// ============================================================
//  SCP Worker - 在后台线程运行 DICOM TLS Storage SCP
//  通过信号通知 UI 层日志和接收到的文件
// ============================================================
#ifndef SCP_WORKER_H
#define SCP_WORKER_H

#include <QObject>
#include <QString>
#include "dcmtk/config/osconfig.h"
#include "../common/tls_config.h"
#include "../common/dicom_index.h"

class SCPWorker : public QObject
{
    Q_OBJECT

public:
    explicit SCPWorker(QObject* parent = nullptr);
    ~SCPWorker();

public slots:
    // 启动 SCP 服务（在工作线程中执行）
    void startServer(const SCPConfig& config);

    // 请求停止服务
    void stopServer();

signals:
    // 日志消息
    void logMessage(const QString& msg);

    // 接收到新的 DICOM 文件
    void fileReceived(const QString& filePath);

    // 服务状态变化
    void serverStarted();
    void serverStopped();
    void serverError(const QString& errorMsg);

private:
    volatile bool m_running;
    DicomIndex m_index;   // DICOM 文件索引（SQLite），支持 C-FIND 查询
};

#endif // SCP_WORKER_H
