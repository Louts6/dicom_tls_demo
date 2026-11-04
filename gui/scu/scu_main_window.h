// ============================================================
//  SCU 客户端主窗口 - 配置 + 文件选择 + 发送 + 查询检索 + 日志
// ============================================================
#ifndef SCU_MAIN_WINDOW_H
#define SCU_MAIN_WINDOW_H

#include <QMainWindow>
#include <QThread>
#include <QSettings>
#include <QCloseEvent>
#include "scu_worker.h"
#include "../common/tls_config.h"

class QLineEdit;
class QPushButton;
class QTextEdit;
class QLabel;
class QProgressBar;
class QGroupBox;
class QListWidget;
class QComboBox;
class QTableWidget;

class SCUMainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit SCUMainWindow(QWidget* parent = nullptr);
    ~SCUMainWindow();

private slots:
    void onSend();
    void onBrowseDcmFile();
    void onRemoveDcmFile();
    void onBrowseCert();
    void onBrowseKey();
    void onBrowseCA();
    void onLogMessage(const QString& msg);
    void onSendFinished(bool success, const QString& message);
    void onSendProgress(const QString& step);
    void onFileProgress(int current, int total);
    // C-FIND
    void onFind();
    void onFindFinished(bool success, const QString& message, const QList<FindResult>& results);
    // C-MOVE
    void onMove();
    void onBrowseMoveOutputDir();
    void onMoveFinished(bool success, const QString& message, int receivedCount);
    // 配置持久化
    void onRestoreDefaults();

private:
    void setupUI();
    SCUConfig getConfig() const;
    void setControlsEnabled(bool enabled);
    QGroupBox* createConfigGroup();
    QGroupBox* createFileGroup();
    QGroupBox* createFindGroup();
    QGroupBox* createMoveGroup();
    QWidget* createLogPanel();
    // 配置持久化
    void loadSettings();
    void saveSettings();
    void closeEvent(QCloseEvent* event) override;

    // 网络配置
    QLineEdit* m_hostEdit;
    QLineEdit* m_portEdit;
    QLineEdit* m_ourAETitleEdit;
    QLineEdit* m_peerAETitleEdit;

    // 证书配置
    QLineEdit* m_certEdit;
    QLineEdit* m_keyEdit;
    QLineEdit* m_caEdit;

    // 文件列表
    QListWidget* m_dcmFileList;

    // 发送按钮和进度
    QPushButton* m_sendBtn;
    QProgressBar* m_progressBar;
    QLabel* m_statusLabel;

    // C-FIND 控件
    QComboBox* m_findLevelCombo;
    QLineEdit* m_findPatientIDEdit;
    QLineEdit* m_findStudyDateEdit;
    QLineEdit* m_findModalityEdit;
    QPushButton* m_findBtn;
    QTableWidget* m_findResultsTable;

    // C-MOVE 控件
    QLineEdit* m_moveDestAEEdit;
    QLineEdit* m_moveListenPortEdit;
    QLineEdit* m_moveOutputDirEdit;
    QLineEdit* m_movePatientIDEdit;
    QLineEdit* m_moveStudyUIDEdit;
    QPushButton* m_moveBtn;

    // 日志
    QTextEdit* m_logEdit;

    // 工作线程
    QThread* m_workerThread;
    SCUWorker* m_worker;
};

#endif // SCU_MAIN_WINDOW_H
