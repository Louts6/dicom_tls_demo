// ============================================================
//  SCU 客户端主窗口实现
// ============================================================
#include "scu_main_window.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QGroupBox>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QTextEdit>
#include <QFileDialog>
#include <QMessageBox>
#include <QProgressBar>
#include <QDateTime>
#include <QListWidget>
#include <QFileInfo>
#include <QComboBox>
#include <QTableWidget>
#include <QHeaderView>

SCUMainWindow::SCUMainWindow(QWidget* parent)
    : QMainWindow(parent)
    , m_workerThread(nullptr)
    , m_worker(nullptr)
{
    setupUI();
    loadSettings();
    setWindowTitle("DICOM TLS Storage SCU - 客户端");
    resize(750, 650);
}

SCUMainWindow::~SCUMainWindow()
{
    if (m_workerThread) {
        m_workerThread->quit();
        m_workerThread->wait();
    }
}

void SCUMainWindow::setupUI()
{
    QWidget* central = new QWidget(this);
    setCentralWidget(central);

    QVBoxLayout* mainLayout = new QVBoxLayout(central);

    // 网络配置
    mainLayout->addWidget(createConfigGroup());

    // 证书配置
    QGroupBox* certGroup = new QGroupBox("TLS 证书配置", this);
    QGridLayout* certLayout = new QGridLayout(certGroup);

    certLayout->addWidget(new QLabel("客户端证书:"), 0, 0);
    m_certEdit = new QLineEdit("certs/client.crt", this);
    QPushButton* browseCertBtn = new QPushButton("浏览...", this);
    connect(browseCertBtn, &QPushButton::clicked, this, &SCUMainWindow::onBrowseCert);
    QHBoxLayout* c1 = new QHBoxLayout();
    c1->addWidget(m_certEdit);
    c1->addWidget(browseCertBtn);
    certLayout->addLayout(c1, 0, 1);

    certLayout->addWidget(new QLabel("客户端私钥:"), 1, 0);
    m_keyEdit = new QLineEdit("certs/client.key", this);
    QPushButton* browseKeyBtn = new QPushButton("浏览...", this);
    connect(browseKeyBtn, &QPushButton::clicked, this, &SCUMainWindow::onBrowseKey);
    QHBoxLayout* c2 = new QHBoxLayout();
    c2->addWidget(m_keyEdit);
    c2->addWidget(browseKeyBtn);
    certLayout->addLayout(c2, 1, 1);

    certLayout->addWidget(new QLabel("CA 根证书:"), 2, 0);
    m_caEdit = new QLineEdit("certs/ca.crt", this);
    QPushButton* browseCABtn = new QPushButton("浏览...", this);
    connect(browseCABtn, &QPushButton::clicked, this, &SCUMainWindow::onBrowseCA);
    QHBoxLayout* c3 = new QHBoxLayout();
    c3->addWidget(m_caEdit);
    c3->addWidget(browseCABtn);
    certLayout->addLayout(c3, 2, 1);

    mainLayout->addWidget(certGroup);

    // 文件选择
    mainLayout->addWidget(createFileGroup());

    // C-FIND 查询
    mainLayout->addWidget(createFindGroup());

    // C-MOVE 检索
    mainLayout->addWidget(createMoveGroup());

    // 发送按钮和进度
    QHBoxLayout* sendLayout = new QHBoxLayout();
    m_sendBtn = new QPushButton("发送 DICOM 文件", this);
    m_sendBtn->setMinimumHeight(40);
    m_sendBtn->setStyleSheet("background-color: #2196F3; color: white; font-weight: bold; font-size: 14px;");
    connect(m_sendBtn, &QPushButton::clicked, this, &SCUMainWindow::onSend);
    sendLayout->addWidget(m_sendBtn);

    m_progressBar = new QProgressBar(this);
    m_progressBar->setRange(0, 0); // 不确定进度
    m_progressBar->setVisible(false);
    sendLayout->addWidget(m_progressBar, 1);
    mainLayout->addLayout(sendLayout);

    m_statusLabel = new QLabel("就绪", this);
    m_statusLabel->setStyleSheet("color: #666; padding: 4px;");
    mainLayout->addWidget(m_statusLabel);

    // 日志
    mainLayout->addWidget(createLogPanel(), 1);
}

QGroupBox* SCUMainWindow::createConfigGroup()
{
    QGroupBox* group = new QGroupBox("网络配置", this);
    QGridLayout* layout = new QGridLayout(group);

    layout->addWidget(new QLabel("服务端地址:"), 0, 0);
    m_hostEdit = new QLineEdit("127.0.0.1", this);
    layout->addWidget(m_hostEdit, 0, 1);

    layout->addWidget(new QLabel("端口:"), 0, 2);
    m_portEdit = new QLineEdit("11112", this);
    m_portEdit->setMaximumWidth(100);
    layout->addWidget(m_portEdit, 0, 3);

    layout->addWidget(new QLabel("本地 AE Title:"), 1, 0);
    m_ourAETitleEdit = new QLineEdit("TLS_SCU", this);
    layout->addWidget(m_ourAETitleEdit, 1, 1);

    layout->addWidget(new QLabel("远端 AE Title:"), 1, 2);
    m_peerAETitleEdit = new QLineEdit("TLS_SCP", this);
    layout->addWidget(m_peerAETitleEdit, 1, 3);

    // 恢复默认值按钮
    QPushButton* restoreBtn = new QPushButton("恢复默认值", this);
    restoreBtn->setStyleSheet("color: #888;");
    connect(restoreBtn, &QPushButton::clicked, this, &SCUMainWindow::onRestoreDefaults);
    layout->addWidget(restoreBtn, 2, 0);

    return group;
}

QGroupBox* SCUMainWindow::createFileGroup()
{
    QGroupBox* group = new QGroupBox("DICOM 文件（支持多选，复用同一关联批量发送）", this);
    QVBoxLayout* layout = new QVBoxLayout(group);

    m_dcmFileList = new QListWidget(this);
    m_dcmFileList->setSelectionMode(QAbstractItemView::ExtendedSelection);
    m_dcmFileList->setMaximumHeight(120);
    layout->addWidget(m_dcmFileList);

    QHBoxLayout* btnLayout = new QHBoxLayout();
    QPushButton* addBtn = new QPushButton("添加文件...", this);
    connect(addBtn, &QPushButton::clicked, this, &SCUMainWindow::onBrowseDcmFile);
    btnLayout->addWidget(addBtn);

    QPushButton* removeBtn = new QPushButton("移除选中", this);
    connect(removeBtn, &QPushButton::clicked, this, &SCUMainWindow::onRemoveDcmFile);
    btnLayout->addWidget(removeBtn);

    btnLayout->addStretch();
    layout->addLayout(btnLayout);

    return group;
}

QGroupBox* SCUMainWindow::createFindGroup()
{
    QGroupBox* group = new QGroupBox("C-FIND 查询（Study Root）", this);
    QGridLayout* layout = new QGridLayout(group);

    // 查询层级
    layout->addWidget(new QLabel("查询层级:"), 0, 0);
    m_findLevelCombo = new QComboBox(this);
    m_findLevelCombo->addItem("PATIENT", "PATIENT");
    m_findLevelCombo->addItem("STUDY", "STUDY");
    m_findLevelCombo->addItem("SERIES", "SERIES");
    m_findLevelCombo->addItem("IMAGE", "IMAGE");
    m_findLevelCombo->setCurrentIndex(1); // 默认 STUDY
    layout->addWidget(m_findLevelCombo, 0, 1);

    // Patient ID
    layout->addWidget(new QLabel("Patient ID:"), 0, 2);
    m_findPatientIDEdit = new QLineEdit(this);
    m_findPatientIDEdit->setPlaceholderText("* 或具体 ID");
    layout->addWidget(m_findPatientIDEdit, 0, 3);

    // Study Date
    layout->addWidget(new QLabel("检查日期:"), 1, 0);
    m_findStudyDateEdit = new QLineEdit(this);
    m_findStudyDateEdit->setPlaceholderText("YYYYMMDD 或留空");
    layout->addWidget(m_findStudyDateEdit, 1, 1);

    // Modality
    layout->addWidget(new QLabel("模态:"), 1, 2);
    m_findModalityEdit = new QLineEdit(this);
    m_findModalityEdit->setPlaceholderText("如 CT、MR 或留空");
    layout->addWidget(m_findModalityEdit, 1, 3);

    // 查询按钮
    m_findBtn = new QPushButton("查询", this);
    m_findBtn->setStyleSheet("background-color: #FF9800; color: white; font-weight: bold;");
    connect(m_findBtn, &QPushButton::clicked, this, &SCUMainWindow::onFind);
    layout->addWidget(m_findBtn, 2, 0, 1, 2);

    layout->addWidget(new QLabel("（留空表示不限定，* 为通配符）"), 2, 2, 1, 2);

    // 结果表格
    m_findResultsTable = new QTableWidget(this);
    m_findResultsTable->setColumnCount(6);
    m_findResultsTable->setHorizontalHeaderLabels(
        QStringList() << "PatientID" << "PatientName" << "StudyInstanceUID"
                      << "StudyDate" << "Modality" << "SeriesInstanceUID");
    m_findResultsTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    m_findResultsTable->setMaximumHeight(160);
    m_findResultsTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    layout->addWidget(m_findResultsTable, 3, 0, 1, 4);

    return group;
}

QGroupBox* SCUMainWindow::createMoveGroup()
{
    QGroupBox* group = new QGroupBox("C-MOVE 检索（Study Root）", this);
    QGridLayout* layout = new QGridLayout(group);

    // Move Destination AE
    layout->addWidget(new QLabel("目标 AE Title:"), 0, 0);
    m_moveDestAEEdit = new QLineEdit("TLS_SCU", this);
    layout->addWidget(m_moveDestAEEdit, 0, 1);

    // 监听端口
    layout->addWidget(new QLabel("监听端口:"), 0, 2);
    m_moveListenPortEdit = new QLineEdit("11113", this);
    m_moveListenPortEdit->setMaximumWidth(100);
    layout->addWidget(m_moveListenPortEdit, 0, 3);

    // 输出目录
    layout->addWidget(new QLabel("输出目录:"), 1, 0);
    m_moveOutputDirEdit = new QLineEdit("./retrieved", this);
    QPushButton* browseDirBtn = new QPushButton("浏览...", this);
    connect(browseDirBtn, &QPushButton::clicked, this, &SCUMainWindow::onBrowseMoveOutputDir);
    QHBoxLayout* dirLayout = new QHBoxLayout();
    dirLayout->addWidget(m_moveOutputDirEdit);
    dirLayout->addWidget(browseDirBtn);
    layout->addLayout(dirLayout, 1, 1, 1, 3);

    // Patient ID
    layout->addWidget(new QLabel("Patient ID:"), 2, 0);
    m_movePatientIDEdit = new QLineEdit(this);
    m_movePatientIDEdit->setPlaceholderText("* 或具体 ID");
    layout->addWidget(m_movePatientIDEdit, 2, 1);

    // Study UID
    layout->addWidget(new QLabel("Study UID:"), 2, 2);
    m_moveStudyUIDEdit = new QLineEdit(this);
    m_moveStudyUIDEdit->setPlaceholderText("可选，指定检查");
    layout->addWidget(m_moveStudyUIDEdit, 2, 3);

    // 检索按钮
    m_moveBtn = new QPushButton("检索", this);
    m_moveBtn->setStyleSheet("background-color: #9C27B0; color: white; font-weight: bold;");
    connect(m_moveBtn, &QPushButton::clicked, this, &SCUMainWindow::onMove);
    layout->addWidget(m_moveBtn, 3, 0, 1, 2);

    layout->addWidget(new QLabel("（SCP 将通过子关联把匹配实例 C-STORE 回传到本机）"), 4, 0, 1, 4);

    return group;
}

QWidget* SCUMainWindow::createLogPanel()
{
    QGroupBox* group = new QGroupBox("运行日志", this);
    QVBoxLayout* layout = new QVBoxLayout(group);
    m_logEdit = new QTextEdit(this);
    m_logEdit->setReadOnly(true);
    m_logEdit->setFont(QFont("Consolas", 9));
    layout->addWidget(m_logEdit);
    return group;
}

SCUConfig SCUMainWindow::getConfig() const
{
    SCUConfig config;
    config.peerHost    = m_hostEdit->text().toUtf8().constData();
    config.peerPort    = m_portEdit->text().toUShort();
    config.ourAETitle  = m_ourAETitleEdit->text().toUtf8().constData();
    config.peerAETitle = m_peerAETitleEdit->text().toUtf8().constData();
    config.certFile    = m_certEdit->text().toUtf8().constData();
    config.keyFile     = m_keyEdit->text().toUtf8().constData();
    config.caFile      = m_caEdit->text().toUtf8().constData();
    for (int i = 0; i < m_dcmFileList->count(); i++) {
        config.dcmFiles.append(m_dcmFileList->item(i)->text());
    }
    return config;
}

void SCUMainWindow::setControlsEnabled(bool enabled)
{
    m_hostEdit->setEnabled(enabled);
    m_portEdit->setEnabled(enabled);
    m_ourAETitleEdit->setEnabled(enabled);
    m_peerAETitleEdit->setEnabled(enabled);
    m_certEdit->setEnabled(enabled);
    m_keyEdit->setEnabled(enabled);
    m_caEdit->setEnabled(enabled);
    m_dcmFileList->setEnabled(enabled);
    // C-FIND / C-MOVE 控件
    m_findLevelCombo->setEnabled(enabled);
    m_findPatientIDEdit->setEnabled(enabled);
    m_findStudyDateEdit->setEnabled(enabled);
    m_findModalityEdit->setEnabled(enabled);
    m_findBtn->setEnabled(enabled);
    m_moveDestAEEdit->setEnabled(enabled);
    m_moveListenPortEdit->setEnabled(enabled);
    m_moveOutputDirEdit->setEnabled(enabled);
    m_movePatientIDEdit->setEnabled(enabled);
    m_moveStudyUIDEdit->setEnabled(enabled);
    m_moveBtn->setEnabled(enabled);
}

void SCUMainWindow::onSend()
{
    SCUConfig config = getConfig();
    if (config.peerHost.empty() || config.peerPort == 0) {
        QMessageBox::warning(this, "错误", "请填写有效的服务端地址和端口");
        return;
    }
    if (config.dcmFiles.isEmpty()) {
        QMessageBox::warning(this, "错误", "请选择至少一个 DICOM 文件");
        return;
    }

    m_logEdit->clear();
    m_sendBtn->setEnabled(false);
    m_progressBar->setVisible(true);
    m_progressBar->setRange(0, config.dcmFiles.size());
    m_progressBar->setValue(0);
    setControlsEnabled(false);
    m_statusLabel->setText(QString("正在发送 %1 个文件...").arg(config.dcmFiles.size()));

    m_workerThread = new QThread(this);
    m_worker = new SCUWorker();
    m_worker->moveToThread(m_workerThread);

    connect(m_workerThread, &QThread::started, [this, config]() {
        m_worker->sendFile(config);
    });
    connect(m_worker, &SCUWorker::logMessage, this, &SCUMainWindow::onLogMessage);
    connect(m_worker, &SCUWorker::sendProgress, this, &SCUMainWindow::onSendProgress);
    connect(m_worker, &SCUWorker::fileProgress, this, &SCUMainWindow::onFileProgress);
    connect(m_worker, &SCUWorker::sendFinished, this, &SCUMainWindow::onSendFinished);

    m_workerThread->start();
}

void SCUMainWindow::onFileProgress(int current, int total)
{
    m_progressBar->setRange(0, total);
    m_progressBar->setValue(current);
}

void SCUMainWindow::onSendProgress(const QString& step)
{
    m_statusLabel->setText(step);
}

void SCUMainWindow::onLogMessage(const QString& msg)
{
    QString timestamp = QDateTime::currentDateTime().toString("HH:mm:ss");
    m_logEdit->append(QString("[%1] %2").arg(timestamp, msg));
}

void SCUMainWindow::onSendFinished(bool success, const QString& message)
{
    m_progressBar->setVisible(false);
    m_sendBtn->setEnabled(true);
    setControlsEnabled(true);

    if (success) {
        m_statusLabel->setText(QString("✓ %1").arg(message));
        m_statusLabel->setStyleSheet("color: #4CAF50; padding: 4px; font-weight: bold;");
    } else {
        m_statusLabel->setText(QString("✗ %1").arg(message));
        m_statusLabel->setStyleSheet("color: #f44336; padding: 4px; font-weight: bold;");
    }

    // 清理线程：先调度 worker 删除，再退出线程事件循环，最后等待
    if (m_worker) {
        m_worker->deleteLater();
        m_worker = nullptr;
    }
    if (m_workerThread) {
        m_workerThread->quit();
        m_workerThread->wait();
        m_workerThread->deleteLater();
        m_workerThread = nullptr;
    }
}

// ============================================================
//  C-FIND 查询
// ============================================================
void SCUMainWindow::onFind()
{
    SCUConfig config = getConfig();
    if (config.peerHost.empty() || config.peerPort == 0) {
        QMessageBox::warning(this, "错误", "请填写有效的服务端地址和端口");
        return;
    }

    QString level = m_findLevelCombo->currentData().toString();
    // 必须在 UI 线程采集所有输入值，工作线程不得触碰 QWidget
    QString patientID = m_findPatientIDEdit->text();
    QString studyDate = m_findStudyDateEdit->text();
    QString modality = m_findModalityEdit->text();

    m_findResultsTable->setRowCount(0);
    m_findBtn->setEnabled(false);
    m_moveBtn->setEnabled(false);
    m_sendBtn->setEnabled(false);
    setControlsEnabled(false);
    m_statusLabel->setText(QString("C-FIND 查询中 (Level=%1)...").arg(level));

    m_workerThread = new QThread(this);
    m_worker = new SCUWorker();
    m_worker->moveToThread(m_workerThread);

    connect(m_workerThread, &QThread::started, [this, config, level, patientID, studyDate, modality]() {
        m_worker->findStudies(config, level, patientID, studyDate, modality);
    });
    connect(m_worker, &SCUWorker::logMessage, this, &SCUMainWindow::onLogMessage);
    connect(m_worker, &SCUWorker::findFinished, this, &SCUMainWindow::onFindFinished);

    m_workerThread->start();
}

void SCUMainWindow::onFindFinished(bool success, const QString& message,
                                   const QList<FindResult>& results)
{
    m_findBtn->setEnabled(true);
    m_moveBtn->setEnabled(true);
    m_sendBtn->setEnabled(true);
    setControlsEnabled(true);

    // 填充结果表格
    m_findResultsTable->setRowCount(results.size());
    for (int i = 0; i < results.size(); i++) {
        const FindResult& r = results[i];
        m_findResultsTable->setItem(i, 0, new QTableWidgetItem(r.patientID));
        m_findResultsTable->setItem(i, 1, new QTableWidgetItem(r.patientName));
        m_findResultsTable->setItem(i, 2, new QTableWidgetItem(r.studyInstanceUID));
        m_findResultsTable->setItem(i, 3, new QTableWidgetItem(r.studyDate));
        m_findResultsTable->setItem(i, 4, new QTableWidgetItem(r.modality));
        m_findResultsTable->setItem(i, 5, new QTableWidgetItem(r.seriesInstanceUID));
    }

    if (success) {
        m_statusLabel->setText(QString("✓ %1").arg(message));
        m_statusLabel->setStyleSheet("color: #4CAF50; padding: 4px; font-weight: bold;");
    } else {
        m_statusLabel->setText(QString("✗ %1").arg(message));
        m_statusLabel->setStyleSheet("color: #f44336; padding: 4px; font-weight: bold;");
    }

    // 清理线程：先调度 worker 删除，再退出线程事件循环，最后等待
    if (m_worker) {
        m_worker->deleteLater();
        m_worker = nullptr;
    }
    if (m_workerThread) {
        m_workerThread->quit();
        m_workerThread->wait();
        m_workerThread->deleteLater();
        m_workerThread = nullptr;
    }
}

// ============================================================
//  C-MOVE 检索
// ============================================================
void SCUMainWindow::onMove()
{
    SCUConfig config = getConfig();
    if (config.peerHost.empty() || config.peerPort == 0) {
        QMessageBox::warning(this, "错误", "请填写有效的服务端地址和端口");
        return;
    }
    if (m_moveDestAEEdit->text().isEmpty()) {
        QMessageBox::warning(this, "错误", "请填写目标 AE Title");
        return;
    }
    if (m_moveListenPortEdit->text().toUShort() == 0) {
        QMessageBox::warning(this, "错误", "请填写有效的监听端口");
        return;
    }

    m_findBtn->setEnabled(false);
    m_moveBtn->setEnabled(false);
    m_sendBtn->setEnabled(false);
    setControlsEnabled(false);
    m_statusLabel->setText("C-MOVE 检索中...");

    m_workerThread = new QThread(this);
    m_worker = new SCUWorker();
    m_worker->moveToThread(m_workerThread);

    QString moveDestAE = m_moveDestAEEdit->text();
    quint16 listenPort = m_moveListenPortEdit->text().toUShort();
    QString outputDir = m_moveOutputDirEdit->text();
    QString patientID = m_movePatientIDEdit->text();
    QString studyUID = m_moveStudyUIDEdit->text();

    connect(m_workerThread, &QThread::started, [this, config, moveDestAE, listenPort,
                                                outputDir, patientID, studyUID]() {
        m_worker->moveStudies(config, moveDestAE, listenPort, outputDir, patientID, studyUID);
    });
    connect(m_worker, &SCUWorker::logMessage, this, &SCUMainWindow::onLogMessage);
    connect(m_worker, &SCUWorker::moveFinished, this, &SCUMainWindow::onMoveFinished);

    m_workerThread->start();
}

void SCUMainWindow::onBrowseMoveOutputDir()
{
    QString dir = QFileDialog::getExistingDirectory(this, "选择检索输出目录",
                                                     m_moveOutputDirEdit->text());
    if (!dir.isEmpty()) m_moveOutputDirEdit->setText(dir);
}

void SCUMainWindow::onMoveFinished(bool success, const QString& message, int receivedCount)
{
    m_findBtn->setEnabled(true);
    m_moveBtn->setEnabled(true);
    m_sendBtn->setEnabled(true);
    setControlsEnabled(true);

    Q_UNUSED(receivedCount);
    if (success) {
        m_statusLabel->setText(QString("✓ %1").arg(message));
        m_statusLabel->setStyleSheet("color: #4CAF50; padding: 4px; font-weight: bold;");
    } else {
        m_statusLabel->setText(QString("✗ %1").arg(message));
        m_statusLabel->setStyleSheet("color: #f44336; padding: 4px; font-weight: bold;");
    }

    // 清理线程：先调度 worker 删除，再退出线程事件循环，最后等待
    if (m_worker) {
        m_worker->deleteLater();
        m_worker = nullptr;
    }
    if (m_workerThread) {
        m_workerThread->quit();
        m_workerThread->wait();
        m_workerThread->deleteLater();
        m_workerThread = nullptr;
    }
}

void SCUMainWindow::onBrowseDcmFile()
{
    QStringList files = QFileDialog::getOpenFileNames(this, "选择 DICOM 文件（可多选）", QString(),
                                                      "DICOM 文件 (*.dcm *.dic *.ima);;所有文件 (*)");
    for (const QString& f : files) {
        // 避免重复添加
        bool exists = false;
        for (int i = 0; i < m_dcmFileList->count(); i++) {
            if (m_dcmFileList->item(i)->text() == f) { exists = true; break; }
        }
        if (!exists) m_dcmFileList->addItem(f);
    }
}

void SCUMainWindow::onRemoveDcmFile()
{
    QList<QListWidgetItem*> selected = m_dcmFileList->selectedItems();
    for (QListWidgetItem* item : selected) {
        delete m_dcmFileList->takeItem(m_dcmFileList->row(item));
    }
}

void SCUMainWindow::onBrowseCert()
{
    QString f = QFileDialog::getOpenFileName(this, "选择客户端证书", m_certEdit->text(),
                                             "证书文件 (*.crt *.pem *.cer);;所有文件 (*)");
    if (!f.isEmpty()) m_certEdit->setText(f);
}

void SCUMainWindow::onBrowseKey()
{
    QString f = QFileDialog::getOpenFileName(this, "选择客户端私钥", m_keyEdit->text(),
                                             "私钥文件 (*.key *.pem);;所有文件 (*)");
    if (!f.isEmpty()) m_keyEdit->setText(f);
}

void SCUMainWindow::onBrowseCA()
{
    QString f = QFileDialog::getOpenFileName(this, "选择 CA 根证书", m_caEdit->text(),
                                             "证书文件 (*.crt *.pem *.cer);;所有文件 (*)");
    if (!f.isEmpty()) m_caEdit->setText(f);
}

// ============================================================
//  配置持久化（QSettings）
// ============================================================
void SCUMainWindow::loadSettings()
{
    QSettings settings(QSettings::IniFormat, QSettings::UserScope,
                       "DICOM_TLS_Demo", "SCU");
    m_hostEdit->setText(settings.value("scu/host", "127.0.0.1").toString());
    m_portEdit->setText(settings.value("scu/port", "11112").toString());
    m_ourAETitleEdit->setText(settings.value("scu/ourAETitle", "TLS_SCU").toString());
    m_peerAETitleEdit->setText(settings.value("scu/peerAETitle", "TLS_SCP").toString());
    m_certEdit->setText(settings.value("scu/certFile", "certs/client.crt").toString());
    m_keyEdit->setText(settings.value("scu/keyFile", "certs/client.key").toString());
    m_caEdit->setText(settings.value("scu/caFile", "certs/ca.crt").toString());
    // C-FIND
    m_findPatientIDEdit->setText(settings.value("scu/findPatientID", "").toString());
    m_findStudyDateEdit->setText(settings.value("scu/findStudyDate", "").toString());
    m_findModalityEdit->setText(settings.value("scu/findModality", "").toString());
    int idx = m_findLevelCombo->findData(settings.value("scu/findLevel", "STUDY").toString());
    if (idx >= 0) m_findLevelCombo->setCurrentIndex(idx);
    // C-MOVE
    m_moveDestAEEdit->setText(settings.value("scu/moveDestAE", "TLS_SCU").toString());
    m_moveListenPortEdit->setText(settings.value("scu/moveListenPort", "11113").toString());
    m_moveOutputDirEdit->setText(settings.value("scu/moveOutputDir", "./retrieved").toString());
    m_movePatientIDEdit->setText(settings.value("scu/movePatientID", "").toString());
    m_moveStudyUIDEdit->setText(settings.value("scu/moveStudyUID", "").toString());
}

void SCUMainWindow::saveSettings()
{
    QSettings settings(QSettings::IniFormat, QSettings::UserScope,
                       "DICOM_TLS_Demo", "SCU");
    settings.setValue("scu/host", m_hostEdit->text());
    settings.setValue("scu/port", m_portEdit->text());
    settings.setValue("scu/ourAETitle", m_ourAETitleEdit->text());
    settings.setValue("scu/peerAETitle", m_peerAETitleEdit->text());
    settings.setValue("scu/certFile", m_certEdit->text());
    settings.setValue("scu/keyFile", m_keyEdit->text());
    settings.setValue("scu/caFile", m_caEdit->text());
    // C-FIND
    settings.setValue("scu/findLevel", m_findLevelCombo->currentData().toString());
    settings.setValue("scu/findPatientID", m_findPatientIDEdit->text());
    settings.setValue("scu/findStudyDate", m_findStudyDateEdit->text());
    settings.setValue("scu/findModality", m_findModalityEdit->text());
    // C-MOVE
    settings.setValue("scu/moveDestAE", m_moveDestAEEdit->text());
    settings.setValue("scu/moveListenPort", m_moveListenPortEdit->text());
    settings.setValue("scu/moveOutputDir", m_moveOutputDirEdit->text());
    settings.setValue("scu/movePatientID", m_movePatientIDEdit->text());
    settings.setValue("scu/moveStudyUID", m_moveStudyUIDEdit->text());
}

void SCUMainWindow::closeEvent(QCloseEvent* event)
{
    saveSettings();
    event->accept();
}

void SCUMainWindow::onRestoreDefaults()
{
    m_hostEdit->setText("127.0.0.1");
    m_portEdit->setText("11112");
    m_ourAETitleEdit->setText("TLS_SCU");
    m_peerAETitleEdit->setText("TLS_SCP");
    m_certEdit->setText("certs/client.crt");
    m_keyEdit->setText("certs/client.key");
    m_caEdit->setText("certs/ca.crt");
    // C-FIND
    m_findLevelCombo->setCurrentIndex(1); // STUDY
    m_findPatientIDEdit->clear();
    m_findStudyDateEdit->clear();
    m_findModalityEdit->clear();
    // C-MOVE
    m_moveDestAEEdit->setText("TLS_SCU");
    m_moveListenPortEdit->setText("11113");
    m_moveOutputDirEdit->setText("./retrieved");
    m_movePatientIDEdit->clear();
    m_moveStudyUIDEdit->clear();
}
