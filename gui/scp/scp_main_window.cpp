// ============================================================
//  SCP 服务端主窗口实现
// ============================================================
#include "scp_main_window.h"
#include "../common/dicom_image_util.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QGroupBox>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QTextEdit>
#include <QListWidget>
#include <QListWidgetItem>
#include <QFileDialog>
#include <QMessageBox>
#include <QSpinBox>
#include <QSplitter>
#include <QScrollArea>
#include <QDateTime>
#include <QSlider>
#include <QComboBox>

SCPMainWindow::SCPMainWindow(QWidget* parent)
    : QMainWindow(parent)
    , m_workerThread(nullptr)
    , m_worker(nullptr)
    , m_running(false)
{
    setupUI();
    loadSettings();
    setWindowTitle("DICOM TLS Storage SCP - 服务端");
    resize(1200, 750);
}

SCPMainWindow::~SCPMainWindow()
{
    if (m_worker) {
        m_worker->stopServer();
    }
    if (m_workerThread) {
        m_workerThread->quit();
        m_workerThread->wait();
    }
}

void SCPMainWindow::setupUI()
{
    QWidget* central = new QWidget(this);
    setCentralWidget(central);

    QVBoxLayout* mainLayout = new QVBoxLayout(central);

    // 配置区
    QGroupBox* configGroup = createConfigGroup();
    mainLayout->addWidget(configGroup);

    // 启动/停止按钮
    QHBoxLayout* btnLayout = new QHBoxLayout();
    m_startStopBtn = new QPushButton("启动服务", this);
    m_startStopBtn->setMinimumHeight(36);
    m_startStopBtn->setStyleSheet("background-color: #4CAF50; color: white; font-weight: bold; font-size: 14px;");
    connect(m_startStopBtn, &QPushButton::clicked, this, &SCPMainWindow::onStartStop);
    btnLayout->addStretch();
    btnLayout->addWidget(m_startStopBtn);
    mainLayout->addLayout(btnLayout);

    // 主体区：左侧文件列表+日志，右侧图像显示
    QSplitter* splitter = new QSplitter(Qt::Horizontal, this);

    // 左侧：文件列表 + 日志
    QWidget* leftPanel = new QWidget();
    QVBoxLayout* leftLayout = new QVBoxLayout(leftPanel);
    leftLayout->addWidget(createFileListPanel());
    leftLayout->addWidget(createLogPanel(), 1);
    splitter->addWidget(leftPanel);

    // 右侧：图像显示
    splitter->addWidget(createImagePanel());

    splitter->setStretchFactor(0, 1);
    splitter->setStretchFactor(1, 2);
    mainLayout->addWidget(splitter, 1);
}

QGroupBox* SCPMainWindow::createConfigGroup()
{
    QGroupBox* group = new QGroupBox("服务配置", this);
    QGridLayout* layout = new QGridLayout(group);

    // 监听端口
    layout->addWidget(new QLabel("监听端口:"), 0, 0);
    m_portEdit = new QLineEdit("11112", this);
    m_portEdit->setMaximumWidth(100);
    layout->addWidget(m_portEdit, 0, 1);

    // C-MOVE 子关联目标端口
    layout->addWidget(new QLabel("C-MOVE 回连端口:"), 0, 2);
    m_moveDestPortEdit = new QLineEdit("11113", this);
    m_moveDestPortEdit->setMaximumWidth(100);
    layout->addWidget(m_moveDestPortEdit, 0, 3);

    // AE Title
    layout->addWidget(new QLabel("AE Title:"), 1, 0);
    m_aeTitleEdit = new QLineEdit("TLS_SCP", this);
    layout->addWidget(m_aeTitleEdit, 1, 1);
    layout->addWidget(new QLabel("（C-MOVE 子关联使用此 AE 回连 SCU）"), 1, 2, 1, 2);

    // 保存目录
    layout->addWidget(new QLabel("保存目录:"), 2, 0);
    m_outputDirEdit = new QLineEdit("./received", this);
    QPushButton* browseDirBtn = new QPushButton("浏览...", this);
    connect(browseDirBtn, &QPushButton::clicked, this, &SCPMainWindow::onBrowseOutputDir);
    QHBoxLayout* dirLayout = new QHBoxLayout();
    dirLayout->addWidget(m_outputDirEdit);
    dirLayout->addWidget(browseDirBtn);
    layout->addLayout(dirLayout, 2, 1, 1, 3);

    // 服务端证书
    layout->addWidget(new QLabel("服务端证书:"), 3, 0);
    m_certEdit = new QLineEdit("certs/server.crt", this);
    QPushButton* browseCertBtn = new QPushButton("浏览...", this);
    connect(browseCertBtn, &QPushButton::clicked, this, &SCPMainWindow::onBrowseCert);
    QHBoxLayout* certLayout = new QHBoxLayout();
    certLayout->addWidget(m_certEdit);
    certLayout->addWidget(browseCertBtn);
    layout->addLayout(certLayout, 3, 1, 1, 3);

    // 服务端私钥
    layout->addWidget(new QLabel("服务端私钥:"), 4, 0);
    m_keyEdit = new QLineEdit("certs/server.key", this);
    QPushButton* browseKeyBtn = new QPushButton("浏览...", this);
    connect(browseKeyBtn, &QPushButton::clicked, this, &SCPMainWindow::onBrowseKey);
    QHBoxLayout* keyLayout = new QHBoxLayout();
    keyLayout->addWidget(m_keyEdit);
    keyLayout->addWidget(browseKeyBtn);
    layout->addLayout(keyLayout, 4, 1, 1, 3);

    // CA 根证书
    layout->addWidget(new QLabel("CA 根证书:"), 5, 0);
    m_caEdit = new QLineEdit("certs/ca.crt", this);
    QPushButton* browseCABtn = new QPushButton("浏览...", this);
    connect(browseCABtn, &QPushButton::clicked, this, &SCPMainWindow::onBrowseCA);
    QHBoxLayout* caLayout = new QHBoxLayout();
    caLayout->addWidget(m_caEdit);
    caLayout->addWidget(browseCABtn);
    layout->addLayout(caLayout, 5, 1, 1, 3);

    // 恢复默认值按钮
    QPushButton* restoreBtn = new QPushButton("恢复默认值", this);
    restoreBtn->setStyleSheet("color: #888;");
    connect(restoreBtn, &QPushButton::clicked, this, &SCPMainWindow::onRestoreDefaults);
    layout->addWidget(restoreBtn, 6, 0);

    return group;
}

QWidget* SCPMainWindow::createLogPanel()
{
    QGroupBox* group = new QGroupBox("运行日志", this);
    QVBoxLayout* layout = new QVBoxLayout(group);
    m_logEdit = new QTextEdit(this);
    m_logEdit->setReadOnly(true);
    m_logEdit->setFont(QFont("Consolas", 9));
    layout->addWidget(m_logEdit);
    return group;
}

QWidget* SCPMainWindow::createFileListPanel()
{
    QGroupBox* group = new QGroupBox("已接收 DICOM 文件", this);
    QVBoxLayout* layout = new QVBoxLayout(group);
    m_fileList = new QListWidget(this);
    connect(m_fileList, &QListWidget::currentRowChanged, this, &SCPMainWindow::onFileClicked);
    layout->addWidget(m_fileList);
    return group;
}

QWidget* SCPMainWindow::createImagePanel()
{
    QGroupBox* group = new QGroupBox("DICOM 图像显示", this);
    QVBoxLayout* layout = new QVBoxLayout(group);

    m_infoLabel = new QLabel("（点击左侧文件列表查看图像）", this);
    m_infoLabel->setAlignment(Qt::AlignCenter);
    m_infoLabel->setStyleSheet("color: #888; padding: 8px;");
    layout->addWidget(m_infoLabel);

    QScrollArea* scrollArea = new QScrollArea(this);
    scrollArea->setAlignment(Qt::AlignCenter);
    m_imageLabel = new QLabel(this);
    m_imageLabel->setAlignment(Qt::AlignCenter);
    m_imageLabel->setStyleSheet("background-color: #222; border: 1px solid #444;");
    m_imageLabel->setMinimumSize(400, 400);
    scrollArea->setWidget(m_imageLabel);
    scrollArea->setWidgetResizable(true);
    layout->addWidget(scrollArea, 1);

    // 窗宽窗位控制区
    QGroupBox* windowGroup = new QGroupBox("窗宽 / 窗位调节", this);
    QGridLayout* winLayout = new QGridLayout(windowGroup);

    // 预设窗口
    winLayout->addWidget(new QLabel("预设:"), 0, 0);
    m_presetCombo = new QComboBox(this);
    for (const auto& p : DicomImageUtil::commonPresets()) {
        m_presetCombo->addItem(p.name, QVariant::fromValue(QPair<double,double>(p.center, p.width)));
    }
    connect(m_presetCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &SCPMainWindow::onPresetChanged);
    winLayout->addWidget(m_presetCombo, 0, 1, 1, 3);

    // 窗位
    winLayout->addWidget(new QLabel("窗位(C):"), 1, 0);
    m_centerSlider = new QSlider(Qt::Horizontal, this);
    m_centerSlider->setRange(-1024, 3071);
    connect(m_centerSlider, &QSlider::valueChanged, this, &SCPMainWindow::onWindowCenterChanged);
    winLayout->addWidget(m_centerSlider, 1, 1, 1, 2);
    m_centerValueLabel = new QLabel("40", this);
    m_centerValueLabel->setMinimumWidth(60);
    m_centerValueLabel->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    winLayout->addWidget(m_centerValueLabel, 1, 3);

    // 窗宽
    winLayout->addWidget(new QLabel("窗宽(W):"), 2, 0);
    m_widthSlider = new QSlider(Qt::Horizontal, this);
    m_widthSlider->setRange(1, 4096);
    connect(m_widthSlider, &QSlider::valueChanged, this, &SCPMainWindow::onWindowWidthChanged);
    winLayout->addWidget(m_widthSlider, 2, 1, 1, 2);
    m_widthValueLabel = new QLabel("400", this);
    m_widthValueLabel->setMinimumWidth(60);
    m_widthValueLabel->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    winLayout->addWidget(m_widthValueLabel, 2, 3);

    layout->addWidget(windowGroup);

    // 初始化默认值
    m_windowCenter = 40.0;
    m_windowWidth = 400.0;

    return group;
}

SCPConfig SCPMainWindow::getConfig() const
{
    SCPConfig config;
    config.listenPort      = m_portEdit->text().toUShort();
    config.moveDestPort    = m_moveDestPortEdit->text().toUShort();
    config.ourAETitle      = m_aeTitleEdit->text().toUtf8().constData();
    config.outputDir       = m_outputDirEdit->text().toUtf8().constData();
    config.certFile        = m_certEdit->text().toUtf8().constData();
    config.keyFile         = m_keyEdit->text().toUtf8().constData();
    config.caFile          = m_caEdit->text().toUtf8().constData();
    // C-MOVE 子关联默认复用服务端证书/私钥作为客户端证书
    config.clientCertFile  = m_certEdit->text().toUtf8().constData();
    config.clientKeyFile   = m_keyEdit->text().toUtf8().constData();
    config.verbose         = true;
    return config;
}

void SCPMainWindow::setControlsEnabled(bool enabled)
{
    m_portEdit->setEnabled(enabled);
    m_moveDestPortEdit->setEnabled(enabled);
    m_aeTitleEdit->setEnabled(enabled);
    m_outputDirEdit->setEnabled(enabled);
    m_certEdit->setEnabled(enabled);
    m_keyEdit->setEnabled(enabled);
    m_caEdit->setEnabled(enabled);
}

void SCPMainWindow::onStartStop()
{
    if (!m_running) {
        // 启动
        SCPConfig config = getConfig();
        if (config.listenPort == 0) {
            QMessageBox::warning(this, "错误", "请输入有效的端口号");
            return;
        }

        m_workerThread = new QThread(this);
        m_worker = new SCPWorker();
        m_worker->moveToThread(m_workerThread);

        connect(m_workerThread, &QThread::started, [this, config]() {
            m_worker->startServer(config);
        });
        connect(m_worker, &SCPWorker::logMessage, this, &SCPMainWindow::onLogMessage);
        connect(m_worker, &SCPWorker::fileReceived, this, &SCPMainWindow::onFileReceived);
        connect(m_worker, &SCPWorker::serverStarted, this, &SCPMainWindow::onServerStarted);
        connect(m_worker, &SCPWorker::serverStopped, this, &SCPMainWindow::onServerStopped);
        connect(m_worker, &SCPWorker::serverError, this, [this](const QString& err) {
            QMessageBox::critical(this, "服务错误", err);
        });

        m_running = true;
        setControlsEnabled(false);
        m_startStopBtn->setText("停止服务");
        m_startStopBtn->setStyleSheet("background-color: #f44336; color: white; font-weight: bold; font-size: 14px;");
        m_workerThread->start();
    } else {
        // 停止
        if (m_worker) {
            m_worker->stopServer();
        }
    }
}

void SCPMainWindow::onServerStarted()
{
    onLogMessage("[SCP] 服务已启动");
}

void SCPMainWindow::onServerStopped()
{
    m_running = false;
    setControlsEnabled(true);
    m_startStopBtn->setText("启动服务");
    m_startStopBtn->setStyleSheet("background-color: #4CAF50; color: white; font-weight: bold; font-size: 14px;");
    onLogMessage("[SCP] 服务已停止");

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

void SCPMainWindow::onLogMessage(const QString& msg)
{
    QString timestamp = QDateTime::currentDateTime().toString("HH:mm:ss");
    m_logEdit->append(QString("[%1] %2").arg(timestamp, msg));
}

void SCPMainWindow::onFileReceived(const QString& filePath)
{
    QFileInfo fi(filePath);
    QListWidgetItem* item = new QListWidgetItem(fi.fileName());
    item->setData(Qt::UserRole, filePath);
    m_fileList->addItem(item);
}

void SCPMainWindow::onFileClicked(int row)
{
    if (row < 0 || row >= m_fileList->count()) return;
    QListWidgetItem* item = m_fileList->item(row);
    QString filePath = item->data(Qt::UserRole).toString();
    m_currentImagePath = filePath;

    // 获取并显示文件信息
    DicomImageUtil::DicomInfo info = DicomImageUtil::getDicomInfo(filePath);
    QString infoText = QString("<b>%1</b><br>"
                               "患者: %2 | 检查日期: %3 | 模态: %4<br>"
                               "尺寸: %5 x %6")
        .arg(info.sopInstanceUID)
        .arg(info.patientName.isEmpty() ? "(未知)" : info.patientName)
        .arg(info.studyDate.isEmpty() ? "(未知)" : info.studyDate)
        .arg(info.modality.isEmpty() ? "(未知)" : info.modality)
        .arg(info.width).arg(info.height);
    m_infoLabel->setText(infoText);

    // 设置滑块范围（根据文件位深）
    m_centerSlider->blockSignals(true);
    m_widthSlider->blockSignals(true);
    m_centerSlider->setRange((int)info.minWindowCenter, (int)info.maxWindowCenter);
    m_widthSlider->setRange((int)info.minWindowWidth, (int)info.maxWindowWidth);

    if (info.hasPixelData) {
        // 使用文件中的默认窗宽窗位
        m_windowCenter = info.defaultWindowCenter;
        m_windowWidth = info.defaultWindowWidth;
        m_centerSlider->setValue((int)m_windowCenter);
        m_widthSlider->setValue((int)m_windowWidth);
        m_centerSlider->blockSignals(false);
        m_widthSlider->blockSignals(false);
        loadAndDisplayImage(filePath);
    } else {
        m_centerSlider->blockSignals(false);
        m_widthSlider->blockSignals(false);
        m_imageLabel->setText("此文件不包含像素数据");
        m_imageLabel->setStyleSheet("background-color: #222; color: #aaa;");
        m_imageLabel->setPixmap(QPixmap());
    }
}

void SCPMainWindow::loadAndDisplayImage(const QString& filePath)
{
    if (filePath.isEmpty()) return;
    QImage img = DicomImageUtil::loadDicomImage(filePath, m_windowCenter, m_windowWidth);
    if (!img.isNull()) {
        QPixmap pixmap = QPixmap::fromImage(img);
        m_imageLabel->setPixmap(pixmap.scaled(
            m_imageLabel->size(), Qt::KeepAspectRatio, Qt::SmoothTransformation));
    } else {
        m_imageLabel->setText("无法加载像素数据");
    }
}

void SCPMainWindow::updateWindowDisplay()
{
    m_centerValueLabel->setText(QString::number((int)m_windowCenter));
    m_widthValueLabel->setText(QString::number((int)m_windowWidth));
    if (!m_currentImagePath.isEmpty()) {
        loadAndDisplayImage(m_currentImagePath);
    }
}

void SCPMainWindow::onWindowCenterChanged(int value)
{
    m_windowCenter = (double)value;
    updateWindowDisplay();
}

void SCPMainWindow::onWindowWidthChanged(int value)
{
    m_windowWidth = (double)value;
    updateWindowDisplay();
}

void SCPMainWindow::onPresetChanged(int index)
{
    QVariant data = m_presetCombo->itemData(index);
    QPair<double, double> cw = data.value<QPair<double,double>>();
    if (cw.first < 0 && cw.second < 0) {
        // 自动窗宽窗位
        m_windowCenter = -1.0;
        m_windowWidth = -1.0;
    } else {
        m_windowCenter = cw.first;
        m_windowWidth = cw.second;
    }
    m_centerSlider->blockSignals(true);
    m_widthSlider->blockSignals(true);
    if (m_windowCenter >= 0) m_centerSlider->setValue((int)m_windowCenter);
    if (m_windowWidth > 0) m_widthSlider->setValue((int)m_windowWidth);
    m_centerSlider->blockSignals(false);
    m_widthSlider->blockSignals(false);
    updateWindowDisplay();
}

void SCPMainWindow::onBrowseOutputDir()
{
    QString dir = QFileDialog::getExistingDirectory(this, "选择保存目录", m_outputDirEdit->text());
    if (!dir.isEmpty()) m_outputDirEdit->setText(dir);
}

void SCPMainWindow::onBrowseCert()
{
    QString f = QFileDialog::getOpenFileName(this, "选择服务端证书", m_certEdit->text(),
                                             "证书文件 (*.crt *.pem *.cer);;所有文件 (*)");
    if (!f.isEmpty()) m_certEdit->setText(f);
}

void SCPMainWindow::onBrowseKey()
{
    QString f = QFileDialog::getOpenFileName(this, "选择服务端私钥", m_keyEdit->text(),
                                             "私钥文件 (*.key *.pem);;所有文件 (*)");
    if (!f.isEmpty()) m_keyEdit->setText(f);
}

void SCPMainWindow::onBrowseCA()
{
    QString f = QFileDialog::getOpenFileName(this, "选择 CA 根证书", m_caEdit->text(),
                                             "证书文件 (*.crt *.pem *.cer);;所有文件 (*)");
    if (!f.isEmpty()) m_caEdit->setText(f);
}

// ============================================================
//  配置持久化（QSettings）
// ============================================================
void SCPMainWindow::loadSettings()
{
    QSettings settings(QSettings::IniFormat, QSettings::UserScope,
                       "DICOM_TLS_Demo", "SCP");
    m_portEdit->setText(settings.value("scp/port", "11112").toString());
    m_moveDestPortEdit->setText(settings.value("scp/moveDestPort", "11113").toString());
    m_aeTitleEdit->setText(settings.value("scp/aeTitle", "TLS_SCP").toString());
    m_outputDirEdit->setText(settings.value("scp/outputDir", "./received").toString());
    m_certEdit->setText(settings.value("scp/certFile", "certs/server.crt").toString());
    m_keyEdit->setText(settings.value("scp/keyFile", "certs/server.key").toString());
    m_caEdit->setText(settings.value("scp/caFile", "certs/ca.crt").toString());
}

void SCPMainWindow::saveSettings()
{
    QSettings settings(QSettings::IniFormat, QSettings::UserScope,
                       "DICOM_TLS_Demo", "SCP");
    settings.setValue("scp/port", m_portEdit->text());
    settings.setValue("scp/moveDestPort", m_moveDestPortEdit->text());
    settings.setValue("scp/aeTitle", m_aeTitleEdit->text());
    settings.setValue("scp/outputDir", m_outputDirEdit->text());
    settings.setValue("scp/certFile", m_certEdit->text());
    settings.setValue("scp/keyFile", m_keyEdit->text());
    settings.setValue("scp/caFile", m_caEdit->text());
}

void SCPMainWindow::closeEvent(QCloseEvent* event)
{
    saveSettings();
    if (m_worker) {
        m_worker->stopServer();
    }
    event->accept();
}

void SCPMainWindow::onRestoreDefaults()
{
    m_portEdit->setText("11112");
    m_moveDestPortEdit->setText("11113");
    m_aeTitleEdit->setText("TLS_SCP");
    m_outputDirEdit->setText("./received");
    m_certEdit->setText("certs/server.crt");
    m_keyEdit->setText("certs/server.key");
    m_caEdit->setText("certs/ca.crt");
}
