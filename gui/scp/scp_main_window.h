// ============================================================
//  SCP 服务端主窗口 - 配置 + 日志 + 接收文件列表 + DICOM 图像显示
// ============================================================
#ifndef SCP_MAIN_WINDOW_H
#define SCP_MAIN_WINDOW_H

#include <QMainWindow>
#include <QThread>
#include <QSettings>
#include <QCloseEvent>
#include "scp_worker.h"
#include "../common/tls_config.h"

class QLineEdit;
class QPushButton;
class QTextEdit;
class QListWidget;
class QLabel;
class QGroupBox;
class QSlider;
class QComboBox;

class SCPMainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit SCPMainWindow(QWidget* parent = nullptr);
    ~SCPMainWindow();

private slots:
    void onStartStop();
    void onBrowseOutputDir();
    void onBrowseCert();
    void onBrowseKey();
    void onBrowseCA();
    void onLogMessage(const QString& msg);
    void onFileReceived(const QString& filePath);
    void onServerStarted();
    void onServerStopped();
    void onFileClicked(int row);
    // 窗宽窗位控制
    void onWindowCenterChanged(int value);
    void onWindowWidthChanged(int value);
    void onPresetChanged(int index);
    // 配置持久化
    void onRestoreDefaults();

private:
    void setupUI();
    SCPConfig getConfig() const;
    void setControlsEnabled(bool enabled);
    QGroupBox* createConfigGroup();
    QWidget* createLogPanel();
    QWidget* createFileListPanel();
    QWidget* createImagePanel();
    void loadAndDisplayImage(const QString& filePath);
    void updateWindowDisplay();
    // 配置持久化
    void loadSettings();
    void saveSettings();
    void closeEvent(QCloseEvent* event) override;

    // 配置控件
    QLineEdit* m_portEdit;
    QLineEdit* m_moveDestPortEdit;
    QLineEdit* m_aeTitleEdit;
    QLineEdit* m_outputDirEdit;
    QLineEdit* m_certEdit;
    QLineEdit* m_keyEdit;
    QLineEdit* m_caEdit;
    QPushButton* m_startStopBtn;

    // 日志
    QTextEdit* m_logEdit;

    // 文件列表
    QListWidget* m_fileList;

    // 图像显示
    QLabel* m_imageLabel;
    QLabel* m_infoLabel;
    QString m_currentImagePath;

    // 窗宽窗位控制
    QSlider* m_centerSlider;
    QSlider* m_widthSlider;
    QLabel* m_centerValueLabel;
    QLabel* m_widthValueLabel;
    QComboBox* m_presetCombo;
    double m_windowCenter;
    double m_windowWidth;

    // 工作线程
    QThread* m_workerThread;
    SCPWorker* m_worker;
    bool m_running;
};

#endif // SCP_MAIN_WINDOW_H
