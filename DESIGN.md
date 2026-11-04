# DICOM TLS 加密传输 Demo — 设计文档

## 1. 项目概述

### 1.1 项目目标

实现一个基于 DICOM 协议的 TLS 加密传输演示系统，完整覆盖 DICOM 存储与查询检索三大核心服务：

- **服务端（SCP）**：DICOM Storage / Query-Retrieve Service Class Provider，接收加密的 C-STORE 请求并保存文件，支持 C-FIND 查询与 C-MOVE 检索
- **客户端（SCU）**：DICOM Storage / Query-Retrieve Service Class User，将 DICOM 文件通过 TLS 加密通道发送给 SCP，支持 C-FIND 查询与 C-MOVE 检索
- **Qt 图形界面**：为 SCP 和 SCU 分别提供可视化配置、操作、DICOM 图像显示与查询检索界面

### 1.2 技术栈

| 组件       | 技术/版本                     | 用途                                   |
| ---------- | ----------------------------- | -------------------------------------- |
| DICOM 协议 | DCMTK 3.6.4                   | DICOM 网络通信、数据解析、图像编解码   |
| TLS 加密   | OpenSSL 1.1.1f + DCMTK dcmtls | 双向证书认证的 TLS 1.2 加密通道        |
| 本地索引   | SQLite 3                      | DICOM 文件元数据索引，支持 C-FIND 查询 |
| GUI 框架   | Qt 5.12.8                     | 图形界面、信号槽、多线程               |
| 构建系统   | CMake 3.10+                   | 跨平台构建                             |
| 语言       | C++11                         |                                        |

### 1.3 交付产物

| 可执行文件  | 类型   | 说明                                    |
| ----------- | ------ | --------------------------------------- |
| `tls_scp` | 命令行 | SCP 服务端（C-STORE + C-FIND + C-MOVE） |
| `tls_scu` | 命令行 | SCU 客户端（C-STORE + C-FIND + C-MOVE） |
| `scp_gui` | Qt GUI | SCP 服务端图形界面（含 DICOM 图像显示） |
| `scu_gui` | Qt GUI | SCU 客户端图形界面（含查询检索）        |

### 1.4 支持的 DICOM 服务

| 服务    | SOP Class UID                         | 说明                                |
| ------- | ------------------------------------- | ----------------------------------- |
| C-STORE | 由文件 SOP Class UID 决定             | 存储服务，支持多传输语法协商        |
| C-ECHO  | `1.2.840.10008.1.1`（Verification） | 连通性测试                          |
| C-FIND  | `1.2.840.10008.5.1.4.1.2.2.1`       | Study Root 查询                     |
| C-MOVE  | `1.2.840.10008.5.1.4.1.2.2.2`       | Study Root 检索（带子关联 C-STORE） |

---

## 2. 系统架构

### 2.1 总体架构

```
┌─────────────────────────────────────┐       ┌─────────────────────────────────────┐
│           SCU 客户端                 │       │           SCP 服务端                 │
│                                     │       │                                     │
│  ┌───────────┐   ┌───────────────┐  │       │  ┌───────────┐   ┌───────────────┐  │
│  │  Qt GUI   │   │  SCUWorker    │  │       │  │  Qt GUI   │   │  SCPWorker    │  │
│  │ (UI 线程) │──▶│ (QThread)     │  │       │  │ (UI 线程) │◀──│ (QThread)     │  │
│  └───────────┘   └───────┬───────┘  │       │  └───────────┘   └───────▲───────┘  │
│                          │            │       │                          │            │
│              DCMTK dcmnet + dcmtls   │       │              DCMTK dcmnet + dcmtls   │
│              + SQLite (本地索引)     │       │              + SQLite (本地索引)     │
└──────────────────────────┼───────────┘       └──────────────────────────┼───────────┘
                           │                                                 │
                           │   TLS 1.2 加密通道 (双向证书认证)                 │
                           └─────────────────────────────────────────────────┘
```

### 2.2 目录结构

```
dicom_tls_demo/
├── CMakeLists.txt                  # 构建配置
├── tls_scp.cpp                     # 命令行 SCP（C-STORE/C-FIND/C-MOVE Provider）
├── tls_scu.cpp                     # 命令行 SCU（C-STORE/C-FIND/C-MOVE User）
├── generate_certs.sh/.bat          # 证书生成脚本
├── openssl_tls12.cnf               # OpenSSL TLS 1.2 强制配置
├── certs/                          # CA/服务端/客户端证书
├── received/                       # SCP 接收文件目录（运行时生成）
├── retrieved/                      # SCU C-MOVE 检索输出目录（运行时生成）
└── gui/
    ├── common/
    │   ├── tls_config.h            # SCP/SCU 配置结构体
    │   ├── tls_helper.h/.cpp       # TLS 传输层设置（共用）
    │   ├── dicom_image_util.h/.cpp # DICOM 图像转 QImage + 窗宽窗位
    │   └── dicom_index.h/.cpp      # SQLite DICOM 文件索引
    ├── scp/
    │   ├── main.cpp                # SCP GUI 入口
    │   ├── scp_main_window.h/.cpp  # SCP 主窗口（含图像显示、窗宽窗位）
    │   └── scp_worker.h/.cpp       # SCP 后台 Worker
    └── scu/
        ├── main.cpp                # SCU GUI 入口
        ├── scu_main_window.h/.cpp  # SCU 主窗口（含 C-FIND/C-MOVE 界面）
        └── scu_worker.h/.cpp       # SCU 后台 Worker
```

---

## 3. 模块设计

### 3.1 公共模块（gui/common/）

#### 3.1.1 TLS 配置结构（tls_config.h）

```cpp
struct SCPConfig {
    Uint16   listenPort;       // 监听端口，默认 11112
    OFString ourAETitle;       // 本地 AE Title，默认 "TLS_SCP"
    OFString outputDir;        // 接收文件保存目录，默认 "./received"
    OFString certFile;         // 服务端证书路径
    OFString keyFile;          // 服务端私钥路径
    OFString caFile;           // CA 根证书路径
    OFString clientCertFile;   // 客户端证书（C-MOVE 子关联回连用）
    OFString clientKeyFile;    // 客户端私钥（C-MOVE 子关联回连用）
    Uint32   maxPDULength;     // 最大 PDU 长度
    bool     verbose;          // 详细日志
    Uint16   moveDestPort;     // C-MOVE 子关联目标端口，默认 11113
};

struct SCUConfig {
    OFString peerHost;         // SCP 主机地址
    Uint16   peerPort;         // SCP 端口
    OFString ourAETitle;       // 本地 AE Title (SCU)
    OFString peerAETitle;      // 对端 AE Title (SCP)
    OFString certFile;         // 客户端证书
    OFString keyFile;          // 客户端私钥
    OFString caFile;           // CA 根证书
    Uint32   maxPDULength;     // 最大 PDU 长度
    QStringList dcmFiles;      // 要发送的 DICOM 文件列表（支持多文件批量发送）
};
```

#### 3.1.2 TLS 传输层设置（tls_helper.h/.cpp）

`TlsHelper::setupTLS()` 为网络对象统一配置 TLS 传输层，SCP 和 SCU 共用：

```cpp
OFCondition setupTLS(T_ASC_Network* net,
                     T_ASC_NetworkRole role,
                     const std::string& certFile,
                     const std::string& keyFile,
                     const std::string& caFile,
                     bool requirePeerCert = true);
```

**核心步骤：**

1. 创建 `DcmTLSTransportLayer`（指定角色 `NET_ACCEPTOR` / `NET_REQUESTOR`）
2. 加载私钥：`setPrivateKeyFile(keyFile, DCF_Filetype_PEM)`
3. 加载证书：`setCertificateFile(certFile, DCF_Filetype_PEM)`
4. 加载 CA 信任链：`addTrustedCertificateFile(caFile, DCF_Filetype_PEM)`
5. 设置对端证书验证策略：`setCertificateVerification(DCV_requireCertificate)`（双向认证）
6. 设置加密套件：`setTLSProfile(TSP_Profile_BCP195)` + `activateCipherSuites()`
7. **强制 TLS 1.2**：通过 `SSL_CTX_set_options()` 禁用 SSLv2/v3、TLS 1.0/1.1/1.3
8. 绑定到网络层：`ASC_setTransportLayer(net, tlsLayer, 1)`（DCMTK 接管 TLS 层所有权）

> **设计说明**：TLS 1.3 在 DCMTK 3.6.4 + OpenSSL 1.1.1 组合下存在 "no suitable signature algorithm" 兼容性问题，因此强制使用 TLS 1.2。

#### 3.1.3 DICOM 图像工具（dicom_image_util.h/.cpp）

```cpp
struct DicomInfo {
    QString sopClassUID;
    QString sopInstanceUID;
    QString patientName;
    QString patientID;
    QString studyDate;
    QString modality;
    int rows;
    int columns;
    int bitsAllocated;
};

class DicomImageUtil {
public:
    static QImage loadDicomImage(const QString& filePath,
                                 double windowCenter = 0,
                                 double windowWidth = 0);
    static DicomInfo getDicomInfo(const QString& filePath);
};
```

- `loadDicomImage`：使用 DCMTK `DicomImage` 加载 DICOM 像素数据，支持窗宽窗位参数，转换为 `QImage`（`Format_Grayscale8` 或 `Format_RGB888`）。当 `windowCenter/windowWidth` 为 0 时自动调用 `setMinMaxWindow()`
- `getDicomInfo`：提取 SOP Class/Instance UID、患者姓名、检查日期、模态、图像尺寸等元数据

#### 3.1.4 DICOM 文件索引（dicom_index.h/.cpp）

基于 SQLite 的本地 DICOM 文件索引，为 C-FIND/C-MOVE 提供查询能力。

```cpp
class DicomIndex {
public:
    bool open(const QString& dbPath);
    bool addFile(const QString& filePath);       // 增量添加单文件
    bool rebuildFromDir(const QString& dirPath);  // 全量扫描重建
    QList<FindResult> query(const QString& level,
                            const QString& patientID,
                            const QString& studyDate,
                            const QString& modality,
                            const QString& studyUID);
    QString getFilePath(const QString& sopInstanceUID);
};
```

**索引表结构（单表 `instance`，20 字段，主键 `sopInstanceUID`）：**

| 字段              | 说明             |
| ----------------- | ---------------- |
| PatientID         | 患者 ID          |
| PatientName       | 患者姓名         |
| PatientBirthDate  | 出生日期         |
| PatientSex        | 性别             |
| StudyInstanceUID  | 检查 UID         |
| StudyDate         | 检查日期         |
| StudyTime         | 检查时间         |
| StudyDescription  | 检查描述         |
| ModalitiesInStudy | 检查内模态       |
| SeriesInstanceUID | 序列 UID         |
| SeriesNumber      | 序列号           |
| Modality          | 模态             |
| SeriesDescription | 序列描述         |
| SOPInstanceUID    | 实例 UID（主键） |
| SOPClassUID       | SOP 类 UID       |
| InstanceNumber    | 实例号           |
| Rows / Columns    | 图像行列         |
| BitsAllocated     | 位深             |
| filePath          | 文件绝对路径     |

**查询逻辑**：通配符 `*` 转为 SQL `%`，按 `QueryRetrieveLevel` 执行 `GROUP BY` 去重（PATIENT 级按 PatientID、STUDY 级按 StudyInstanceUID 等）。

### 3.2 SCP 服务端模块

#### 3.2.1 SCPMainWindow（gui/scp/scp_main_window.h/.cpp）

服务端主窗口，继承 `QMainWindow`，包含以下区域：

| 区域           | 控件                                            | 功能                                                               |
| -------------- | ----------------------------------------------- | ------------------------------------------------------------------ |
| 服务配置       | QLineEdit × 7 + QPushButton × 5               | 端口、C-MOVE 回连端口、AE Title、保存目录、证书/私钥/CA 路径       |
| 控制按钮       | QPushButton                                     | 启动/停止服务，运行时禁用配置项                                    |
| 接收文件列表   | QListWidget                                     | 自动列出接收到的 DICOM 文件                                        |
| DICOM 图像显示 | QLabel + QScrollArea + QSlider × 2 + QComboBox | 显示 DICOM 图像，支持窗宽/窗位滑块调节和预设（肺窗/骨窗/软组织窗） |
| 运行日志       | QTextEdit                                       | 实时显示连接、C-STORE/C-FIND/C-MOVE、错误日志                      |

**核心槽函数：**

- `onStartStop()`：创建 `QThread` + `SCPWorker`，通过 `moveToThread` 将 Worker 移入工作线程
- `onLogMessage()`：将 Worker 发来的日志追加到文本框
- `onFileReceived()`：将新接收的文件添加到列表
- `onFileClicked(int row)`：加载并显示 DICOM 图像
- `onWindowCenterChanged(int)` / `onWindowWidthChanged(int)`：调节窗宽窗位并刷新图像
- `onPresetChanged(int)`：切换窗宽窗位预设
- `loadSettings()` / `saveSettings()`：配置持久化（QSettings）

#### 3.2.2 SCPWorker（gui/scp/scp_worker.h/.cpp）

后台 Worker，继承 `QObject`，运行在 `QThread` 中执行阻塞的 DCMTK 网络操作。

**信号：**

```cpp
void logMessage(const QString& msg);          // 日志消息
void fileReceived(const QString& filePath);   // 接收到新文件
void serverStarted();                         // 服务启动成功
void serverStopped();                         // 服务已停止
void serverError(const QString& errorMsg);    // 启动失败
```

**核心方法 `startServer(const SCPConfig& config)` 执行流程：**

1. 创建输出目录，初始化 SQLite 索引并全量扫描已有文件
2. `ASC_initializeNetwork(NET_ACCEPTOR, port, timeout, &net)` — 绑定监听端口
3. `TlsHelper::setupTLS()` — 配置 TLS 加密传输层
4. 进入主循环，`ASC_receiveAssociation(net, &assoc, ..., OFTrue)` 等待 TLS 加密的 DICOM 连接
5. 接受所有 Presentation Context，`ASC_acknowledgeAssociation()` 确认关联
6. `DIMSE_receiveCommand()` 循环处理 DIMSE 命令：
   - `DIMSE_C_STORE_RQ`：`DIMSE_storeProvider()` 接收数据集，保存为 `.dcm` 文件，更新 SQLite 索引，返回成功响应
   - `DIMSE_C_ECHO_RQ`：返回 C-ECHO 响应
   - `DIMSE_C_FIND_RQ`：`DIMSE_findProvider()` 处理查询，通过回调在 SQLite 索引中匹配并逐条返回 Pending 响应
   - `DIMSE_C_MOVE_RQ`：`DIMSE_moveProvider()` 处理检索，匹配实例后建立子关联（客户端 TLS）以 C-STORE 方式回传文件
7. 对端释放或中止时，`ASC_destroyAssociation()` 清理关联

**线程安全策略：**

| 共享状态                  | 保护手段          | 跨线程通信                                         |
| ------------------------- | ----------------- | -------------------------------------------------- |
| `m_running`（运行标志） | `volatile bool` | Worker 轮询，UI 线程调用 `stopServer()` 置 false |
| 日志消息                  | 无共享内存        | 信号 `logMessage` → 槽（queued connection）     |
| 接收文件路径              | 无共享内存        | 信号 `fileReceived` → 槽（queued connection）   |

### 3.3 SCU 客户端模块

#### 3.3.1 SCUMainWindow（gui/scu/scu_main_window.h/.cpp）

客户端主窗口，包含以下区域：

| 区域                  | 控件                                                    | 功能                                               |
| --------------------- | ------------------------------------------------------- | -------------------------------------------------- |
| 网络配置              | QLineEdit × 4                                          | 服务端地址、端口、本地/远端 AE Title               |
| TLS 证书配置          | QLineEdit × 3 + QPushButton × 3                       | 客户端证书、私钥、CA 根证书                        |
| DICOM 文件选择        | QListWidget + QPushButton × 2                          | 多文件选择、移除（复用同一关联批量发送）           |
| **C-FIND 查询** | QComboBox + QLineEdit × 3 + QPushButton + QTableWidget | 查询层级、PatientID、StudyDate、Modality、结果表格 |
| **C-MOVE 检索** | QLineEdit × 5 + QPushButton × 2                       | 目标 AE、监听端口、输出目录、PatientID、StudyUID   |
| 发送控制              | QPushButton + QProgressBar                              | 发送按钮 + 进度条                                  |
| 状态显示              | QLabel                                                  | 操作结果（成功/失败）                              |
| 运行日志              | QTextEdit                                               | TLS 握手、Association、C-STORE/C-FIND/C-MOVE 日志  |

**核心槽函数：**

- `onSend()`：批量发送选中的 DICOM 文件（复用同一 Association）
- `onFind()`：执行 C-FIND 查询，结果填入表格
- `onMove()`：执行 C-MOVE 检索，SCP 通过子关联回传文件到输出目录
- `onLogMessage()`：日志追加
- `onSendProgress()` / `onFileProgress()`：进度更新
- `onSendFinished()` / `onFindFinished()` / `onMoveFinished()`：操作完成，恢复控件状态

#### 3.3.2 SCUWorker（gui/scu/scu_worker.h/.cpp）

后台 Worker，继承 `QObject`，运行在 `QThread` 中执行 DICOM 网络操作。

**信号：**

```cpp
void logMessage(const QString& msg);
void sendProgress(const QString& step);
void fileProgress(int current, int total);
void sendFinished(bool success, const QString& message);
void findFinished(bool success, const QString& message,
                  const QList<FindResult>& results);
void moveFinished(bool success, const QString& message, int receivedCount);
```

> **注意**：`findFinished` 携带 `QList<FindResult>` 跨线程传递，必须通过 `Q_DECLARE_METATYPE(FindResult)` / `Q_DECLARE_METATYPE(QList<FindResult>)` + `qRegisterMetaType` 注册为 Qt 元类型，否则 queued connection 会静默失败。

**核心方法：**

**（1）`sendFile(const SCUConfig& config)` — 多文件批量 C-STORE**

1. `ASC_initializeNetwork(NET_REQUESTOR, 0, timeout, &net)` — 初始化客户端网络
2. `TlsHelper::setupTLS()` — 配置 TLS
3. 预扫描所有文件，收集 SOP Class UID 集合（用于提议 Presentation Context）
4. 创建 Association 参数，设置 AE Title、Presentation Address、按优先级提议多个传输语法
5. `ASC_requestAssociation()` — 发起 TLS 加密的 DICOM 关联（一次性提议所有 SOP Class）
6. 循环发送每个文件：
   - `ASC_findAcceptedPresentationContextID()` 获取被接受的 PC
   - `DcmFileFormat::loadFile()` + `getAndRemoveDataset()` 取出数据集
   - `DIMSE_storeUser()` 发送 C-STORE 请求（30s 超时）
   - 累计成功/失败计数
7. `ASC_releaseAssociation()` / `ASC_abortAssociation()` 释放关联
8. `ASC_dropNetwork()` 释放网络资源

**（2）`findStudies(config, queryLevel, patientID, studyDate, modality)` — C-FIND 查询**

1. 初始化网络 + TLS
2. 提议 `FINDStudyRootQueryRetrieveInformationModel` Presentation Context（Implicit VR Little Endian）
3. `ASC_requestAssociation()` 建立关联
4. 构建查询标识符数据集（`QueryRetrieveLevel` + 查询键，留空不限定，`*` 通配）
5. `DIMSE_findUser()` 执行查询（30s 超时），通过回调收集 Pending 响应到 `QList<FindResult>`
6. 释放关联，返回结果列表

**（3）`moveStudies(config, moveDestAE, listenPort, outputDir, patientID, studyUID)` — C-MOVE 检索**

1. 初始化主网络 + TLS（客户端模式），建立主关联，提议 `MOVEStudyRootQueryRetrieveInformationModel`
2. 初始化子关联监听网络（`NET_ACCEPTOR` 模式，监听 `listenPort`），配置**服务端 TLS**
3. 构建 C-MOVE 请求标识符（`QueryRetrieveLevel=STUDY` + PatientID/StudyUID）
4. `DIMSE_moveUser(assoc, presID, &rq, reqIds, callback, DIMSE_BLOCKING, 60, subNet, subOpCallback, ...)` 执行检索
   - 主关联发送 C-MOVE-RQ 并接收 C-MOVE-RSP
   - 子关联 `subOpProviderCallback` 中接受 SCP 回连，循环接收 C-STORE 并保存到 `outputDir`
5. 释放子关联网络和主关联网络，返回接收文件数

---

## 4. 数据流与时序

### 4.1 TLS 加密的 DICOM C-STORE 完整时序

```
SCU (客户端)                          SCP (服务端)
    │                                     │
    │ 1. TCP 连接                         │
    ├────────────────────────────────────▶│
    │                                     │
    │ 2. TLS 握手（双向证书认证）          │
    │    ClientHello                      │
    ├────────────────────────────────────▶│
    │                        ServerHello  │
    │                        Certificate  │
    │◀────────────────────────────────────┤
    │    Certificate (client)            │
    ├────────────────────────────────────▶│
    │    ChangeCipherSpec / Finished      │
    │◀───────────────────────────────────▶│
    │                                     │
    │ 3. A-ASSOCIATE-RQ (加密)            │
    ├────────────────────────────────────▶│
    │                        A-ASSOCIATE-AC│
    │◀────────────────────────────────────┤
    │                                     │
    │ 4. C-STORE-RQ + Dataset (加密)      │
    ├────────────────────────────────────▶│
    │                        C-STORE-RSP  │
    │◀────────────────────────────────────┤
    │                                     │
    │ 5. A-RELEASE-RQ                     │
    ├────────────────────────────────────▶│
    │                        A-RELEASE-RP │
    │◀────────────────────────────────────┤
    │                                     │
    │ 6. TLS close_notify                 │
    │◀───────────────────────────────────▶│
```

### 4.2 C-MOVE 检索双关联时序

```
SCU (客户端)                          SCP (服务端)
    │  主关联 (C-MOVE)                    │  子关联 (C-STORE 回传)
    │                                     │
    │ 1. A-ASSOCIATE-RQ (MOVE)           │
    ├────────────────────────────────────▶│
    │                        A-ASSOCIATE-AC│
    │◀────────────────────────────────────┤
    │                                     │
    │ 2. C-MOVE-RQ (MoveDest=TLS_SCU)    │
    ├────────────────────────────────────▶│
    │                                     │
    │                                     │ 3. 匹配实例，建立子关联
    │                                     │    (NET_REQUESTOR + 客户端证书)
    │◀════════════════════════════════════│  TCP + TLS 握手
    │                                     │
    │ 4. 子关联 A-ASSOCIATE-RQ (C-STORE) │
    │◀────────────────────────────────────┤
    │    A-ASSOCIATE-AC                   │
    ├────────────────────────────────────▶│
    │                                     │
    │ 5. C-STORE-RQ + Dataset            │
    │◀────────────────────────────────────┤
    │    C-STORE-RSP (Success)            │
    ├────────────────────────────────────▶│
    │                                     │
    │ 6. C-MOVE-RSP (Pending/Success)    │
    │◀────────────────────────────────────┤
    │                                     │
    │ 7. 子关联 A-RELEASE                 │
    │    主关联 A-RELEASE                 │
    │◀───────────────────────────────────▶│
```

### 4.3 GUI 线程交互时序（以 SCU C-FIND 为例）

```
UI 线程 (SCUMainWindow)              工作线程 (SCUWorker)
    │                                     │
    │ 用户点击"查询"                       │
    │──onFind()                           │
    │  UI 线程预先采集所有输入值（按值捕获）│
    │  创建 QThread + SCUWorker           │
    │  moveToThread(thread)               │
    │  禁用所有控件                        │
    │  thread.start()                     │
    ├────────────────────────────────────▶│  findStudies(config, level, ...)
    │                                     │── ASC_initializeNetwork
    │                                     │── TlsHelper::setupTLS
    │                                     │── ASC_requestAssociation
    │  ◀────── logMessage(...) ───────────┤
    │                                     │── DIMSE_findUser (30s 超时)
    │  ◀────── findFinished(success, msg, │
    │             QList<FindResult>) ─────┤  ← queued connection，需元类型注册
    │──onFindFinished()                   │
    │  填充结果表格                        │
    │  恢复控件                            │
    │  worker.deleteLater()               │
    │  thread.quit() / wait()             │
    │  thread.deleteLater()               │
```

---

## 5. 关键技术决策

### 5.1 TLS 双向认证

- 服务端和客户端各自持有由同一 CA 签发的证书
- 两端均设置 `DCV_requireCertificate`，要求对端提供有效证书
- 通过 CA 根证书验证对端证书的合法性

### 5.2 TLS 1.2 强制

DCMTK 3.6.4 与 OpenSSL 1.1.1 的 TLS 1.3 握手存在兼容性问题（"no suitable signature algorithm"）。通过 `SSL_CTX_set_options()` 禁用 TLS 1.3 及以下版本，仅保留 TLS 1.2：

```cpp
SSL_CTX_set_options(sslCtx,
    SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
    SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1_3);
```

### 5.3 Qt 多线程设计

- DCMTK 的网络操作（`ASC_receiveAssociation`、`DIMSE_receiveCommand`、`DIMSE_storeUser`、`DIMSE_findUser`、`DIMSE_moveUser`）是阻塞调用
- 将这些操作放入 `QThread` 中执行，避免阻塞 UI 线程
- Worker 通过信号槽（queued connection）与 UI 线程通信
- **UI 线程预先采集输入值按值传入 lambda**，工作线程不得触碰 QWidget 控件
- 操作进行时禁用所有交互控件，完成后统一恢复
- **线程清理顺序**：`worker->deleteLater()` → `thread->quit()` → `thread->wait()` → `thread->deleteLater()`
- **超时设置**：C-FIND/C-STORE 30s，C-MOVE 60s，避免无限阻塞

### 5.4 跨线程自定义类型元类型注册

Qt queued connection 要求信号参数类型必须是已注册的元类型，否则信号投递会静默失败（槽函数不被调用）。

本项目中 `findFinished` 信号携带 `QList<FindResult>`，需要：

```cpp
// scu_worker.h
Q_DECLARE_METATYPE(FindResult)
Q_DECLARE_METATYPE(QList<FindResult>)

// main.cpp（在 QApplication 创建前）
qRegisterMetaType<FindResult>("FindResult");
qRegisterMetaType<QList<FindResult>>("QList<FindResult>");
```

### 5.5 DCMTK 资源所有权

| 资源                      | 创建                                                    | 释放                                                                      | 所有权说明                                      |
| ------------------------- | ------------------------------------------------------- | ------------------------------------------------------------------------- | ----------------------------------------------- |
| `T_ASC_Network*`        | `ASC_initializeNetwork`                               | `ASC_dropNetwork`                                                       | 调用者负责                                      |
| `T_ASC_Association*`    | `ASC_requestAssociation` / `ASC_receiveAssociation` | `ASC_destroyAssociation`                                                | 调用者负责                                      |
| `T_ASC_Parameters*`     | `ASC_createAssociationParameters`                     | 成功后由 `assoc` 接管；失败时手动 `ASC_destroyAssociationParameters`  | **关键**：成功后 assoc 接管，不可手动释放 |
| `DcmDataset*`           | `getAndRemoveDataset`                                 | 调用者 `delete`（C-STORE SCU）；`DIMSE_storeProvider` 内部接管（SCP） | 注意区分调用方角色                              |
| `DcmTLSTransportLayer*` | `new`                                                 | `ASC_setTransportLayer(net, layer, 1)` 后由 DCMTK 接管                  | 第 3 个参数 `1` 表示移交所有权                |

> **C-MOVE 子关联特别注意**：`ASC_requestAssociation(subNet, subParams, &subAssoc)` 成功后，`subAssoc->params` 仍指向原始 `subParams`。**不能**提前调用 `ASC_destroyAssociationParameters(&subParams)`，否则 `ASC_findAcceptedPresentationContextID` 返回 0 且 `ASC_destroyAssociation` 时 double-free。应由 `ASC_destroyAssociation(&subAssoc)` 统一释放。

### 5.6 多传输语法协商

SCU 提议 9 种传输语法（按优先级排序），对端选择第一个支持的返回：

| 优先级 | 传输语法                      | UID                        |
| ------ | ----------------------------- | -------------------------- |
| 1      | Explicit VR Little Endian     | `1.2.840.10008.1.2.1`    |
| 2      | Implicit VR Little Endian     | `1.2.840.10008.1.2`      |
| 3      | Explicit VR Big Endian        | `1.2.840.10008.1.2.2`    |
| 4      | RLE Lossless                  | `1.2.840.10008.1.2.5`    |
| 5      | JPEG Lossless (Process 14)    | `1.2.840.10008.1.2.4.57` |
| 6      | JPEG-LS Lossless              | `1.2.840.10008.1.2.4.80` |
| 7      | JPEG Baseline (Process 1)     | `1.2.840.10008.1.2.4.50` |
| 8      | JPEG Extended (Process 2 & 4) | `1.2.840.10008.1.2.4.51` |
| 9      | JPEG-LS Lossy                 | `1.2.840.10008.1.2.4.81` |

所有 4 个入口点在启动时注册 RLE/JPEG/JPEG-LS 编解码器。

---

## 6. 构建与部署

### 6.1 依赖安装

**Linux (Ubuntu/Debian)：**

```bash
sudo apt install libdcmtk-dev libssl-dev qtbase5-dev libsqlite3-dev
```

**手动指定 DCMTK 路径（无 root 权限时）：**

```bash
cmake .. -DDCMTK_DIR=/path/to/dcmtk/usr/lib/x86_64-linux-gnu/cmake/dcmtk
```

### 6.2 编译

```bash
cd dicom_tls_demo
mkdir build && cd build
cmake .. -DDCMTK_DIR=/path/to/dcmtk/cmake/dcmtk
make -j$(nproc)
```

编译产物：`build/tls_scp`、`build/tls_scu`、`build/scp_gui`、`build/scu_gui`

### 6.3 运行环境变量

```bash
export LD_LIBRARY_PATH=/path/to/dcmtk/lib       # DCMTK 库路径
export DCMDICTPATH=/path/to/dcmtk/share/dicom.dic  # DICOM 字典
unset OPENSSL_CONF                                  # 避免系统 OpenSSL 配置干扰 TLS 1.2
```

### 6.4 证书生成

```bash
./generate_certs.sh
# 生成 certs/ca.{crt,key}, certs/server.{crt,key}, certs/client.{crt,key}
```

### 6.5 运行

**命令行版本：**

```bash
# SCP 服务端（端口, AE Title, 接收目录, C-MOVE回连端口）
./build/tls_scp 11112 TLS_SCP ./received 11113

# SCU 发送
./build/tls_scu 127.0.0.1 11112 TLS_SCU TLS_SCP file1.dcm file2.dcm

# SCU C-FIND 查询
./build/tls_scu --find 127.0.0.1 11112 TLS_SCU TLS_SCP STUDY PAT001

# SCU C-MOVE 检索
./build/tls_scu --move 127.0.0.1 11112 TLS_SCU TLS_SCP TLS_SCU 11113 ./retrieved PAT001
```

**GUI 版本：**

```bash
./build/scp_gui   # 服务端，点击"启动服务"
./build/scu_gui   # 客户端，配置后点击"发送"/"查询"/"检索"
```

---

## 7. 已知问题与解决方案

| 问题                                    | 原因                                                                                                               | 解决方案                                                                                                               |
| --------------------------------------- | ------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------- |
| TLS 1.3 握手失败 "wrong version number" | DCMTK 3.6.4 + OpenSSL 1.1.1 不兼容 TLS 1.3                                                                         | `SSL_CTX_set_options` 强制 TLS 1.2                                                                                   |
| SCP 未使用 TLS                          | `ASC_receiveAssociation` 未启用安全层                                                                            | 添加 `useSecureLayer=OFTrue` 参数                                                                                    |
| SCU 双重释放崩溃                        | `ASC_destroyAssociationParameters` 与 `ASC_destroyAssociation` 重复释放 params                                 | 成功路径不调用 `ASC_destroyAssociationParameters`，由 assoc 接管                                                     |
| DIMSE_storeUser dataset 悬垂            | 直接 `ff.getDataset()` 后 `ff` 析构导致 dataset 悬垂                                                           | 使用 `ff.getAndRemoveDataset()` 移出 dataset                                                                         |
| DcmXfer() 悬垂指针                      | 临时 `DcmXfer` 对象析构后 `getXferID()` 返回悬垂指针                                                           | 改用静态常量 `UID_LittleEndianExplicitTransferSyntax` 等                                                             |
| C-MOVE 子关联 presID=0 + double-free    | 提前调用 `ASC_destroyAssociationParameters(&subParams)` 导致 `subAssoc->params` 悬垂                           | 移除提前销毁，由 `ASC_destroyAssociation(&subAssoc)` 统一释放 params                                                 |
| C-MOVE 子关联 TLS 角色错误              | SCP 回连时误用服务端证书，SCU 监听时误用客户端证书                                                                 | SCP 回连用 `NET_REQUESTOR` + 客户端证书；SCU 监听用 `NET_ACCEPTOR` + 服务端证书                                    |
| **GUI 查询无反应 + 发送按钮禁用** | `FindResult` / `QList<FindResult>` 未注册为 Qt 元类型，queued connection 静默失败，`onFindFinished` 永不调用 | `Q_DECLARE_METATYPE` + `qRegisterMetaType` 注册自定义类型                                                          |
| **GUI C-MOVE 检索按钮点击无反应** | `QGridLayout` 中按钮与说明标签在第 1 列重叠，标签在上层拦截鼠标点击                                              | 将说明标签移到下一行独占整行（`(4, 0, 1, 4)`）                                                                       |
| GUI 操作假死不返回                      | `DIMSE_BLOCKING, 0` 无限超时                                                                                     | C-FIND/C-STORE 设 30s，C-MOVE 设 60s                                                                                   |
| GUI 卡死死机                            | `onFind()` lambda 在工作线程访问 UI 控件；线程清理顺序错误                                                       | UI 线程预先采集值按值传入；清理顺序改为 `deleteLater(worker)` → `quit()` → `wait()` → `deleteLater(thread)` |

---

## 8. 功能实现清单

### 8.1 C-STORE 多文件批量发送 ✅

- `SCUConfig::dcmFiles` 改为 `QStringList`
- `SCUWorker::sendFile` 预扫描所有文件，一次性提议所有 SOP Class 的 Presentation Context，复用同一 Association 循环发送
- UI 支持 `QFileDialog::getOpenFileNames` 多选，文件列表显示与移除
- 累计成功/失败计数，全部完成后统一释放 Association

### 8.2 DICOM 图像窗宽/窗位交互调节 ✅

- `DicomImageUtil::loadDicomImage` 支持 `windowCenter` / `windowWidth` 参数
- SCP 主窗口图像区添加窗位/窗宽 QSlider + 预设下拉框（CT 肺窗/骨窗/软组织窗/默认）
- 滑块变化时重新调用 `setWindow` 并刷新 QImage

### 8.3 C-FIND / C-MOVE 查询检索 ✅

**（1）C-FIND 查询**

- SCU：`DIMSE_findUser` + 回调收集 Pending 响应
- SCP：`DIMSE_findProvider` 回调中查询 SQLite 索引，逐条返回
- SOP Class：`FINDStudyRootQueryRetrieveInformationModel`（1.2.840.10008.5.1.4.1.2.2.1）
- 支持查询层级：PATIENT / STUDY / SERIES / IMAGE

**（2）C-MOVE 检索**

- SCU：`DIMSE_moveUser` + 子关联监听网络接收 C-STORE 回传
- SCP：`DIMSE_moveProvider` 回调匹配实例，建立子关联（客户端 TLS）以 C-STORE 回传
- SOP Class：`MOVEStudyRootQueryRetrieveInformationModel`（1.2.840.10008.5.1.4.1.2.2.2）
- 子关联 TLS 角色：SCP 回连为 `NET_REQUESTOR`（客户端证书），SCU 监听为 `NET_ACCEPTOR`（服务端证书）

**（3）本地索引**

- SQLite 单表 `instance`，20 字段，主键 `sopInstanceUID`
- SCP 启动时全量扫描 `outputDir` 重建索引；接收新文件时增量插入
- 通配符 `*` 转 SQL `%`，按查询层级 `GROUP BY` 去重

### 8.4 GUI 配置持久化 ✅

- `QSettings`（`IniFormat` + `UserScope`），组织名 `DICOM_TLS_Demo`
- 窗口关闭时 `saveSettings()`，构造时 `loadSettings()`
- 提供"恢复默认值"按钮

**持久化字段：**

| SCP 端               | SCU 端                 |
| -------------------- | ---------------------- |
| `scp/port`         | `scu/host`           |
| `scp/moveDestPort` | `scu/port`           |
| `scp/aeTitle`      | `scu/ourAETitle`     |
| `scp/outputDir`    | `scu/peerAETitle`    |
| `scp/certFile`     | `scu/certFile`       |
| `scp/keyFile`      | `scu/keyFile`        |
| `scp/caFile`       | `scu/caFile`         |
|                      | `scu/findLevel`      |
|                      | `scu/findPatientID`  |
|                      | `scu/findStudyDate`  |
|                      | `scu/findModality`   |
|                      | `scu/moveDestAE`     |
|                      | `scu/moveListenPort` |
|                      | `scu/moveOutputDir`  |
|                      | `scu/movePatientID`  |
|                      | `scu/moveStudyUID`   |

### 8.5 多传输语法协商 ✅

SCU 提议 9 种传输语法，SCP 接受第一个匹配的。所有入口点注册 RLE/JPEG/JPEG-LS 编解码器。

---

## 9. 扩展方向

| 方向              | 优先级 | 说明                                                                    |
| ----------------- | ------ | ----------------------------------------------------------------------- |
| TLS 证书指纹校验  | P2     | 在日志中显示对端证书的 SHA-256 指纹，增强身份验证可视化                 |
| 传输速率统计      | P2     | 在 SCU 发送时统计并显示吞吐量（MB/s）和剩余时间                         |
| 接收文件拖拽      | P2     | SCP 支持将接收到的 DICOM 文件从列表拖拽到外部应用                       |
| 多客户端并发      | P2     | SCP 使用 `ASC_receiveAssociation` 的非阻塞模式，支持多个 SCU 同时连接 |
| 日志导出          | P2     | GUI 日志支持导出为文本文件，便于问题排查                                |
| C-GET 检索        | P2     | 替代 C-MOVE 的单关联检索模式（无需子关联）                              |
| Modality Worklist | P3     | 支持 C-FIND Modality Worklist SOP Class                                 |
