// ============================================================
//  DICOM TLS SCU GUI 入口
// ============================================================
#include <QApplication>
#include <QDir>
#include <QFileInfo>
#include <openssl/ssl.h>

#include "dcmtk/dcmdata/dcrleerg.h"
#include "dcmtk/dcmdata/dcrledrg.h"
#include "dcmtk/dcmjpeg/djencode.h"
#include "dcmtk/dcmjpeg/djdecode.h"
#include "dcmtk/dcmjpls/djencode.h"
#include "dcmtk/dcmjpls/djdecode.h"

#include "scu_main_window.h"
#include "scu_worker.h"

int main(int argc, char* argv[])
{
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);

    // 注册自定义元类型，供跨线程 queued signal/slot 传递
    qRegisterMetaType<FindResult>("FindResult");
    qRegisterMetaType<QList<FindResult>>("QList<FindResult>");

    // 注册 DICOM 压缩传输语法编解码器（RLE / JPEG / JPEG-LS）
    DcmRLEEncoderRegistration::registerCodecs();
    DcmRLEDecoderRegistration::registerCodecs();
    DJEncoderRegistration::registerCodecs();
    DJDecoderRegistration::registerCodecs();
    DJLSEncoderRegistration::registerCodecs();
    DJLSDecoderRegistration::registerCodecs();

    QApplication app(argc, argv);
    app.setApplicationName("DICOM TLS SCU");

    // 智能设置工作目录：确保相对路径的证书文件能找到
    // 1. 如果当前目录已有 certs/，保持不变
    // 2. 否则尝试可执行文件所在目录的上级目录（build/ 的上级 = 项目根）
    if (!QFileInfo::exists("./certs")) {
        QString appDir = QCoreApplication::applicationDirPath();
        QDir appDirObj(appDir);
        if (appDirObj.cdUp()) {
            if (QFileInfo::exists(appDirObj.absoluteFilePath("certs"))) {
                QDir::setCurrent(appDirObj.absolutePath());
            } else {
                QDir::setCurrent(appDir);
            }
        }
    }

    SCUMainWindow w;
    w.show();

    return app.exec();
}
