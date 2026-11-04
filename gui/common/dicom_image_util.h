// ============================================================
//  DICOM 图像工具 - 将 DICOM 文件转换为 QImage 用于显示
// ============================================================
#ifndef DICOM_IMAGE_UTIL_H
#define DICOM_IMAGE_UTIL_H

#include <QImage>
#include <QString>
#include <QList>
#include "dcmtk/config/osconfig.h"

class DicomImageUtil
{
public:
    // 将 DICOM 文件加载为 QImage（用于 GUI 显示），使用自动窗宽窗位
    static QImage loadDicomImage(const QString& filePath);

    // 使用指定的窗位(center)和窗宽(width)加载 DICOM 图像
    // center=-1, width=-1 表示使用自动窗宽窗位
    static QImage loadDicomImage(const QString& filePath, double center, double width);

    // 获取 DICOM 文件的基本信息（用于列表显示）
    struct DicomInfo {
        QString sopClassUID;
        QString sopInstanceUID;
        QString patientName;
        QString studyDate;
        QString modality;
        int     width;
        int     height;
        bool    hasPixelData;
        // 推荐的窗宽窗位范围（用于滑块范围设置）
        double  minWindowCenter;
        double  maxWindowCenter;
        double  minWindowWidth;
        double  maxWindowWidth;
        double  defaultWindowCenter;
        double  defaultWindowWidth;
    };
    static DicomInfo getDicomInfo(const QString& filePath);

    // 常见 CT 预设窗口
    struct WindowPreset {
        QString name;
        double  center;
        double  width;
    };
    static QList<WindowPreset> commonPresets();
};

#endif // DICOM_IMAGE_UTIL_H
