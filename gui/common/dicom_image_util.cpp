// ============================================================
//  DICOM 图像工具实现
// ============================================================
#include "dicom_image_util.h"

#include "dcmtk/dcmimgle/dcmimage.h"
#include "dcmtk/dcmdata/dcfilefo.h"
#include "dcmtk/dcmdata/dcdeftag.h"
#include "dcmtk/dcmdata/dcuid.h"

QImage DicomImageUtil::loadDicomImage(const QString& filePath)
{
    return loadDicomImage(filePath, -1.0, -1.0);
}

QImage DicomImageUtil::loadDicomImage(const QString& filePath, double center, double width)
{
    QImage result;

    DicomImage* dcmImg = new DicomImage(
        filePath.toLocal8Bit().constData(),
        EXS_Unknown
    );

    if (dcmImg == NULL || dcmImg->getStatus() != EIS_Normal) {
        delete dcmImg;
        return result;
    }

    if (dcmImg->getFrameCount() == 0) {
        delete dcmImg;
        return result;
    }

    // 设置窗宽窗位
    if (center >= 0 && width > 0) {
        dcmImg->setWindow(center, width);
    } else {
        dcmImg->setMinMaxWindow();
    }

    int imgWidth  = dcmImg->getWidth();
    int imgHeight = dcmImg->getHeight();

    const void* pixelData = dcmImg->getOutputData(8 /* bits */);
    if (pixelData == NULL || imgWidth <= 0 || imgHeight <= 0) {
        delete dcmImg;
        return result;
    }

    int samplesPerPixel = dcmImg->isMonochrome() ? 1 : 3;

    if (samplesPerPixel == 1) {
        result = QImage(imgWidth, imgHeight, QImage::Format_Grayscale8);
        if (!result.isNull()) {
            memcpy(result.bits(), pixelData, (size_t)(imgWidth * imgHeight));
        }
    } else {
        result = QImage(imgWidth, imgHeight, QImage::Format_RGB888);
        if (!result.isNull()) {
            memcpy(result.bits(), pixelData, (size_t)(imgWidth * imgHeight * 3));
        }
    }

    delete dcmImg;
    return result;
}

DicomImageUtil::DicomInfo DicomImageUtil::getDicomInfo(const QString& filePath)
{
    DicomInfo info;
    info.width = 0;
    info.height = 0;
    info.hasPixelData = false;
    info.minWindowCenter = -1024.0;
    info.maxWindowCenter = 3071.0;
    info.minWindowWidth = 1.0;
    info.maxWindowWidth = 4096.0;
    info.defaultWindowCenter = 40.0;
    info.defaultWindowWidth = 400.0;

    DcmFileFormat fileFormat;
    OFCondition cond = fileFormat.loadFile(filePath.toLocal8Bit().constData());
    if (cond.bad()) {
        return info;
    }

    DcmDataset* dataset = fileFormat.getDataset();

    OFString str;
    if (dataset->findAndGetOFString(DCM_SOPClassUID, str).good()) {
        const char* name = dcmFindNameOfUID(str.c_str());
        info.sopClassUID = name ? QString::fromUtf8(name) : QString::fromUtf8(str.c_str());
    }
    if (dataset->findAndGetOFString(DCM_SOPInstanceUID, str).good()) {
        info.sopInstanceUID = QString::fromUtf8(str.c_str());
    }
    if (dataset->findAndGetOFString(DCM_PatientName, str).good()) {
        info.patientName = QString::fromUtf8(str.c_str());
    }
    if (dataset->findAndGetOFString(DCM_StudyDate, str).good()) {
        info.studyDate = QString::fromUtf8(str.c_str());
    }
    if (dataset->findAndGetOFString(DCM_Modality, str).good()) {
        info.modality = QString::fromUtf8(str.c_str());
    }

    if (dataset->findAndGetUint16(DCM_Rows, (Uint16&)info.height).good() &&
        dataset->findAndGetUint16(DCM_Columns, (Uint16&)info.width).good()) {
        info.hasPixelData = (info.width > 0 && info.height > 0);
    }

    // 尝试从 DICOM 文件读取 Window Center/Width
    double wc = 0.0, ww = 0.0;
    if (dataset->findAndGetFloat64(DCM_WindowCenter, wc).good() &&
        dataset->findAndGetFloat64(DCM_WindowWidth, ww).good() && ww > 0) {
        info.defaultWindowCenter = wc;
        info.defaultWindowWidth = ww;
    }

    // 根据位深估算合理的窗宽范围
    Uint16 bitsAllocated = 16;
    dataset->findAndGetUint16(DCM_BitsAllocated, bitsAllocated);
    double maxVal = (double)((1ULL << bitsAllocated) - 1);
    info.minWindowCenter = -maxVal / 2.0;
    info.maxWindowCenter = maxVal / 2.0;
    info.maxWindowWidth = maxVal;

    return info;
}

QList<DicomImageUtil::WindowPreset> DicomImageUtil::commonPresets()
{
    QList<WindowPreset> presets;
    presets.append({"自动", -1, -1});
    presets.append({"CT 肺窗", -500, 1500});
    presets.append({"CT 纵隔窗", 40, 400});
    presets.append({"CT 骨窗", 300, 1500});
    presets.append({"CT 脑窗", 40, 80});
    presets.append({"CT 腹部窗", 40, 250});
    return presets;
}
