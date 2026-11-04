// ============================================================
//  DICOM 文件索引（基于 SQLite）
//  提供 Patient/Study/Series/Instance 四级索引与查询
// ============================================================
#ifndef DICOM_INDEX_H
#define DICOM_INDEX_H

#include <string>
#include <vector>
#include <map>
#include <sqlite3.h>

// 单条 DICOM 实例记录
struct DicomRecord {
    std::string patientID;
    std::string patientName;
    std::string patientBirthDate;
    std::string patientSex;
    std::string studyInstanceUID;
    std::string studyDate;
    std::string studyTime;
    std::string studyDescription;
    std::string modalitiesInStudy;
    std::string seriesInstanceUID;
    std::string seriesNumber;
    std::string modality;
    std::string seriesDescription;
    std::string sopInstanceUID;
    std::string sopClassUID;
    std::string instanceNumber;
    std::string rows;
    std::string columns;
    std::string bitsAllocated;
    std::string filePath;       // 磁盘上的完整路径
};

// 查询条件（字段名 -> 值，空值表示不限制）
typedef std::map<std::string, std::string> QueryCondition;

class DicomIndex
{
public:
    DicomIndex();
    ~DicomIndex();

    // 打开/创建索引数据库（dbPath 为 SQLite 文件路径）
    bool open(const std::string& dbPath);

    // 关闭数据库
    void close();

    // 扫描目录，重建索引（先清空再重新索引）
    int scanDirectory(const std::string& dirPath);

    // 增量添加单个 DICOM 文件到索引
    bool addFile(const std::string& filePath);

    // 按条件查询，返回匹配的记录列表
    std::vector<DicomRecord> query(const QueryCondition& cond,
                                    const std::string& queryLevel = "STUDY");

    // 获取索引中的记录总数
    int count();

private:
    sqlite3* m_db;

    // 创建表结构
    bool createTables();

    // 从 DICOM 文件读取关键字段
    bool readDicomTags(const std::string& filePath, DicomRecord& rec);

    // 判断文件是否为 DICOM 文件
    bool isDicomFile(const std::string& filePath);
};

#endif // DICOM_INDEX_H
