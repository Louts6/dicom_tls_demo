// ============================================================
//  DICOM 文件索引（基于 SQLite）实现
// ============================================================
#include "dicom_index.h"

#include <dcmtk/dcmdata/dcfilefo.h>
#include <dcmtk/dcmdata/dcdeftag.h>
#include <dcmtk/dcmdata/dcuid.h>

#include <sys/stat.h>
#include <dirent.h>
#include <cstring>
#include <algorithm>

// 递归遍历目录获取所有文件
static void listFiles(const std::string& dir, std::vector<std::string>& files)
{
    DIR* d = opendir(dir.c_str());
    if (!d) return;
    struct dirent* entry;
    while ((entry = readdir(d)) != NULL) {
        std::string name = entry->d_name;
        if (name == "." || name == "..") continue;
        std::string fullPath = dir + "/" + name;
        struct stat st;
        if (stat(fullPath.c_str(), &st) == 0) {
            if (S_ISDIR(st.st_mode)) {
                listFiles(fullPath, files);
            } else {
                files.push_back(fullPath);
            }
        }
    }
    closedir(d);
}

DicomIndex::DicomIndex() : m_db(NULL) {}

DicomIndex::~DicomIndex()
{
    close();
}

bool DicomIndex::open(const std::string& dbPath)
{
    close();
    int rc = sqlite3_open(dbPath.c_str(), &m_db);
    if (rc != SQLITE_OK) {
        return false;
    }
    // 启用 WAL 模式提升并发性能
    sqlite3_exec(m_db, "PRAGMA journal_mode=WAL;", NULL, NULL, NULL);
    sqlite3_exec(m_db, "PRAGMA synchronous=NORMAL;", NULL, NULL, NULL);
    return createTables();
}

void DicomIndex::close()
{
    if (m_db) {
        sqlite3_close(m_db);
        m_db = NULL;
    }
}

bool DicomIndex::createTables()
{
    if (!m_db) return false;
    const char* sql =
        "CREATE TABLE IF NOT EXISTS instance ("
        "  patientID TEXT,"
        "  patientName TEXT,"
        "  patientBirthDate TEXT,"
        "  patientSex TEXT,"
        "  studyInstanceUID TEXT,"
        "  studyDate TEXT,"
        "  studyTime TEXT,"
        "  studyDescription TEXT,"
        "  modalitiesInStudy TEXT,"
        "  seriesInstanceUID TEXT,"
        "  seriesNumber TEXT,"
        "  modality TEXT,"
        "  seriesDescription TEXT,"
        "  sopInstanceUID TEXT PRIMARY KEY,"
        "  sopClassUID TEXT,"
        "  instanceNumber TEXT,"
        "  rows TEXT,"
        "  columns TEXT,"
        "  bitsAllocated TEXT,"
        "  filePath TEXT"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_patientID ON instance(patientID);"
        "CREATE INDEX IF NOT EXISTS idx_studyUID ON instance(studyInstanceUID);"
        "CREATE INDEX IF NOT EXISTS idx_seriesUID ON instance(seriesInstanceUID);"
        "CREATE INDEX IF NOT EXISTS idx_modality ON instance(modality);"
        "CREATE INDEX IF NOT EXISTS idx_studyDate ON instance(studyDate);";

    char* errMsg = NULL;
    int rc = sqlite3_exec(m_db, sql, NULL, NULL, &errMsg);
    if (rc != SQLITE_OK) {
        if (errMsg) sqlite3_free(errMsg);
        return false;
    }
    return true;
}

bool DicomIndex::isDicomFile(const std::string& filePath)
{
    // 检查 DICM 前缀
    FILE* f = fopen(filePath.c_str(), "rb");
    if (!f) return false;
    char buf[132];
    size_t n = fread(buf, 1, 132, f);
    fclose(f);
    if (n < 132) return false;
    return memcmp(buf + 128, "DICM", 4) == 0;
}

bool DicomIndex::readDicomTags(const std::string& filePath, DicomRecord& rec)
{
    DcmFileFormat fileFormat;
    OFCondition cond = fileFormat.loadFile(filePath.c_str());
    if (cond.bad()) return false;

    DcmDataset* dataset = fileFormat.getDataset();
    if (!dataset) return false;

    rec.filePath = filePath;

    OFString val;
    if (dataset->findAndGetOFString(DCM_PatientID, val).good())
        rec.patientID = val.c_str();
    if (dataset->findAndGetOFString(DCM_PatientName, val).good())
        rec.patientName = val.c_str();
    if (dataset->findAndGetOFString(DCM_PatientBirthDate, val).good())
        rec.patientBirthDate = val.c_str();
    if (dataset->findAndGetOFString(DCM_PatientSex, val).good())
        rec.patientSex = val.c_str();
    if (dataset->findAndGetOFString(DCM_StudyInstanceUID, val).good())
        rec.studyInstanceUID = val.c_str();
    if (dataset->findAndGetOFString(DCM_StudyDate, val).good())
        rec.studyDate = val.c_str();
    if (dataset->findAndGetOFString(DCM_StudyTime, val).good())
        rec.studyTime = val.c_str();
    if (dataset->findAndGetOFString(DCM_StudyDescription, val).good())
        rec.studyDescription = val.c_str();
    if (dataset->findAndGetOFString(DCM_ModalitiesInStudy, val).good())
        rec.modalitiesInStudy = val.c_str();
    if (dataset->findAndGetOFString(DCM_SeriesInstanceUID, val).good())
        rec.seriesInstanceUID = val.c_str();
    if (dataset->findAndGetOFString(DCM_SeriesNumber, val).good())
        rec.seriesNumber = val.c_str();
    if (dataset->findAndGetOFString(DCM_Modality, val).good())
        rec.modality = val.c_str();
    if (dataset->findAndGetOFString(DCM_SeriesDescription, val).good())
        rec.seriesDescription = val.c_str();
    if (dataset->findAndGetOFString(DCM_SOPInstanceUID, val).good())
        rec.sopInstanceUID = val.c_str();
    if (dataset->findAndGetOFString(DCM_SOPClassUID, val).good())
        rec.sopClassUID = val.c_str();
    if (dataset->findAndGetOFString(DCM_InstanceNumber, val).good())
        rec.instanceNumber = val.c_str();
    if (dataset->findAndGetOFString(DCM_Rows, val).good())
        rec.rows = val.c_str();
    if (dataset->findAndGetOFString(DCM_Columns, val).good())
        rec.columns = val.c_str();
    if (dataset->findAndGetOFString(DCM_BitsAllocated, val).good())
        rec.bitsAllocated = val.c_str();

    return !rec.sopInstanceUID.empty();
}

bool DicomIndex::addFile(const std::string& filePath)
{
    if (!m_db) return false;

    DicomRecord rec;
    if (!readDicomTags(filePath, rec)) return false;

    // 插入或替换（以 SOPInstanceUID 为主键）
    const char* sql =
        "INSERT OR REPLACE INTO instance ("
        "patientID, patientName, patientBirthDate, patientSex,"
        "studyInstanceUID, studyDate, studyTime, studyDescription, modalitiesInStudy,"
        "seriesInstanceUID, seriesNumber, modality, seriesDescription,"
        "sopInstanceUID, sopClassUID, instanceNumber, rows, columns, bitsAllocated, filePath"
        ") VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";

    sqlite3_stmt* stmt = NULL;
    if (sqlite3_prepare_v2(m_db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return false;
    }

    sqlite3_bind_text(stmt, 1, rec.patientID.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, rec.patientName.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, rec.patientBirthDate.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, rec.patientSex.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, rec.studyInstanceUID.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, rec.studyDate.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 7, rec.studyTime.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 8, rec.studyDescription.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 9, rec.modalitiesInStudy.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 10, rec.seriesInstanceUID.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 11, rec.seriesNumber.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 12, rec.modality.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 13, rec.seriesDescription.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 14, rec.sopInstanceUID.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 15, rec.sopClassUID.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 16, rec.instanceNumber.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 17, rec.rows.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 18, rec.columns.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 19, rec.bitsAllocated.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 20, rec.filePath.c_str(), -1, SQLITE_TRANSIENT);

    bool ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return ok;
}

int DicomIndex::scanDirectory(const std::string& dirPath)
{
    if (!m_db) return 0;

    // 清空现有索引
    sqlite3_exec(m_db, "DELETE FROM instance;", NULL, NULL, NULL);

    std::vector<std::string> files;
    listFiles(dirPath, files);

    int count = 0;
    for (size_t i = 0; i < files.size(); i++) {
        if (isDicomFile(files[i])) {
            if (addFile(files[i])) count++;
        }
    }
    return count;
}

std::vector<DicomRecord> DicomIndex::query(const QueryCondition& cond,
                                            const std::string& queryLevel)
{
    std::vector<DicomRecord> results;
    if (!m_db) return results;

    // 构建 WHERE 子句（支持通配符匹配，* 转为 %）
    std::string where = "1=1";
    for (QueryCondition::const_iterator it = cond.begin(); it != cond.end(); ++it) {
        if (it->second.empty()) continue;
        std::string val = it->second;
        // 将 DICOM 通配符 * 转为 SQL 通配符 %
        std::replace(val.begin(), val.end(), '*', '%');
        where += " AND " + it->first + " LIKE '" + val + "'";
    }

    // 按查询层级去重
    std::string groupBy;
    if (queryLevel == "PATIENT") {
        groupBy = " GROUP BY patientID";
    } else if (queryLevel == "STUDY") {
        groupBy = " GROUP BY studyInstanceUID";
    } else if (queryLevel == "SERIES") {
        groupBy = " GROUP BY seriesInstanceUID";
    }

    std::string sql = "SELECT patientID, patientName, patientBirthDate, patientSex,"
                      "studyInstanceUID, studyDate, studyTime, studyDescription, modalitiesInStudy,"
                      "seriesInstanceUID, seriesNumber, modality, seriesDescription,"
                      "sopInstanceUID, sopClassUID, instanceNumber, rows, columns, bitsAllocated, filePath "
                      "FROM instance WHERE " + where + groupBy +
                      " ORDER BY studyDate DESC, seriesNumber, instanceNumber";

    sqlite3_stmt* stmt = NULL;
    if (sqlite3_prepare_v2(m_db, sql.c_str(), -1, &stmt, NULL) != SQLITE_OK) {
        return results;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        DicomRecord rec;
        rec.patientID = (const char*)sqlite3_column_text(stmt, 0);
        rec.patientName = (const char*)sqlite3_column_text(stmt, 1);
        rec.patientBirthDate = (const char*)sqlite3_column_text(stmt, 2);
        rec.patientSex = (const char*)sqlite3_column_text(stmt, 3);
        rec.studyInstanceUID = (const char*)sqlite3_column_text(stmt, 4);
        rec.studyDate = (const char*)sqlite3_column_text(stmt, 5);
        rec.studyTime = (const char*)sqlite3_column_text(stmt, 6);
        rec.studyDescription = (const char*)sqlite3_column_text(stmt, 7);
        rec.modalitiesInStudy = (const char*)sqlite3_column_text(stmt, 8);
        rec.seriesInstanceUID = (const char*)sqlite3_column_text(stmt, 9);
        rec.seriesNumber = (const char*)sqlite3_column_text(stmt, 10);
        rec.modality = (const char*)sqlite3_column_text(stmt, 11);
        rec.seriesDescription = (const char*)sqlite3_column_text(stmt, 12);
        rec.sopInstanceUID = (const char*)sqlite3_column_text(stmt, 13);
        rec.sopClassUID = (const char*)sqlite3_column_text(stmt, 14);
        rec.instanceNumber = (const char*)sqlite3_column_text(stmt, 15);
        rec.rows = (const char*)sqlite3_column_text(stmt, 16);
        rec.columns = (const char*)sqlite3_column_text(stmt, 17);
        rec.bitsAllocated = (const char*)sqlite3_column_text(stmt, 18);
        rec.filePath = (const char*)sqlite3_column_text(stmt, 19);
        results.push_back(rec);
    }
    sqlite3_finalize(stmt);
    return results;
}

int DicomIndex::count()
{
    if (!m_db) return 0;
    sqlite3_stmt* stmt = NULL;
    int count = 0;
    if (sqlite3_prepare_v2(m_db, "SELECT COUNT(*) FROM instance;", -1, &stmt, NULL) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            count = sqlite3_column_int(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }
    return count;
}
