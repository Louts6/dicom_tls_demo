# ============================================================
#  DICOM TLS 传输加密 Demo - CMake 构建配置
#  依赖：DCMTK (dcmdata, dcmnet, dcmtls) + OpenSSL
# ============================================================

cmake_minimum_required(VERSION 3.10)
project(DICOM_TLS_Demo CXX)

# C++ 标准
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ============================================================
#  查找 DCMTK
# ============================================================
# 方式 1：DCMTK 提供的 CMake config 文件（推荐）
find_package(DCMTK QUIET)

if(NOT DCMTK_FOUND)
    # 方式 2：手动指定 DCMTK 路径
    # Windows 下使用 DCMTK 预编译包时设置：
    #   cmake .. -DDCMTK_DIR="C:/dcmtk-3.6.7"
    # Linux 下通常在 /usr 或 /usr/local
    if(NOT DEFINED DCMTK_DIR)
        if(WIN32)
            set(DCMTK_DIR "C:/dcmtk" CACHE PATH "DCMTK 根目录")
        else()
            set(DCMTK_DIR "/usr/local" CACHE PATH "DCMTK 根目录")
        endif()
    endif()

    set(DCMTK_INCLUDE_DIRS
        ${DCMTK_DIR}/include
        ${DCMTK_DIR}/include/dcmtk
    )

    if(WIN32)
        # Windows 下的库目录（根据编译模式选择）
        if(CMAKE_SIZEOF_VOID_P EQUAL 8)
            set(DCMTK_LIB_DIR ${DCMTK_DIR}/lib)
        else()
            set(DCMTK_LIB_DIR ${DCMTK_DIR}/lib)
        endif()
    else()
        set(DCMTK_LIB_DIR ${DCMTK_DIR}/lib)
    endif()

    # DCMTK 库文件（TLS 需要 dcmtls，图像显示需要 dcmimage/dcmimgle）
    set(DCMTK_LIBRARIES
        dcmtls
        dcmnet
        dcmdata
        dcmimage
        dcmimgle
        oflog
        ofstd
    )

    set(DCMTK_FOUND TRUE)
endif()

message(STATUS "DCMTK 头文件目录: ${DCMTK_INCLUDE_DIRS}")
message(STATUS "DCMTK 库: ${DCMTK_LIBRARIES}")

# ============================================================
#  查找 OpenSSL
# ============================================================
find_package(OpenSSL REQUIRED)
message(STATUS "OpenSSL 版本: ${OPENSSL_VERSION}")
message(STATUS "OpenSSL 头文件: ${OPENSSL_INCLUDE_DIR}")

# ============================================================
#  查找 SQLite3（用于 DICOM 文件索引）
# ============================================================
find_package(SQLite3 QUIET)
if(NOT SQLite3_FOUND)
    # 手动查找
    find_path(SQLITE3_INCLUDE_DIR sqlite3.h)
    find_library(SQLITE3_LIBRARY NAMES sqlite3)
    if(SQLITE3_INCLUDE_DIR AND SQLITE3_LIBRARY)
        set(SQLite3_FOUND TRUE)
        set(SQLite3_INCLUDE_DIRS ${SQLITE3_INCLUDE_DIR})
        set(SQLite3_LIBRARIES ${SQLITE3_LIBRARY})
    endif()
endif()
if(SQLite3_FOUND)
    message(STATUS "SQLite3 已找到: ${SQLite3_LIBRARIES}")
else()
    message(WARNING "SQLite3 未找到，C-FIND 查询功能将不可用")
endif()

# ============================================================
#  编译目标
# ============================================================

include_directories(
    ${DCMTK_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
)
if(SQLite3_FOUND)
    include_directories(${SQLite3_INCLUDE_DIRS})
endif()

link_directories(
    ${DCMTK_LIB_DIR}
)

# --- TLS SCU (发送端) ---
add_executable(tls_scu
    tls_scu.cpp
    gui/common/dicom_index.cpp
)
target_link_libraries(tls_scu
    ${DCMTK_LIBRARIES}
    OpenSSL::SSL
    OpenSSL::Crypto
)
if(SQLite3_FOUND)
    target_link_libraries(tls_scu ${SQLite3_LIBRARIES})
endif()

# Windows 下需要额外的库
if(WIN32)
    target_link_libraries(tls_scu
        ws2_32       # WinSock
        netapi32     # 网络 API
        wsock32
    )
endif()

# --- TLS SCP (接收端) ---
add_executable(tls_scp
    tls_scp.cpp
    gui/common/dicom_index.cpp
)
target_link_libraries(tls_scp
    ${DCMTK_LIBRARIES}
    OpenSSL::SSL
    OpenSSL::Crypto
)
if(SQLite3_FOUND)
    target_link_libraries(tls_scp ${SQLite3_LIBRARIES})
endif()

if(WIN32)
    target_link_libraries(tls_scp
        ws2_32
        netapi32
        wsock32
    )
endif()

# ============================================================
#  Qt GUI 应用（可选，需要 Qt5）
# ============================================================
find_package(Qt5 COMPONENTS Widgets Core Gui QUIET)

if(Qt5_FOUND)
    message(STATUS "Qt5 已找到，构建 GUI 应用")
    set(CMAKE_AUTOMOC ON)

    # 公共源文件
    set(GUI_COMMON_SOURCES
        gui/common/tls_helper.cpp
        gui/common/dicom_image_util.cpp
        gui/common/dicom_index.cpp
    )

    # --- SCP GUI（服务端） ---
    add_executable(scp_gui
        gui/scp/main.cpp
        gui/scp/scp_main_window.cpp
        gui/scp/scp_worker.cpp
        ${GUI_COMMON_SOURCES}
    )
    target_include_directories(scp_gui PRIVATE gui)
    target_link_libraries(scp_gui
        ${DCMTK_LIBRARIES}
        OpenSSL::SSL
        OpenSSL::Crypto
        Qt5::Widgets
        Qt5::Core
        Qt5::Gui
    )
    if(SQLite3_FOUND)
        target_link_libraries(scp_gui ${SQLite3_LIBRARIES})
    endif()
    if(WIN32)
        target_link_libraries(scp_gui ws2_32 netapi32 wsock32)
    endif()

    # --- SCU GUI（客户端） ---
    add_executable(scu_gui
        gui/scu/main.cpp
        gui/scu/scu_main_window.cpp
        gui/scu/scu_worker.cpp
        ${GUI_COMMON_SOURCES}
    )
    target_include_directories(scu_gui PRIVATE gui)
    target_link_libraries(scu_gui
        ${DCMTK_LIBRARIES}
        OpenSSL::SSL
        OpenSSL::Crypto
        Qt5::Widgets
        Qt5::Core
        Qt5::Gui
    )
    if(SQLite3_FOUND)
        target_link_libraries(scu_gui ${SQLite3_LIBRARIES})
    endif()
    if(WIN32)
        target_link_libraries(scu_gui ws2_32 netapi32 wsock32)
    endif()
else()
    message(STATUS "Qt5 未找到，跳过 GUI 应用构建")
endif()

# ============================================================
#  安装规则
# ============================================================
install(TARGETS tls_scu tls_scp
    RUNTIME DESTINATION bin
)
if(Qt5_FOUND)
    install(TARGETS scp_gui scu_gui
        RUNTIME DESTINATION bin
    )
endif()

message(STATUS "========================================")
message(STATUS "  构建配置完成")
message(STATUS "  目标: tls_scu, tls_scp")
if(Qt5_FOUND)
    message(STATUS "  GUI: scp_gui, scu_gui")
endif()
message(STATUS "========================================")
