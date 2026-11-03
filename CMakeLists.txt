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

    # DCMTK 库文件（TLS 需要 dcmtls）
    set(DCMTK_LIBRARIES
        dcmtls
        dcmnet
        dcmdata
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
#  编译目标
# ============================================================

include_directories(
    ${DCMTK_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
)

link_directories(
    ${DCMTK_LIB_DIR}
)

# --- TLS SCU (发送端) ---
add_executable(tls_scu tls_scu.cpp)
target_link_libraries(tls_scu
    ${DCMTK_LIBRARIES}
    OpenSSL::SSL
    OpenSSL::Crypto
)

# Windows 下需要额外的库
if(WIN32)
    target_link_libraries(tls_scu
        ws2_32       # WinSock
        netapi32     # 网络 API
        wsock32
    )
endif()

# --- TLS SCP (接收端) ---
add_executable(tls_scp tls_scp.cpp)
target_link_libraries(tls_scp
    ${DCMTK_LIBRARIES}
    OpenSSL::SSL
    OpenSSL::Crypto
)

if(WIN32)
    target_link_libraries(tls_scp
        ws2_32
        netapi32
        wsock32
    )
endif()

# ============================================================
#  安装规则
# ============================================================
install(TARGETS tls_scu tls_scp
    RUNTIME DESTINATION bin
)

message(STATUS "========================================")
message(STATUS "  构建配置完成")
message(STATUS "  目标: tls_scu, tls_scp")
message(STATUS "========================================")
