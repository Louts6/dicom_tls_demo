// ============================================================
//  TLS 传输层设置辅助函数（SCP 和 SCU 共用）
// ============================================================
#ifndef TLS_HELPER_H
#define TLS_HELPER_H

#include "dcmtk/config/osconfig.h"
#include "dcmtk/dcmnet/dicom.h"
#include "dcmtk/dcmnet/assoc.h"
#include "dcmtk/dcmtls/tlslayer.h"
#include "dcmtk/ofstd/ofcond.h"

#include <openssl/ssl.h>
#include <string>

namespace TlsHelper {

// 为网络对象设置 TLS 传输层
// role: NET_ACCEPTOR (SCP) 或 NET_REQUESTOR (SCU)
// certFile, keyFile, caFile: PEM 格式的证书/私钥/CA 文件路径
// requirePeerCert: 是否要求对端提供证书（双向认证）
OFCondition setupTLS(T_ASC_Network* net,
                     T_ASC_NetworkRole role,
                     const std::string& certFile,
                     const std::string& keyFile,
                     const std::string& caFile,
                     bool requirePeerCert = true);

} // namespace TlsHelper

#endif // TLS_HELPER_H
