// ============================================================
//  TLS 传输层设置辅助实现
// ============================================================
#include "tls_helper.h"
#include <iostream>

namespace TlsHelper {

OFCondition setupTLS(T_ASC_Network* net,
                     T_ASC_NetworkRole role,
                     const std::string& certFile,
                     const std::string& keyFile,
                     const std::string& caFile,
                     bool requirePeerCert)
{
    DcmTLSTransportLayer* tlsLayer = new DcmTLSTransportLayer(
        role, NULL, OFTrue
    );

    if (tlsLayer == NULL) {
        return EC_IllegalCall;
    }

    // 私钥
    if (!keyFile.empty()) {
        DcmTransportLayerStatus st = tlsLayer->setPrivateKeyFile(
            keyFile.c_str(), DCF_Filetype_PEM);
        if (st != TCS_ok) {
            delete tlsLayer;
            return EC_IllegalCall;
        }
    }

    // 证书
    if (!certFile.empty()) {
        DcmTransportLayerStatus st = tlsLayer->setCertificateFile(
            certFile.c_str(), DCF_Filetype_PEM);
        if (st != TCS_ok) {
            delete tlsLayer;
            return EC_IllegalCall;
        }
    }

    // CA 信任链
    if (!caFile.empty()) {
        DcmTransportLayerStatus st = tlsLayer->addTrustedCertificateFile(
            caFile.c_str(), DCF_Filetype_PEM);
        if (st != TCS_ok) {
            delete tlsLayer;
            return EC_IllegalCall;
        }
    }

    // 对端证书验证策略
    tlsLayer->setCertificateVerification(
        requirePeerCert ? DCV_requireCertificate : DCV_ignoreCertificate);

    // 密码套件
    tlsLayer->setTLSProfile(TSP_Profile_BCP195);
    tlsLayer->activateCipherSuites();

    // 强制 TLS 1.2（DCMTK 3.6.4 + OpenSSL 1.1.1 兼容问题）
    SSL_CTX* sslCtx = tlsLayer->getNativeHandle();
    if (sslCtx != NULL) {
        SSL_CTX_set_options(sslCtx,
            SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
            SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1_3);
    }

    // 设置到网络层
    OFCondition cond = ASC_setTransportLayer(net, tlsLayer, 1);
    if (cond.bad()) {
        delete tlsLayer;
        return cond;
    }

    return EC_Normal;
}

} // namespace TlsHelper
