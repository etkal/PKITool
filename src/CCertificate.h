//
//  Copyright (c) 2018-2022 Erik Tkal. All rights reserved.
//
#ifndef _CCERTIFICATE_H
#define _CCERTIFICATE_H

#include "COpenSSL.h"
#include <string>

using namespace std;

class CCertificate {
public:
    CCertificate();
    ~CCertificate();

    bool HasKey();

    int ReadPfx(string strFile, string& strPassword);
    int ReadCert(string strFile);
    int ReadCrl(string strFile, bool bCreateIfMissing = false);
    int ReadReq(string strFile);

    int GenerateKey(int key_type, int key_size, int nCurve);

    int CreateReq(CONF* pConf, const char* szSection, const char* szX509v3ext);
    int CreateReqFromCert();
    int CreateCert(CONF* pConf, const char* szX509v3ext, CCertificate& oIssuer,
        long nSerial, long nNotBefore, long nNotAfter, const EVP_MD* pDigest);

    int WriteCerFile(string strFile, bool bDer);
    int WriteReqFile(string strFile, bool bDer);
    int WritePfxFile(string strFile, string& strPassword);
    int WriteCrlFile(string strFile, bool bDer);
    int WriteKeyFile(string strFile, bool bDer);
    int Revoke(CCertificate& oCert, int nReason);
    int PrintCert();
    int PrintCrl();

    static int KeyGenCB(int p, int n, BN_GENCB *cb);
    static const EVP_MD* DigestFromSigAlg(int nid);
    static const EVP_MD* DigestFromKey(EVP_PKEY* pKey);

    EVP_PKEY* GetKey();
    int GetCurve(); // EC curve
    X509* CertX509();

private:
    X509* m_pCert;
    EVP_PKEY* m_pKey;
    X509_REQ* m_pReq;
    X509_CRL* m_pCrl;

};


#endif
