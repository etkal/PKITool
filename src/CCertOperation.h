//
//  Copyright (c) 2018-2025 Erik Tkal. All rights reserved.
//
#ifndef _CCERTOPERATION_H
#define _CCERTOPERATION_H

#include "COpenSSL.h"
#include <string>

using namespace std;

enum
{
    kReasonUnspecified          = 0,
    kReasonKeyCompromise        = 1,
    kReasonCACompromise         = 2,
    kReasonAffiliationChanged   = 3,
    kReasonSuperseded           = 4,
    kReasonCessationOfOperation = 5,
    kReasonCertificateHold      = 6,
    kReasonRemoveFromCRL        = 8
};

class CCertOperation
{
public:
    CCertOperation();
    ~CCertOperation();

    int ReadParameters(int argc, const char* argv[]);
    int LoadConf();
    int Execute();

private:
    CONF* m_pConf;

    string m_strAppPath;
    string m_strOperation;
    int m_nStart;
    int m_nDays;
    int m_nKeySize;
    int m_nCurve;
    string m_strConfFile;
    string m_strKeyType;
    string m_strCurve;
    string m_strSigHash;
    string m_strPassword;
    string m_strOutPfx;
    string m_strOutCer;
    string m_strOutReq;
    string m_strOutKey;
    string m_strOutName;
    string m_strEmail;
    string m_strSubject;
    string m_strCert;
    string m_strCrl;
    string m_strReq;
    string m_strIssuerPfx;
    string m_strIssuerCrl;
    string m_strIssuerName;
    string m_strIssuerPassword;
    int m_nReason;
    bool m_bSaveKeyToFile;
    bool m_bSaveKeyBlobToFile;
    bool m_bSaveReqToFile;
    bool m_bSaveCertAsDer;
    bool m_bRenew;

    int m_nKeyType;
    const EVP_MD* m_pDigest;
};


#endif
