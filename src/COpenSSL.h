//
//  Copyright (c) 2018-2022 Erik Tkal. All rights reserved.
//
#ifndef _COPENSSL_H
#define _COPENSSL_H

#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pkcs12.h>

// COpenSSL - Singleton, not thread safe.
class COpenSSL
{
public:
    COpenSSL();
    ~COpenSSL();

    static void PrintError();
    static BIO* Stdout()
    {
        return m_oStdout;
    }

private:
    static void Initialize();
    static void Terminate();

    static COpenSSL* m_pSingleton;
    static unsigned int m_nUsers;
    static BIO* m_oStdout;
};

#endif
