/*
 * CCertificate.cpp
 *
 * Copyright (c) 2023 Erik Tkal
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "PKITool.h"
#include "CCertOperation.h"
#include "CCertificate.h"

CCertOperation::CCertOperation()
    : m_nDays(396),
      m_nKeySize(0),
      m_nCurve(0),
      m_nReason(kReasonUnspecified),
      m_bSaveKeyToFile(false),
      m_bSaveKeyBlobToFile(false),
      m_bSaveReqToFile(false),
      m_bSaveCertAsDer(false),
      m_bRenew(false),
      m_nKeyType(EVP_PKEY_NONE),
      m_pDigest(NULL),
      m_pConf(NULL)
{
    m_strConfFile = "pkitool.ini";
    m_strPassword = "test";
}

CCertOperation::~CCertOperation()
{
    if (m_pConf)
    {
        NCONF_free(m_pConf);
    }
}

int CCertOperation::ReadParameters(int argc, const char* argv[])
{
    argv++;
    argc--;
    if (argc == 0)
        goto help;

    m_strOperation = *(argv);
    if (m_strOperation != "rootca" && m_strOperation != "intca" && m_strOperation != "user" && m_strOperation != "server" &&
        m_strOperation != "selfserv" && m_strOperation != "client" && m_strOperation != "crl" && m_strOperation != "print")
    {
        printf("Unrecognized operation \"%s\".\n", m_strOperation.c_str());
        goto bad;
    }

    for (;;)
    {
        if (--argc <= 0)
            break;
        const char* pArg = *(++argv);
        if (strcmp(pArg, "-config") == 0)
        {
            if (--argc < 1)
                goto bad;
            m_strConfFile = *(++argv);
        }
        else if (strcmp(pArg, "-issuer") == 0)
        {
            if (--argc < 1)
                goto bad;
            m_strIssuerPfx = *(++argv);
        }
        else if (strcmp(pArg, "-out") == 0)
        {
            if (--argc < 1)
                goto bad;
            m_strOutPfx = *(++argv);
        }
        else if (strcmp(pArg, "-email") == 0)
        {
            if (--argc < 1)
                goto bad;
            m_strEmail = *(++argv);
        }
        else if (strcmp(pArg, "-subject") == 0)
        {
            if (--argc < 1)
                goto bad;
            m_strSubject = *(++argv);
        }
        else if (strcmp(pArg, "-password") == 0)
        {
            if (--argc < 1)
                goto bad;
            m_strPassword = *(++argv);
        }
        else if (strcmp(pArg, "-issuerPassword") == 0)
        {
            if (--argc < 1)
                goto bad;
            m_strIssuerPassword = *(++argv);
        }
        else if (strcmp(pArg, "-days") == 0)
        {
            if (--argc < 1)
                goto bad;
            m_nDays = atoi(*(++argv));
        }
        else if (strcmp(pArg, "-key_type") == 0)
        {
            if (--argc < 1)
                goto bad;
            m_strKeyType = *(++argv);
            if (strcmp(m_strKeyType.c_str(), "rsa") == 0)
            {
                m_nKeyType = EVP_PKEY_RSA;
            }
            else if (strcmp(m_strKeyType.c_str(), "rsa-pss") == 0)
            {
                m_nKeyType = EVP_PKEY_RSA_PSS;
            }
            else if (strcmp(m_strKeyType.c_str(), "ecdsa") == 0)
            {
                m_nKeyType = EVP_PKEY_EC;
            }
            else if (strcmp(m_strKeyType.c_str(), "ed25519") == 0)
            {
                m_nKeyType = EVP_PKEY_ED25519;
            }
            else if (strcmp(m_strKeyType.c_str(), "ed448") == 0)
            {
                m_nKeyType = EVP_PKEY_ED448;
            }
            else
            {
                printf("Invalid key type %s.\n", m_strKeyType.c_str());
                goto bad;
            }
        }
        else if (strcmp(pArg, "-rsa_size") == 0)
        {
            if (--argc < 1)
                goto bad;
            if (m_nKeyType != EVP_PKEY_RSA && m_nKeyType != EVP_PKEY_RSA_PSS && m_nKeyType != EVP_PKEY_NONE)
            {
                printf("rsa_size parameter invalid if not RSA.\n");
                goto bad;
            }
            m_nKeySize = atoi(*(++argv));
        }
        else if (strcmp(pArg, "-ec_curve") == 0)
        {
            if (--argc < 1)
                goto bad;
            if (m_nKeyType != EVP_PKEY_EC && m_nKeyType != EVP_PKEY_NONE)
            {
                printf("ec_curve parameter invalid if not ECDSA.\n");
                goto bad;
            }
            m_nKeyType          = EVP_PKEY_EC;
            const char* szCurve = *(++argv);
            if (strcmp(szCurve, "p256") == 0)
            {
                m_nCurve   = NID_X9_62_prime256v1;
                m_nKeySize = 256;
            }
            else if (strcmp(szCurve, "p384") == 0)
            {
                m_nCurve   = NID_secp384r1;
                m_nKeySize = 384;
            }
            else
            {
                int nid = OBJ_txt2nid(szCurve);
                if (nid == 0)
                {
                    printf("ec_curve must be p256, p384 or an OpenSSL named curve.\n");
                    goto bad;
                }
                m_nCurve = nid;
            }
            m_strCurve = OBJ_nid2sn(m_nCurve);
        }
        else if (strcmp(pArg, "-sig_hash") == 0)
        {
            if (--argc < 1)
                goto bad;
            m_strSigHash = *(++argv); // will be validated later
        }
        else if (strcmp(pArg, "-cert") == 0)
        {
            if (--argc < 1)
                goto bad;
            m_strCert = *(++argv);
        }
        else if (strcmp(pArg, "-crl") == 0)
        {
            if (--argc < 1)
                goto bad;
            m_strCrl = *(++argv);
        }
        else if (strcmp(pArg, "-req") == 0)
        {
            if (--argc < 1)
                goto bad;
            m_strReq = *(++argv);
        }
        else if (strcmp(pArg, "-savekey") == 0)
        {
            m_bSaveKeyToFile = true;
        }
        else if (strcmp(pArg, "-savekeyblob") == 0)
        {
#ifdef _WIN32
            m_bSaveKeyBlobToFile = true;
#else
            printf("Saving key to blob not supported.\n");
#endif
        }
        else if (strcmp(pArg, "-savereq") == 0)
        {
            m_bSaveReqToFile = true;
        }
        else if (strcmp(pArg, "-der") == 0)
        {
            m_bSaveCertAsDer = true;
        }
        else if (strcmp(pArg, "-renew") == 0)
        {
            m_bRenew = true;
        }

        /*
        enum
        {
        unspecified =           0,
        keyCompromise =         1,
        cACompromise =          2,
        affiliationChanged =    3,
        superseded =            4,
        cessationOfOperation =  5,
        certificateHold =       6,
        removeFromCRL =         8
        };
        */
        else if (strcmp(pArg, "-reason") == 0)
        {
            if (--argc < 1)
                goto bad;
            const char* tmp = *(++argv);
            if (strcmp(tmp, "unspecified") == 0)
                m_nReason = kReasonUnspecified;
            else if (strcmp(tmp, "keyCompromise") == 0)
                m_nReason = kReasonKeyCompromise;
            else if (strcmp(tmp, "cACompromise") == 0)
                m_nReason = kReasonCACompromise;
            else if (strcmp(tmp, "affiliationChanged") == 0)
                m_nReason = kReasonAffiliationChanged;
            else if (strcmp(tmp, "keyCompromise") == 0)
                m_nReason = kReasonKeyCompromise;
            else if (strcmp(tmp, "superseded") == 0)
                m_nReason = kReasonSuperseded;
            else if (strcmp(tmp, "cessationOfOperation") == 0)
                m_nReason = kReasonCessationOfOperation;
            else if (strcmp(tmp, "certificateHold") == 0)
                m_nReason = kReasonCertificateHold;
            else if (strcmp(tmp, "removeFromCRL") == 0)
                m_nReason = kReasonRemoveFromCRL;
            else
                m_nReason = kReasonUnspecified;
        }
        else
            break;
    }

    // Post processing
    if (argc >= 1)
        goto bad;

    if (m_strOperation.empty())
        goto bad;

    // Validate the key and signature info
    if (m_nKeyType == EVP_PKEY_NONE)
    {
        // User did not specify key_type or rsa_size or ec_curve
        m_nKeyType = EVP_PKEY_EC;
        m_nCurve   = NID_X9_62_prime256v1;
        m_nKeySize = 256;
    }

    // Validate or set the signature hash to use
    if (!m_strSigHash.empty())
    {
        // User specified
        if (strcmp(m_strSigHash.c_str(), "sha1") == 0 && (m_nKeyType == EVP_PKEY_RSA || m_nKeyType == EVP_PKEY_RSA_PSS))
        {
            m_pDigest = EVP_sha1();
        }
        else if (strcmp(m_strSigHash.c_str(), "md5") == 0 && m_nKeyType == EVP_PKEY_RSA)
        {
            m_pDigest = EVP_md5();
        }
        else if (strcmp(m_strSigHash.c_str(), "sha256") == 0)
        {
            m_pDigest = EVP_sha256();
        }
        else if (strcmp(m_strSigHash.c_str(), "sha384") == 0)
        {
            m_pDigest = EVP_sha384();
        }
        else if (strcmp(m_strSigHash.c_str(), "sha512") == 0)
        {
            m_pDigest = EVP_sha512();
        }
        else
        {
            printf("Unknown or invalid signature hash type %s.\n", m_strSigHash.c_str());
            goto bad;
        }
    }

    // self-signed certs only need a subject
    if (m_strOperation == "rootca" || m_strOperation == "selfserv")
    {
        if (!m_strCert.empty())
            printf("Unexpected -cert parameter ignored.\n");
        if (m_strOutPfx.empty())
        {
            printf("Missing output file.\n");
            goto bad;
        }
        else
            goto good;
    }

    // normal certs need a subject and an issuer
    if (m_strOperation == "intca" || m_strOperation == "user" || m_strOperation == "server" || m_strOperation == "client")
    {
        if (!m_strCert.empty())
            printf("Unexpected -cert parameter ignored.\n");
        if (m_strIssuerPfx.empty() || m_strOutPfx.empty())
        {
            printf("Missing issuer or output file.\n");
            goto bad;
        }
        else
            goto good;
    }
    else if (m_strOperation == "crl")
    {
        if (!m_strOutPfx.empty())
            printf("Unexpected -out parameter ignored.\n");
        if (m_strIssuerPfx.empty() || m_strCert.empty())
        {
            printf("Missing issuer or certificate file.\n");
            goto bad;
        }
        else
            goto good;
    }
    else if (m_strOperation == "print")
    {
        if (m_strCert.empty() && m_strCrl.empty())
        {
            printf("Missing input certificate/crl file.\n");
            goto bad;
        }
        else
            goto good;
    }

help:
{
    FILE* fpReadme = NULL;
    if (fopen_s(&fpReadme, "pkitool.txt", "rb") == 0 || fopen_s(&fpReadme, "..\\pkitool.txt", "rb") == 0)
    {
        char szReadmeBuf[257];
        size_t nRead = 0;
        while ((nRead = fread(szReadmeBuf, sizeof(char), sizeof(szReadmeBuf) - 1, fpReadme)) > 0)
        {
            szReadmeBuf[nRead] = 0;
            printf("%s", szReadmeBuf);
        }
        fclose(fpReadme);
        printf("\n");
        printf("Using %s\n\n", OPENSSL_VERSION_TEXT);
        return -1;
    }
    else
    {
        printf("Help file pkitool.txt not found.\n");
    }
    return -1;
}

good: // (so far)
    // ensure proper file extensions
    if (!m_strOutPfx.empty())
    {
        // if no data, or doesn't end in .pfx
        size_t nPfxExtOffset = m_strOutPfx.find(".pfx");
        if (nPfxExtOffset != m_strOutPfx.length() - 4)
        {
            printf("Improperly specified output PFX file name.\n");
            goto bad;
        }
        else
        {
            m_strOutName = m_strOutPfx.substr(0, nPfxExtOffset); // remove .pfx
            m_strOutCer  = m_strOutName + ".cer";                // replace .pfx
            m_strOutKey  = m_strOutName + ".key";                // replace .pfx
            m_strOutReq  = m_strOutName + ".csr";                // replace .pfx
            // consider removing path
        }
    }
    if (!m_strIssuerPfx.empty())
    {
        // if no data, or doesn't end in .pfx
        size_t nPfxExtOffset = m_strIssuerPfx.find(".pfx");
        if (nPfxExtOffset != m_strIssuerPfx.length() - 4)
        {
            printf("Improperly specified issuer PFX file name.\n");
            goto bad;
        }
        else
        {
            m_strIssuerName = m_strIssuerPfx.substr(0, nPfxExtOffset); // remove .pfx
            m_strIssuerCrl  = m_strIssuerName + ".crl";                // replace .pfx
            // consider removing path
        }
    }
    if (m_strIssuerPassword.empty())
    {
        // if no issuer password assume same as target
        m_strIssuerPassword = m_strPassword;
    }

    printf("operation: %s, issuer: %s, out: %s, subject: %s, days: %d, key_type: %s, rsa_size: %d, cert: "
           "%s\n\n",
           m_strOperation.c_str(),
           m_strIssuerPfx.c_str(),
           m_strOutPfx.c_str(),
           m_strSubject.c_str(),
           m_nDays,
           m_strKeyType.c_str(),
           m_nKeySize,
           m_strCert.c_str());
    printf("Using %s\n\n", OPENSSL_VERSION_TEXT);
    return 1;

bad:
    printf("operation: %s, issuer: %s, out: %s, subject: %s, days: %d, key_type: %s, rsa_size: %d, cert: "
           "%s\n\n",
           m_strOperation.c_str(),
           m_strIssuerPfx.c_str(),
           m_strOutPfx.c_str(),
           m_strSubject.c_str(),
           m_nDays,
           m_strKeyType.c_str(),
           m_nKeySize,
           m_strCert.c_str());
    return -1;
}


static size_t GetSingleLineText(char** ppszMultiLineText, char* pszSingleLineText, unsigned int nSingleLineTextMaxLength)
{
    char* pszNextLineText = NULL;
    if (!(pszNextLineText = strstr(*ppszMultiLineText, "\n")))
        return 0;
    // pszNextLineText points to "\nxxxxxxxxxxxxx", so advance it by 1 to point it to next line;
    pszNextLineText++;
    size_t nSingleLineTextLength = pszNextLineText - (*ppszMultiLineText);
    if ((nSingleLineTextLength + 1) > nSingleLineTextMaxLength) // not sufficient buffer
        return 0;
    // copy single line
    memcpy(pszSingleLineText, *ppszMultiLineText, nSingleLineTextLength);
    pszSingleLineText[nSingleLineTextLength] = '\0';
    // advance to next line
    *ppszMultiLineText = pszNextLineText;
    return strlen(pszSingleLineText);
}


int CCertOperation::LoadConf()
{
    int ret = -1;

    FILE* fpConfFile             = NULL;
    char* pszConfFileText        = NULL;
    char* pszMultiLineText       = NULL;
    char pszSingleLineText[4096] = "";
    char conf_data[1024 * 1024]  = "";
    BIO* bio_mem_conf            = NULL;
    long nConfFileSize           = 0;

    if (fopen_s(&fpConfFile, m_strConfFile.c_str(), "rb") != 0)
    {
        string strUpOne = string("../") + m_strConfFile;
        if (fopen_s(&fpConfFile, strUpOne.c_str(), "rb") != 0)
        {
            printf("Unable to open configuration file \"%s\".\n", m_strConfFile.c_str());
            goto err;
        }
    }

    fseek(fpConfFile, 0, SEEK_END);
    nConfFileSize = ftell(fpConfFile);
    fseek(fpConfFile, 0, SEEK_SET);
    pszConfFileText = new char[nConfFileSize];
    fread(pszConfFileText, sizeof(char), nConfFileSize, fpConfFile);
    fclose(fpConfFile);

    pszMultiLineText = pszConfFileText;
    while (GetSingleLineText(&pszMultiLineText, pszSingleLineText, sizeof(pszSingleLineText)))
    {
        if ((strstr(pszSingleLineText, "%s")))
        {
            char szModifiedSingleLine[512] = "";

            if ((strstr(pszSingleLineText, "crlDistributionPoints")))
            {
                // here take name from issuer, instead of from subject
                string strIssuer;
                if (!m_strIssuerName.empty())
                {
                    strIssuer = m_strIssuerName;
                }
                else
                {
                    // case of rootca conf
                    strIssuer = m_strOutName;
                }
                snprintf(szModifiedSingleLine, sizeof(szModifiedSingleLine), pszSingleLineText, strIssuer.c_str(), strIssuer.c_str());
            }
            else if ((strstr(pszSingleLineText, "emailAddress")))
            {
                // if email specified, use it, otherwise don't echo the line
                if (!m_strEmail.empty())
                    snprintf(szModifiedSingleLine, sizeof(szModifiedSingleLine), pszSingleLineText, m_strEmail.c_str());
            }
            else if ((strstr(pszSingleLineText, "commonName")))
            {
                // if subject specified, use it, otherwise use the pfx file name
                if (!m_strSubject.empty())
                    snprintf(szModifiedSingleLine, sizeof(szModifiedSingleLine), pszSingleLineText, m_strSubject.c_str());
                else
                {
                    snprintf(szModifiedSingleLine, sizeof(szModifiedSingleLine), pszSingleLineText, m_strOutName.c_str());
                }
            }
            else if ((strstr(pszSingleLineText, "DNS.")))
            {
                // if subject specified, use it, otherwise use the pfx file name
                if (!m_strSubject.empty())
                    snprintf(szModifiedSingleLine, sizeof(szModifiedSingleLine), pszSingleLineText, m_strSubject.c_str());
                else
                {
                    snprintf(szModifiedSingleLine, sizeof(szModifiedSingleLine), pszSingleLineText, m_strOutName.c_str());
                }
            }
            else
            {
                snprintf(szModifiedSingleLine, sizeof(szModifiedSingleLine), pszSingleLineText, m_strOutName.c_str());
            }
            strncat(conf_data, szModifiedSingleLine, sizeof(conf_data) - strlen(conf_data) - 1);
        }
        else if (pszSingleLineText[0] != '#') // ignore comment
        {
            strncat(conf_data, pszSingleLineText, sizeof(conf_data) - strlen(conf_data) - 1);
        }
    }
    // printf( "%s", conf_data );

    delete[] pszConfFileText;
    // exit( 0 );

    // get a memory bio for above conf_data
    if (!(bio_mem_conf = BIO_new_mem_buf(conf_data, (int)strlen(conf_data))))
        goto err;
    m_pConf = NCONF_new(NULL);
    if (!NCONF_load_bio(m_pConf, bio_mem_conf, 0))
        goto err;

    ret = 1;
err:
    if (bio_mem_conf)
        BIO_free(bio_mem_conf);

    return ret;
}

int CCertOperation::Execute()
{
    char szSection[256]      = "";
    char szX509v3ext[256]    = "";
    char szX509v3reqext[256] = "";

    string strEcdsa = "";
    if (m_nKeyType == EVP_PKEY_EC && (0 == m_strOperation.compare("server") || 0 == m_strOperation.compare("selfserv") ||
                                      0 == m_strOperation.compare("client") || 0 == m_strOperation.compare("user")))
    {
        strEcdsa = "_ecdsa";
    }
    snprintf(szSection, sizeof(szSection), "%s_op", m_strOperation.c_str());
    snprintf(szX509v3ext, sizeof(szX509v3ext), "%s_x509v3_extensions", m_strOperation.c_str());
    snprintf(szX509v3reqext, sizeof(szX509v3reqext), "%s_x509v3_req_extensions%s", m_strOperation.c_str(), strEcdsa.c_str());

    CCertificate oCert;
    CCertificate oIssuer;

    // If we are renewing a certificate, read in the current one
    if (m_bRenew)
    {
        if (oCert.ReadPfx(m_strOutPfx, m_strPassword) <= 0)
            goto err;
    }

    // Handle self-signed certificates
    if (m_strOperation == "rootca" || m_strOperation == "selfserv")
    {
        // get a random serial number
        long nSerial = 0;
        RAND_bytes((unsigned char*)&nSerial, sizeof(nSerial));

        // Create a key if we do not have one
        if (!oCert.HasKey())
        {
            // default to RSA if unspecified
            if (m_nKeyType == EVP_PKEY_NONE)
            {
                m_nKeyType = EVP_PKEY_RSA;
            }
            if ((m_nKeyType == EVP_PKEY_RSA || m_nKeyType == EVP_PKEY_RSA_PSS) && m_nKeySize == 0)
            {
                m_nKeySize = 2048;
            }
            if (m_nKeyType == EVP_PKEY_EC && m_nCurve == 0)
            {
                m_nCurve = NID_X9_62_prime256v1;
            }
            if (oCert.GenerateKey(m_nKeyType, m_nKeySize, m_nCurve) <= 0)
            {
                goto err;
            }
        }

        // Create the request
        if (m_bRenew)
        {
            X509* pX509 = oCert.CertX509();
            nSerial     = ASN1_INTEGER_get(X509_get_serialNumber(pX509));
            if (oCert.CreateReqFromCert() <= 0)
            {
                goto err;
            }
        }
        else
        {
            if (oCert.CreateReq(m_pConf, szSection, szX509v3reqext) <= 0)
            {
                goto err;
            }
        }

        // Generate the cert
        if (oCert.CreateCert(m_pConf,
                             szX509v3ext,
                             oIssuer,
                             nSerial,
                             (long)(0 - 15 * 60),
                             (long)(m_nDays * 24 * 60 * 60 - 15 * 60),
                             m_pDigest) <= 0)
        {
            goto err;
        }

        // Write the resulting files
        oCert.WriteCerFile(m_strOutCer, m_bSaveCertAsDer);
        oCert.WritePfxFile(m_strOutPfx, m_strPassword);
        if (m_bSaveKeyToFile)
        {
            oCert.WriteKeyFile(m_strOutKey, m_bSaveCertAsDer);
        }
    }
    else if (m_strOperation == "crl")
    {
        // Read issuer pfx
        if (oIssuer.ReadPfx(m_strIssuerPfx, m_strIssuerPassword) <= 0)
        {
            printf("Issuing certificate could not be read.\n");
            goto err;
        }
        if (oCert.ReadCert(m_strCert) <= 0)
        {
            printf("Certificate to be revoked could not be read.\n");
            goto err;
        }
        if (oIssuer.ReadCrl(m_strIssuerCrl, true) <= 0)
        {
            printf("Unable to read/create issuer CRL file.\n");
            goto err;
        }
        if (oIssuer.Revoke(oCert, m_nReason) <= 0)
        {
            printf("Error adding certificate to CRL.\n");
            goto err;
        }
        oIssuer.WriteCrlFile(m_strIssuerCrl, m_bSaveCertAsDer);
    }
    else if (m_strOperation == "print")
    {
        if (!m_strCert.empty())
        {
            if (oCert.ReadCert(m_strCert) <= 0)
            {
                printf("Certificate to be printed could not be read.\n");
                goto err;
            }
            oCert.PrintCert();
        }
        else if (!m_strCrl.empty())
        {
            if (oCert.ReadCrl(m_strCrl) <= 0)
            {
                printf("CRL to be printed could not be read.\n");
                goto err;
            }
            oCert.PrintCrl();
        }
    }
    else
    {
        FILE* fp             = NULL;
        unsigned int nSerial = 0;

        // Read issuer pfx
        if (oIssuer.ReadPfx(m_strIssuerPfx, m_strIssuerPassword) <= 0)
        {
            printf("Issuing certificate could not be read.\n");
            goto err;
        }

        // Serial number file in same location as issuer PFX, with .ser extension
        string strSerialFile = m_strIssuerPfx.substr(0, m_strIssuerPfx.find(".pfx"));
        strSerialFile += ".ser";
        if (fopen_s(&fp, strSerialFile.c_str(), "rb") != 0)
        {
            // no cert serial no file found
            RAND_bytes((unsigned char*)&nSerial, sizeof(nSerial));
            nSerial &= 0xFFFF0000;
            nSerial += 1;
        }
        else
        {
            /* read next cert serial no from file */
            fread(&nSerial, sizeof(int), 1, fp);
            fclose(fp);
        }

        if (!m_strReq.empty())
        {
            if (oCert.ReadReq(m_strReq) <= 0)
            {
                goto err;
            }
        }
        else
        {
            // Create a key if we do not have one
            if (!oCert.HasKey())
            {
                // default to issuer keytype and curve if unspecified
                if (m_nKeyType == EVP_PKEY_NONE)
                {
                    m_nKeyType = EVP_PKEY_id(oIssuer.GetKey());
                    if (m_nKeyType == EVP_PKEY_EC)
                    {
                        // for ECDSA certificate also get the curve/paramset
                        if (m_nCurve == 0)
                        {
                            m_nCurve = oIssuer.GetCurve();
                        }
                    }
                }
                // default EC curve
                if (m_nKeyType == EVP_PKEY_EC && m_nCurve == 0)
                {
                    m_nCurve = NID_X9_62_prime256v1;
                }
                if ((m_nKeyType == EVP_PKEY_RSA || m_nKeyType == EVP_PKEY_RSA_PSS) && m_nKeySize == 0)
                {
                    m_nKeySize = 2048;
                }

                if (oCert.GenerateKey(m_nKeyType, m_nKeySize, m_nCurve) <= 0)
                    goto err;
            }

            // Create the request
            if (m_bRenew)
            {
                if (oCert.CreateReqFromCert() <= 0)
                {
                    goto err;
                }
            }
            else
            {
                if (oCert.CreateReq(m_pConf, szSection, szX509v3reqext) <= 0)
                {
                    goto err;
                }
            }
        }

        // Generate the cert
        if (oCert.CreateCert(m_pConf,
                             szX509v3ext,
                             oIssuer,
                             nSerial,
                             (long)(0 - 15 * 60),
                             (long)(m_nDays * 24 * 60 * 60 - 15 * 60),
                             m_pDigest) <= 0)
            goto err;

        // Update serial number
        if (fopen_s(&fp, strSerialFile.c_str(), "wb") != 0)
        {
            goto err;
        }
        else
        {
            nSerial++; /* next cert serial no to be issued */
            fwrite(&nSerial, sizeof(int), 1, fp);
            fclose(fp);
        }

        // Write the resulting files
        oCert.WriteCerFile(m_strOutCer, m_bSaveCertAsDer);
        if (m_strReq.empty()) // no PFX or private key output if we were given a req
        {
            oCert.WritePfxFile(m_strOutPfx, m_strPassword);
            if (m_bSaveKeyToFile)
            {
                oCert.WriteKeyFile(m_strOutKey, m_bSaveCertAsDer);
            }
        }
        if (m_bSaveReqToFile)
        {
            oCert.WriteReqFile(m_strOutReq, m_bSaveCertAsDer);
        }
    }
    return 1;

err:

    printf("Operation failed.\n");
    return -1;
}
