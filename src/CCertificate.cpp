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
#include "CCertificate.h"


static int copy_extensions_req_to_cert(X509* cert, X509_REQ* req)
{
    STACK_OF(X509_EXTENSION)* exts = NULL;
    X509_EXTENSION* ext;
    ASN1_OBJECT* obj;
    int i, idx, ret = 0;
    if (!cert || !req)
        return 1;
    exts = X509_REQ_get_extensions(req);

    for (i = 0; i < sk_X509_EXTENSION_num(exts); i++)
    {
        ext = sk_X509_EXTENSION_value(exts, i);
        obj = X509_EXTENSION_get_object(ext);
        idx = X509_get_ext_by_OBJ(cert, obj, -1);
        /* Does extension exist? */
        if (idx != -1)
        {
            /* Don't add duplicates */
            continue;
        }
        if (!X509_add_ext(cert, ext, -1))
            goto end;
    }

    ret = 1;

end:

    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    return ret;
}

static int copy_extensions_cert_to_req(X509* cert, X509_REQ* req)
{
    const STACK_OF(X509_EXTENSION)* exts = NULL;
    int ret                              = 0;
    if (!cert || !req)
        return 1;
    exts = X509_get0_extensions(cert);
    if (!X509_REQ_add_extensions(req, (STACK_OF(X509_EXTENSION)*)exts))
    {
        goto end;
    }
    ret = 1;

end:

    return ret;
}


CCertificate::CCertificate()
    : m_pCert(NULL),
      m_pKey(NULL),
      m_pReq(NULL),
      m_pCrl(NULL)
{
}

CCertificate::~CCertificate()
{
    if (m_pCert)
    {
        X509_free(m_pCert);
    }
    if (m_pKey)
    {
        EVP_PKEY_free(m_pKey);
    }
    if (m_pReq)
    {
        X509_REQ_free(m_pReq);
    }
    if (m_pCrl)
    {
        X509_CRL_free(m_pCrl);
    }
}

bool CCertificate::HasKey()
{
    return m_pKey != NULL;
}

EVP_PKEY* CCertificate::GetKey()
{
    return m_pKey;
}

X509* CCertificate::CertX509()
{
    return m_pCert;
}


int CCertificate::ReadPfx(string strFile, string& strPassword)
{
    int ret                             = -1;
    BIO* bio                            = NULL;
    int bag_nid                         = -1;
    PKCS12* p12                         = NULL;
    STACK_OF(PKCS7)* auth_safes         = NULL;
    STACK_OF(PKCS12_SAFEBAG)* safe_bags = NULL;
    PKCS7* auth_safe                    = NULL;
    PKCS12_SAFEBAG* safe_bag            = NULL;
    PKCS8_PRIV_KEY_INFO* p8             = NULL;

    X509* cert    = NULL;
    EVP_PKEY* key = NULL;

    // Free existing objects if they already exist
    if (m_pCert)
    {
        X509_free(m_pCert);
        m_pCert = NULL;
    }
    if (m_pKey)
    {
        EVP_PKEY_free(m_pKey);
        m_pKey = NULL;
    }

    /* get bio */
    if (!(bio = BIO_new_file(strFile.c_str(), "rb")))
        goto err;
    /* read p12 from bio */
    if (!(p12 = d2i_PKCS12_bio(bio, NULL)))
        goto err;
    /* verify the pasword */
    if (!PKCS12_verify_mac(p12, strPassword.c_str(), (int)strPassword.length()))
        goto err;
    /* get the auth_safes */
    if (!(auth_safes = PKCS12_unpack_authsafes(p12)))
        goto err;

    for (int i = 0; i < sk_PKCS7_num(auth_safes); i++)
    {
        auth_safe = 0;
        safe_bags = 0;

        // take one AUTHSAFE
        auth_safe = sk_PKCS7_value(auth_safes, i);
        bag_nid   = OBJ_obj2nid(auth_safe->type);

        // AUTHSAFE type "data"
        if (NID_pkcs7_data == bag_nid)
        {
            // get SAFEBAGs
            if (!(safe_bags = PKCS12_unpack_p7data(auth_safe)))
                continue;
        }
        // AUTHSAFE type "encrypted data"
        else if (NID_pkcs7_encrypted == bag_nid)
        {
            // get SAFEBAGs
            if (!(safe_bags = PKCS12_unpack_p7encdata(auth_safe, strPassword.c_str(), (int)strPassword.length())))
                continue;
        }
        else
            continue;

        for (int j = 0; j < sk_PKCS12_SAFEBAG_num(safe_bags); j++)
        {
            // take one SAFEBAG
            if (!(safe_bag = sk_PKCS12_SAFEBAG_value(safe_bags, j)))
                continue;
            bag_nid = PKCS12_bag_type(safe_bag);

            switch (bag_nid)
            {
            // SAFEBAG type "certificate bag"
            case NID_certBag:
                if (NID_x509Certificate != PKCS12_cert_bag_type(safe_bag))
                    continue;
                if (!(cert = PKCS12_certbag2x509(safe_bag)))
                    continue;
                break;

            // SAFEBAG type "key bag"
            case NID_keyBag:
                if (key)
                    break;
                p8 = (PKCS8_PRIV_KEY_INFO*)PKCS12_SAFEBAG_get0_p8inf(safe_bag);
                if (!(key = EVP_PKCS82PKEY(p8)))
                    continue;
                break;

            // SAFEBAG type "pkcs8 shrouded key bag"
            case NID_pkcs8ShroudedKeyBag:
                if (!(p8 = PKCS12_decrypt_skey(safe_bag, strPassword.c_str(), (int)strPassword.length())))
                    continue;
                key = EVP_PKCS82PKEY(p8);
                break;

            default:
                break;
            }
        }
        if (safe_bags)
            sk_PKCS12_SAFEBAG_pop_free(safe_bags, PKCS12_SAFEBAG_free);
    }

    if (cert && key)
    {
        m_pKey = key;
        EVP_PKEY_up_ref(m_pKey);
        m_pCert = X509_dup(cert);
    }

    ret = 1;

err:
    if (key)
        EVP_PKEY_free(key);
    if (cert)
        X509_free(cert);
    if (p8)
        PKCS8_PRIV_KEY_INFO_free(p8);
    if (auth_safes)
        sk_PKCS7_pop_free(auth_safes, PKCS7_free);
    if (p12)
        PKCS12_free(p12);
    if (bio)
        BIO_free(bio);

    return ret;
}

int CCertificate::KeyGenCB(int p, int n, BN_GENCB* cb)
{
    char ch = '*';

    if (p == 0)
        ch = '.';
    else if (p == 1)
        ch = '+';
    else if (p == 2)
        ch = '*';
    else if (p == 3)
        ch = '\n';

    printf("%c", ch);
    return 1;
}


int CCertificate::GenerateKey(int key_type, int key_size, int nCurve)
{
    int ret            = -1;
    EVP_PKEY* key      = NULL;
    BIGNUM* e          = NULL;
    EVP_PKEY_CTX* pctx = NULL;

    BN_GENCB* pCB = BN_GENCB_new();
    BN_GENCB_set(pCB, KeyGenCB, NULL);

    pctx = EVP_PKEY_CTX_new_id(key_type, NULL);
    if (!pctx)
        goto err;
    if (EVP_PKEY_keygen_init(pctx) <= 0)
        goto err;

    if (key_type == EVP_PKEY_RSA || key_type == EVP_PKEY_RSA_PSS)
    {
        if (0 >= EVP_PKEY_CTX_ctrl(pctx, key_type, EVP_PKEY_OP_KEYGEN, EVP_PKEY_CTRL_RSA_KEYGEN_BITS, key_size, NULL))
            goto err;
        e = BN_new();
        if (!e)
            goto err;
        BN_set_word(e, 0x10001);
        if (0 >= EVP_PKEY_CTX_ctrl(pctx, key_type, EVP_PKEY_OP_KEYGEN, EVP_PKEY_CTRL_RSA_KEYGEN_PUBEXP, 0, e))
            goto err;
    }
    else if (key_type == EVP_PKEY_EC)
    {
        if (0 >= EVP_PKEY_CTX_ctrl(pctx, key_type, EVP_PKEY_OP_KEYGEN, EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID, nCurve, NULL))
            goto err;
        if (0 >= EVP_PKEY_CTX_ctrl(pctx, key_type, EVP_PKEY_OP_KEYGEN, EVP_PKEY_CTRL_EC_PARAM_ENC, OPENSSL_EC_NAMED_CURVE, NULL))
            goto err;
    }
    else if (key_type == EVP_PKEY_ED25519 || key_type == EVP_PKEY_ED448)
    {
    }

    if (EVP_PKEY_keygen(pctx, &key) <= 0)
        goto err;

    m_pKey = key;
    key    = NULL;
    ret    = 1;

err:
    if (key)
        EVP_PKEY_free(key);
    if (pctx)
        EVP_PKEY_CTX_free(pctx);
    if (pCB)
        BN_GENCB_free(pCB);

    return ret;
}


// From OpenSSL req.c
static int do_sign_init(EVP_MD_CTX* ctx, EVP_PKEY* pkey, const EVP_MD* md)
{
    EVP_PKEY_CTX* pKeyCtx = NULL;
    int def_nid;

    if (ctx == NULL)
        return 0;
    // EVP_PKEY_get_default_digest_nid() returns 2 if the digest is mandatory
    // for this algorithm.
    if (EVP_PKEY_get_default_digest_nid(pkey, &def_nid) == 2 && def_nid == NID_undef)
    {
        /* The signing algorithm requires there to be no digest */
        md = NULL;
    }
    if (!EVP_DigestSignInit(ctx, &pKeyCtx, md, NULL, pkey))
        return 0;

    int type = EVP_PKEY_type(EVP_PKEY_base_id(pkey));
    if (type == EVP_PKEY_RSA_PSS)
    {
        EVP_PKEY_CTX_ctrl(pKeyCtx, type, EVP_PKEY_OP_SIGN, EVP_PKEY_CTRL_RSA_PADDING, RSA_PKCS1_PSS_PADDING, NULL);
        EVP_PKEY_CTX_ctrl(pKeyCtx, type, EVP_PKEY_OP_SIGN, EVP_PKEY_CTRL_RSA_MGF1_MD, 0, (void*)md);
        EVP_PKEY_CTX_ctrl(pKeyCtx, type, EVP_PKEY_OP_SIGN, EVP_PKEY_CTRL_RSA_PSS_SALTLEN, -1, NULL);
    }

    return 1;
}


int CCertificate::CreateReq(CONF* pConf, const char* szSection, const char* szX509v3ext)
{
    int ret                          = -1;
    STACK_OF(CONF_VALUE)* dn_sk_user = NULL;
    X509_NAME* dn                    = NULL;
    CONF_VALUE* val                  = NULL;
    int nid                          = NID_undef;
    const EVP_MD* pDigest            = NULL;
    EVP_MD_CTX* pMDCtx               = NULL;
    X509V3_CTX v3ExtCtx;

    if (!(dn_sk_user = NCONF_get_section(pConf, szSection)))
    {
        goto err;
    }

    if (!(m_pReq = X509_REQ_new()))
        goto err;
    if (!X509_REQ_set_version(m_pReq, 0L)) /* 0 => version 1 certificate request */
        goto err;
    if (!(dn = X509_REQ_get_subject_name(m_pReq)))
        goto err;

    for (int i = 0; i < sk_CONF_VALUE_num(dn_sk_user); i++)
    {
        val = sk_CONF_VALUE_value(dn_sk_user, i);
        if (NID_undef == (nid = OBJ_txt2nid(val->name)))
            continue;
        if (!X509_NAME_add_entry_by_NID(dn, nid, MBSTRING_ASC, (unsigned char*)val->value, -1, -1, 0))
            goto err;
    }
    if (!X509_REQ_set_pubkey(m_pReq, m_pKey))
        goto err;

    // ###ET###
    memset(&v3ExtCtx, 0, sizeof(v3ExtCtx));
    X509V3_set_ctx(&v3ExtCtx, NULL, NULL, m_pReq, NULL, 0);
    X509V3_set_nconf(&v3ExtCtx, pConf);
    if (!X509V3_EXT_REQ_add_nconf(pConf, &v3ExtCtx, szX509v3ext, m_pReq))
        goto err;

    pDigest = DigestFromKey(m_pKey);

    pMDCtx = EVP_MD_CTX_new();
    ret    = do_sign_init(pMDCtx, m_pKey, pDigest);
    if (ret <= 0)
        goto err;

    ret = X509_REQ_sign_ctx(m_pReq, pMDCtx);
    EVP_MD_CTX_free(pMDCtx);
    if (ret <= 0)
        goto err;

    X509_REQ_print(COpenSSL::Stdout(), m_pReq);
    ret = 1;

err:
    if (ret <= 0 && NULL != m_pReq)
    {
        X509_REQ_free(m_pReq);
        m_pReq = NULL;
    }
    return ret;
}


int CCertificate::CreateReqFromCert()
{
    int ret = -1;
    m_pReq  = X509_to_X509_REQ(m_pCert, m_pKey, DigestFromKey(m_pKey));
    if (!m_pReq)
    {
        return -1;
    }
    ret = copy_extensions_cert_to_req(m_pCert, m_pReq);
    if (ret <= 0)
        goto err;

    X509_REQ_print(COpenSSL::Stdout(), m_pReq);
    ret = 1;

err:
    if (ret <= 0 && NULL != m_pReq)
    {
        X509_REQ_free(m_pReq);
        m_pReq = NULL;
    }
    return ret;
}


const EVP_MD* CCertificate::DigestFromSigAlg(int nid)
{
    switch (nid)
    {
    case NID_md5WithRSAEncryption:
        return EVP_md5();
    case NID_sha1WithRSAEncryption:
    case NID_ecdsa_with_SHA1:
        return EVP_sha1();
    case NID_sha224WithRSAEncryption:
    case NID_ecdsa_with_SHA224:
        return EVP_sha224();
    case NID_sha256WithRSAEncryption:
    case NID_ecdsa_with_SHA256:
        return EVP_sha256();
    case NID_sha384WithRSAEncryption:
    case NID_ecdsa_with_SHA384:
        return EVP_sha384();
    case NID_sha512WithRSAEncryption:
    case NID_ecdsa_with_SHA512:
        return EVP_sha512();
    default:
        return EVP_sha1();
    }
}

const EVP_MD* CCertificate::DigestFromKey(EVP_PKEY* pKey)
{
    int type = EVP_PKEY_type(EVP_PKEY_base_id(pKey));
    int bits = EVP_PKEY_bits(pKey);

    if (type == EVP_PKEY_RSA || type == EVP_PKEY_RSA_PSS)
    {
        return EVP_sha256();
    }
    else if (type == EVP_PKEY_EC)
    {
        if (bits >= 521)
        {
            return EVP_sha512();
        }
        else if (bits >= 384)
        {
            return EVP_sha384();
        }
        else
        {
            return EVP_sha256();
        }
    }
    // EdDSA should pass NULL
    return NULL;
}


int CCertificate::GetCurve()
{
    int pkey_param_nid = NID_undef;
    switch (EVP_PKEY_base_id(m_pKey))
    {
    case EVP_PKEY_EC:
        pkey_param_nid = EC_GROUP_get_curve_name(EC_KEY_get0_group((const EC_KEY*)EVP_PKEY_get0((EVP_PKEY*)m_pKey)));
        break;
    default:
        break;
    }
    return pkey_param_nid;
}


int CCertificate::CreateCert(CONF* pConf,
                             const char* szX509v3ext,
                             CCertificate& oIssuer,
                             long nSerial,
                             long nNotBefore,
                             long nNotAfter,
                             const EVP_MD* pDigest)
{
    int ret              = -1;
    X509* pCert          = NULL;
    EVP_PKEY* pPubKey    = NULL;
    EVP_PKEY* pPrivKey   = NULL;
    X509V3_CTX pV3ExtCtx = {0};
    EVP_MD_CTX* pMDCtx   = NULL;

    if (pDigest)
    {
        const char* name = EVP_MD_name(pDigest);
        printf("Digest: %s", name);
    }

    if (!(pCert = X509_new()))
        goto err;

    if (!X509_set_version(pCert, 2)) // 2 => version 3 certificate
        goto err;

    X509_gmtime_adj(X509_get_notBefore(pCert), nNotBefore);
    X509_gmtime_adj(X509_get_notAfter(pCert), nNotAfter);

    X509_set_subject_name(pCert, X509_REQ_get_subject_name(m_pReq));
    pPubKey = X509_REQ_get_pubkey(m_pReq);
    X509_set_pubkey(pCert, pPubKey);
    EVP_PKEY_free(pPubKey);
    X509V3_set_ctx(&pV3ExtCtx, oIssuer.CertX509(), pCert, m_pReq, NULL, 0);
    ASN1_INTEGER_set(X509_get_serialNumber(pCert), nSerial);
    if (!oIssuer.CertX509()) /* self-signed root ca */
        X509_set_issuer_name(pCert, X509_REQ_get_subject_name(m_pReq));
    else /* end user issued by issuer */
        X509_set_issuer_name(pCert, X509_get_subject_name(oIssuer.CertX509()));
    if (!X509V3_EXT_add_nconf(pConf, &pV3ExtCtx, (char*)szX509v3ext, pCert))
        goto err;
    ret = copy_extensions_req_to_cert(pCert, m_pReq);
    if (ret <= 0)
        goto err;

    pPrivKey = oIssuer.HasKey() ? oIssuer.GetKey() : GetKey();
    pDigest  = pDigest ? pDigest : DigestFromKey(pPrivKey);

    pMDCtx = EVP_MD_CTX_new();
    ret    = do_sign_init(pMDCtx, pPrivKey, pDigest);
    if (ret <= 0)
        goto err;

    ret = X509_sign_ctx(pCert, pMDCtx);
    if (ret <= 0)
        goto err;

    X509_print(COpenSSL::Stdout(), pCert);

    m_pCert = pCert;
    pCert   = NULL;
    ret     = 1;

err:
    if (pCert)
        X509_free(pCert);
    if (pMDCtx)
        EVP_MD_CTX_free(pMDCtx);
    return ret;
}


int CCertificate::PrintCert()
{
    if (!m_pCert)
    {
        return -1;
    }

    X509_print(COpenSSL::Stdout(), m_pCert);

    return 1;
}

int CCertificate::PrintCrl()
{
    if (!m_pCrl)
    {
        return -1;
    }

    X509_CRL_print(COpenSSL::Stdout(), m_pCrl);

    return 1;
}

int CCertificate::WritePfxFile(string strFile, string& strPassword)
{
    PKCS12* p12                    = NULL;
    STACK_OF(PKCS7)* safes         = NULL;
    PKCS7* authsafe                = NULL;
    STACK_OF(PKCS12_SAFEBAG)* bags = NULL;
    PKCS12_SAFEBAG* bag            = NULL;
    PKCS8_PRIV_KEY_INFO* p8        = NULL;
    STACK_OF(X509)* certs          = NULL;
    X509* cert                     = NULL;
    unsigned char keyid[EVP_MAX_MD_SIZE];
    unsigned int keyidlen = 0;
    int i                 = 0;

    BIO* bio_user = NULL;

    if (!X509_check_private_key(m_pCert, m_pKey))
        goto err;
    X509_digest(m_pCert, EVP_sha1(), keyid, &keyidlen);


    if (!(certs = sk_X509_new_null()))
        goto err;
    sk_X509_push(certs, m_pCert);
    X509_up_ref(m_pCert);

    if (!(bags = sk_PKCS12_SAFEBAG_new_null()))
        goto err;
    for (i = 0; i < sk_X509_num(certs); i++)
    {
        cert = sk_X509_value(certs, i);
        bag  = PKCS12_x5092certbag(cert);
        if (cert == m_pCert) /* If it matches private key set id */
            PKCS12_add_localkeyid(bag, keyid, keyidlen);
        sk_PKCS12_SAFEBAG_push(bags, bag);
    }
    sk_X509_pop_free(certs, X509_free);
    certs = NULL;

    /* Turn it into unencrypted safe bag */
    if (!(authsafe = PKCS12_pack_p7data(bags)))
        goto err;
    sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
    bags = NULL;

    if (!(safes = sk_PKCS7_new_null()))
        goto err;
    sk_PKCS7_push(safes, authsafe);

    /* Make a shrouded key bag */
    if (!(p8 = EVP_PKEY2PKCS8(m_pKey)))
        goto err;
    bag = PKCS12_MAKE_SHKEYBAG(NID_pbe_WithSHA1And3_Key_TripleDES_CBC, strPassword.c_str(), -1, NULL, 0, PKCS12_DEFAULT_ITER, p8);
    PKCS8_PRIV_KEY_INFO_free(p8);
    p8 = NULL;
    PKCS12_add_localkeyid(bag, keyid, keyidlen);
    if (!(bags = sk_PKCS12_SAFEBAG_new_null()))
        goto err;
    sk_PKCS12_SAFEBAG_push(bags, bag);

    /* Turn it into unencrypted safe bag */
    if (!(authsafe = PKCS12_pack_p7data(bags)))
        goto err;
    sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
    bags = NULL;
    sk_PKCS7_push(safes, authsafe);

    if (!(p12 = PKCS12_init(NID_pkcs7_data)))
        goto err;
    if (!PKCS12_pack_authsafes(p12, safes))
        goto err;
    sk_PKCS7_pop_free(safes, PKCS7_free);
    safes = NULL;
    if (!PKCS12_set_mac(p12, strPassword.c_str(), -1, NULL, 0, PKCS12_DEFAULT_ITER, NULL))
        goto err;

    if (!strFile.empty())
    {
        if (!(bio_user = BIO_new_file(strFile.c_str(), "wb")))
            goto err;
        if (!i2d_PKCS12_bio(bio_user, p12))
            goto err;
        if (bio_user)
            BIO_free(bio_user);
        printf("=> %s saved.\n", strFile.c_str());
    }

    PKCS12_free(p12);
    return 1;

err:
    if (bio_user)
        BIO_free(bio_user);
    if (certs)
        sk_X509_pop_free(certs, X509_free);
    if (p8)
        PKCS8_PRIV_KEY_INFO_free(p8);
    if (safes)
        sk_PKCS7_pop_free(safes, PKCS7_free);
    if (bags)
        sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
    if (p12)
        PKCS12_free(p12);
    return -1;
}

int CCertificate::WriteCerFile(string strFile, bool bDer)
{
    BIO* bio_cert = BIO_new_file(strFile.c_str(), "wb");
    if (!bio_cert)
    {
        printf("Unable to open file \"%s\"\n", strFile.c_str());
        goto err;
    }
    if (bDer)
    {
        if (!i2d_X509_bio(bio_cert, m_pCert))
        {
            printf("Unable to write cert to \"%s\"\n", strFile.c_str());
            goto err;
        }
    }
    else
    {
        if (!PEM_write_bio_X509(bio_cert, m_pCert))
        {
            printf("Unable to write cert to \"%s\"\n", strFile.c_str());
            goto err;
        }
    }
    printf("=> %s saved.\n", strFile.c_str());
    BIO_free(bio_cert);
    return 1;
err:
    if (bio_cert)
        BIO_free(bio_cert);
    return -1;
}

int CCertificate::WriteReqFile(string strFile, bool bDer)
{
    BIO* bio_cert = BIO_new_file(strFile.c_str(), "wb");
    if (!bio_cert)
    {
        printf("Unable to open file \"%s\"\n", strFile.c_str());
        goto err;
    }
    if (bDer)
    {
        if (!i2d_X509_REQ_bio(bio_cert, m_pReq))
        {
            printf("Unable to write req to \"%s\"\n", strFile.c_str());
            goto err;
        }
    }
    else
    {
        if (!PEM_write_bio_X509_REQ(bio_cert, m_pReq))
        {
            printf("Unable to write req to \"%s\"\n", strFile.c_str());
            goto err;
        }
    }
    printf("=> %s saved.\n", strFile.c_str());
    BIO_free(bio_cert);
    return 1;
err:
    if (bio_cert)
        BIO_free(bio_cert);
    return -1;
}

int CCertificate::ReadCert(string strFile)
{
    int ret       = -1;
    BIO* bio_cert = NULL;
    BIO* bio_b64  = NULL;

    if (m_pCert)
    {
        X509_free(m_pCert);
        m_pCert = NULL;
    }

    bio_cert = BIO_new_file(strFile.c_str(), "rb");
    if (bio_cert)
    { // file exists
        // try to read it in
        m_pCert = d2i_X509_bio(bio_cert, NULL);
        if (!m_pCert)
        { // might be b64
            BIO_free(bio_cert);
            bio_cert = BIO_new_file(strFile.c_str(), "rb");
            if (bio_cert)
            {
                bio_b64 = BIO_new(BIO_f_base64());
                if (bio_b64)
                {
                    bio_cert = BIO_push(bio_b64, bio_cert);
                }
                else
                {
                    BIO_free(bio_cert);
                    bio_cert = NULL;
                }
            }
            if (bio_cert)
            {
                m_pCert = d2i_X509_bio(bio_cert, NULL);
            }
        }
    }
    if (bio_cert)
    {
        BIO_free_all(bio_cert);
    }
    ERR_clear_error();

    if (m_pCert)
        ret = 1;

    // err:
    return ret;
}


int CCertificate::ReadCrl(string strFile, bool bCreateIfMissing)
{
    int ret            = -1;
    BIO* bio_crl       = NULL;
    BIO* bio_b64       = NULL;
    EVP_MD_CTX* pMDCtx = NULL;

    if (this->m_pCrl)
    {
        X509_CRL_free(m_pCrl);
        m_pCrl = NULL;
    }

    bio_crl = BIO_new_file(strFile.c_str(), "rb");
    if (bio_crl)
    { // file exists
        // try to read it in
        m_pCrl = d2i_X509_CRL_bio(bio_crl, NULL);
        if (!m_pCrl)
        { // might be b64
            BIO_free(bio_crl);
            bio_crl = BIO_new_file(strFile.c_str(), "rb");
            if (bio_crl)
            {
                bio_b64 = BIO_new(BIO_f_base64());
                if (bio_b64)
                {
                    bio_crl = BIO_push(bio_b64, bio_crl);
                }
                else
                {
                    BIO_free(bio_crl);
                    bio_crl = NULL;
                }
            }
            if (bio_crl)
            {
                m_pCrl = d2i_X509_CRL_bio(bio_crl, NULL);
            }
        }
    }
    if (bio_crl)
    {
        BIO_free_all(bio_crl);
    }
    ERR_clear_error();

    // Create one if we were unable to read it, if requested
    if (!m_pCrl && bCreateIfMissing)
    {
        m_pCrl = X509_CRL_new();
        if (m_pCrl)
        {
            ASN1_UTCTIME* pTime = ASN1_UTCTIME_new();
            X509_CRL_set_version(m_pCrl, 1);
            X509_CRL_set_issuer_name(m_pCrl, X509_get_subject_name(m_pCert));
            X509_CRL_set1_lastUpdate(m_pCrl, ASN1_UTCTIME_adj(pTime, time(0), 0, 0));
            X509_CRL_set1_nextUpdate(m_pCrl, ASN1_UTCTIME_adj(pTime, time(0), 1, 0)); // 1 day
            ASN1_UTCTIME_free(pTime);

            pMDCtx = EVP_MD_CTX_new();
            ret    = do_sign_init(pMDCtx, m_pKey, DigestFromKey(m_pKey));
            if (ret <= 0)
                goto err;

            ret = X509_CRL_sign_ctx(m_pCrl, pMDCtx);
            if (ret <= 0)
            {
                printf("Unable to sign CRL\n");
                goto err;
            }
        }
        else
        {
            printf("Unable to create new CRL\n");
            goto err;
        }
    }
    if (!m_pCrl)
    {
        goto err;
    }

    ret = 1;

err:
    if (pMDCtx)
        EVP_MD_CTX_free(pMDCtx);
    return ret;
}


int CCertificate::ReadReq(string strFile)
{
    int ret      = -1;
    BIO* bio_req = NULL;
    BIO* bio_b64 = NULL;

    if (this->m_pReq)
    {
        X509_REQ_free(m_pReq);
        m_pReq = NULL;
    }

    bio_req = BIO_new_file(strFile.c_str(), "rb");
    if (bio_req)
    { // file exists
        // try to read it in
        m_pReq = d2i_X509_REQ_bio(bio_req, NULL);
        if (!m_pReq)
        { // might be b64
            BIO_free(bio_req);
            bio_req = BIO_new_file(strFile.c_str(), "rb");
            if (bio_req)
            {
                bio_b64 = BIO_new(BIO_f_base64());
                if (bio_b64)
                {
                    bio_req = BIO_push(bio_b64, bio_req);
                }
                else
                {
                    BIO_free(bio_req);
                    bio_req = NULL;
                }
            }
            if (bio_req)
            {
                m_pReq = d2i_X509_REQ_bio(bio_req, NULL);
            }
        }
    }
    if (bio_req)
    {
        BIO_free_all(bio_req);
    }
    ERR_clear_error();

    // Create one if we were unable to read it
    if (!m_pReq)
    {
        printf("Unable to read Certificate Request\n");
        goto err;
    }
    ret = 1;

err:
    return ret;
}


int CCertificate::Revoke(CCertificate& oCert, int nReason)
{
    int ret                       = -1;
    X509_REVOKED* revoked         = NULL;
    ASN1_OCTET_STRING* reason_str = NULL;
    X509_EXTENSION* crl_entry_ext = NULL;
    ASN1_ENUMERATED* reason_enum  = NULL;
    unsigned char* reason_buf     = NULL;
    unsigned char* reason_buf_tmp = NULL;
    int reason_size               = 0;
    EVP_MD_CTX* pMDCtx            = NULL;

    if (!m_pCrl)
    {
        printf("Issuer does not have a CRL to update.\n");
        return ret;
    }

    // Now we have a crl, all we need to do is change it time, plus add subject cert as a revoked cert
    ASN1_UTCTIME* pTime = ASN1_UTCTIME_new();
    X509_CRL_set1_lastUpdate(m_pCrl, ASN1_UTCTIME_adj(pTime, time(0), 0, 0));
    X509_CRL_set1_nextUpdate(m_pCrl, ASN1_UTCTIME_adj(pTime, time(0), 1, 0)); // 1 day

    revoked = X509_REVOKED_new();
    X509_REVOKED_set_serialNumber(revoked, X509_get_serialNumber(oCert.CertX509()));

    int nLocation = sk_X509_REVOKED_find(X509_CRL_get_REVOKED(m_pCrl), revoked);
    if (nLocation >= 0)
    {
        printf("Certificate serial already present in CRL, replacing\n");
        X509_REVOKED* pOrig = sk_X509_REVOKED_delete(X509_CRL_get_REVOKED(m_pCrl), nLocation);
        X509_REVOKED_free(pOrig);
    }
    X509_REVOKED_set_revocationDate(revoked, ASN1_UTCTIME_adj(pTime, time(0), 0, 0));
    ASN1_UTCTIME_free(pTime);

    STACK_OF(X509_EXTENSION)* extensions = sk_X509_EXTENSION_new(0);

    // add revocation reason for certificate
    reason_enum = ASN1_ENUMERATED_new();
    ASN1_ENUMERATED_set(reason_enum, nReason);
    reason_size    = i2d_ASN1_ENUMERATED(reason_enum, NULL);
    reason_buf     = (unsigned char*)OPENSSL_malloc(reason_size);
    reason_buf_tmp = reason_buf;
    reason_size    = i2d_ASN1_ENUMERATED(reason_enum, &reason_buf_tmp);
    reason_str     = ASN1_OCTET_STRING_new();
    ASN1_OCTET_STRING_set(reason_str, reason_buf, reason_size);
    crl_entry_ext = X509_EXTENSION_create_by_NID(NULL, NID_crl_reason, 0, reason_str);
    sk_X509_EXTENSION_push(extensions, crl_entry_ext);
    X509_REVOKED_add_ext(revoked, crl_entry_ext, 0);

    X509_CRL_add0_revoked(m_pCrl, revoked);
    ASN1_OCTET_STRING_free(reason_str);
    OPENSSL_free(reason_buf);
    ASN1_ENUMERATED_free(reason_enum);

    X509_EXTENSION_free(crl_entry_ext); // ###ET###
    sk_X509_EXTENSION_free(extensions);

    /* Sort the data so it will be written in serial number order */
    X509_CRL_sort(m_pCrl);

    pMDCtx = EVP_MD_CTX_new();
    ret    = do_sign_init(pMDCtx, m_pKey, DigestFromKey(m_pKey));
    if (ret <= 0)
        goto err;

    ret = X509_CRL_sign_ctx(m_pCrl, pMDCtx);
    if (ret <= 0)
    {
        printf("Unable to sign CRL\n");
        goto err;
    }

    X509_CRL_print(COpenSSL::Stdout(), m_pCrl);
    ret = 1;

err:
    if (pMDCtx)
        EVP_MD_CTX_free(pMDCtx);
    return ret;
}

int CCertificate::WriteCrlFile(string strFile, bool bDer)
{
    int ret      = -1;
    BIO* bio_crl = BIO_new_file(strFile.c_str(), "wb");
    if (!bio_crl)
    {
        printf("Unable to open file \"%s\"\n", strFile.c_str());
        goto err;
    }
    if (bDer)
    {
        if (!i2d_X509_CRL_bio(bio_crl, m_pCrl))
        {
            printf("Unable to write CRL to \"%s\"\n", strFile.c_str());
            goto err;
        }
    }
    else
    {
        if (!PEM_write_bio_X509_CRL(bio_crl, m_pCrl))
        {
            printf("Unable to write CRL to \"%s\"\n", strFile.c_str());
            goto err;
        }
    }
    printf("=> %s saved.\n", strFile.c_str());
    ret = 1;
err:
    if (bio_crl)
        BIO_free(bio_crl);
    return ret;
}


int CCertificate::WriteKeyFile(string strFile, bool bDer)
{
    int ret      = -1;
    BIO* bio_key = BIO_new_file(strFile.c_str(), "wb");
    if (!bio_key)
    {
        printf("Unable to open file \"%s\"\n", strFile.c_str());
        goto err;
    }
    if (bDer)
    {
        if (!i2d_PrivateKey_bio(bio_key, m_pKey))
        {
            printf("Unable to write key to \"%s\"\n", strFile.c_str());
            goto err;
        }
    }
    else
    {
        int nRet = PEM_write_bio_PrivateKey(bio_key, m_pKey, NULL, NULL, 0, NULL, NULL);
        if (nRet <= 0)
        {
            printf("Unable to write key to \"%s\"\n", strFile.c_str());
            goto err;
        }
    }
    printf("=> %s saved.\n", strFile.c_str());
    ret = 1;

err:
    if (bio_key)
        BIO_free(bio_key);
    return ret;
}
