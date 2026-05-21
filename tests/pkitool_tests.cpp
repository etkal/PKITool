#include "COpenSSL.h"
#include "CCertificate.h"

#include <gtest/gtest.h>

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pkcs12.h>
#include <openssl/bio.h>

#include <cstdio>
#include <string>
#include <thread>
#include <vector>
#include <cstdlib>

using namespace std;

class OpenSSLFixture : public ::testing::Test
{
protected:
    void SetUp() override
    {
        new COpenSSL();
    }
};

TEST_F(OpenSSLFixture, ReadPfx_RSA)
{
    EVP_PKEY* pkey       = nullptr;
    X509* cert           = nullptr;
    PKCS12* p12          = nullptr;
    BIO* bio             = nullptr;
    const char* password = "testpass";
    const char* filename = "test_output.pfx";
    printf("Testing with RSA key, output file = %s\n", filename);

    // Generate RSA key
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    ASSERT_NE(pctx, nullptr);
    ASSERT_GT(EVP_PKEY_keygen_init(pctx), 0);
    ASSERT_GT(EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048), 0);
    ASSERT_GT(EVP_PKEY_keygen(pctx, &pkey), 0);
    EVP_PKEY_CTX_free(pctx);

    // Create self-signed cert
    cert = X509_new();
    ASSERT_NE(cert, nullptr);
    X509_set_version(cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 31536000L);
    X509_set_pubkey(cert, pkey);

    X509_NAME* name = X509_NAME_new();
    ASSERT_NE(name, nullptr);
    X509_NAME_add_entry_by_NID(name, NID_commonName, MBSTRING_ASC, (unsigned char*)"Test Cert", -1, -1, 0);
    X509_set_subject_name(cert, name);
    X509_set_issuer_name(cert, name);
    X509_NAME_free(name);

    ASSERT_GT(X509_sign(cert, pkey, EVP_sha256()), 0);

    p12 = PKCS12_create(password,
                        "pkitool test",
                        pkey,
                        cert,
                        NULL,
                        NID_pbe_WithSHA1And3_Key_TripleDES_CBC,
                        0,
                        PKCS12_DEFAULT_ITER,
                        PKCS12_DEFAULT_ITER,
                        0);
    ASSERT_NE(p12, nullptr);

    bio = BIO_new_file(filename, "wb");
    ASSERT_NE(bio, nullptr);
    ASSERT_GT(i2d_PKCS12_bio(bio, p12), 0);
    BIO_free(bio);
    PKCS12_free(p12);

    CCertificate certObj;
    string pwd(password);
    int r = certObj.ReadPfx(string(filename), pwd);
    EXPECT_EQ(r, 1);
    EXPECT_TRUE(certObj.HasKey());
    EXPECT_NE(certObj.CertX509(), nullptr);

    // cleanup
    if (pkey)
        EVP_PKEY_free(pkey);
    if (cert)
        X509_free(cert);
    printf("Removing %s\n", filename);
    remove(filename);
}

TEST_F(OpenSSLFixture, ReadPfxParallel_ECDSA256)
{
    const char* password = "testpass";
    const int threads    = 4;
    std::vector<int> results(threads, 0);
    std::vector<std::thread> ths;

    auto worker = [&](int idx) {
        EVP_PKEY* pkey = nullptr;
        X509* cert     = nullptr;
        PKCS12* p12    = nullptr;
        BIO* bio       = nullptr;
        char filename[64];
        std::snprintf(filename, sizeof(filename), "test_output_ec_%d.pfx", idx);
        printf("Testing with ECDSA key, output file = %s\n", filename);

        // Generate ECDSA P-256 key
        EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
        if (!pctx)
        {
            results[idx] = 0;
            return;
        }
        if (!(EVP_PKEY_keygen_init(pctx) > 0))
        {
            EVP_PKEY_CTX_free(pctx);
            results[idx] = 0;
            return;
        }
        if (!(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) > 0))
        {
            EVP_PKEY_CTX_free(pctx);
            results[idx] = 0;
            return;
        }
        if (!(EVP_PKEY_keygen(pctx, &pkey) > 0))
        {
            EVP_PKEY_CTX_free(pctx);
            results[idx] = 0;
            return;
        }
        EVP_PKEY_CTX_free(pctx);

        // Create self-signed cert
        cert = X509_new();
        if (!cert)
        {
            if (pkey)
                EVP_PKEY_free(pkey);
            results[idx] = 0;
            return;
        }
        X509_set_version(cert, 2);
        ASN1_INTEGER_set(X509_get_serialNumber(cert), idx + 1);
        X509_gmtime_adj(X509_get_notBefore(cert), 0);
        X509_gmtime_adj(X509_get_notAfter(cert), 31536000L);
        X509_set_pubkey(cert, pkey);

        X509_NAME* name = X509_NAME_new();
        if (!name)
        {
            X509_free(cert);
            if (pkey)
                EVP_PKEY_free(pkey);
            results[idx] = 0;
            return;
        }
        X509_NAME_add_entry_by_NID(name, NID_commonName, MBSTRING_ASC, (unsigned char*)"ECDSA Test Cert", -1, -1, 0);
        X509_set_subject_name(cert, name);
        X509_set_issuer_name(cert, name);
        X509_NAME_free(name);

        if (!(X509_sign(cert, pkey, EVP_sha256()) > 0))
        {
            X509_free(cert);
            if (pkey)
                EVP_PKEY_free(pkey);
            results[idx] = 0;
            return;
        }

        p12 = PKCS12_create(password,
                            "pkitool ec test",
                            pkey,
                            cert,
                            NULL,
                            NID_pbe_WithSHA1And3_Key_TripleDES_CBC,
                            0,
                            PKCS12_DEFAULT_ITER,
                            PKCS12_DEFAULT_ITER,
                            0);
        if (!p12)
        {
            X509_free(cert);
            if (pkey)
                EVP_PKEY_free(pkey);
            results[idx] = 0;
            return;
        }

        bio = BIO_new_file(filename, "wb");
        if (!bio)
        {
            PKCS12_free(p12);
            X509_free(cert);
            if (pkey)
                EVP_PKEY_free(pkey);
            results[idx] = 0;
            return;
        }
        if (!(i2d_PKCS12_bio(bio, p12) > 0))
        {
            BIO_free(bio);
            PKCS12_free(p12);
            X509_free(cert);
            if (pkey)
                EVP_PKEY_free(pkey);
            results[idx] = 0;
            return;
        }
        BIO_free(bio);
        PKCS12_free(p12);

        CCertificate certObj;
        std::string pwd(password);
        int r = certObj.ReadPfx(std::string(filename), pwd);
        if (r != 1)
        {
            if (cert)
                X509_free(cert);
            if (pkey)
                EVP_PKEY_free(pkey);
            remove(filename);
            results[idx] = 0;
            return;
        }
        if (!certObj.HasKey() || certObj.CertX509() == nullptr)
        {
            if (cert)
                X509_free(cert);
            if (pkey)
                EVP_PKEY_free(pkey);
            remove(filename);
            results[idx] = 0;
            return;
        }

        // cleanup
        if (pkey)
            EVP_PKEY_free(pkey);
        if (cert)
            X509_free(cert);
        printf("Removing %s\n", filename);
        remove(filename);
        results[idx] = 1;
    };

    for (int i = 0; i < threads; ++i)
        ths.emplace_back(worker, i);

    for (auto& t : ths)
        t.join();

    for (int i = 0; i < threads; ++i)
        EXPECT_EQ(results[i], 1);
}

TEST_F(OpenSSLFixture, ReadPfx_WrongPasswordFails)
{
    EVP_PKEY* pkey       = nullptr;
    X509* cert           = nullptr;
    PKCS12* p12          = nullptr;
    BIO* bio             = nullptr;
    const char* goodpw   = "goodpass";
    const char* badpw    = "badpass";
    const char* filename = "test_output_wrongpw.pfx";

    // Generate RSA key
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    ASSERT_NE(pctx, nullptr);
    ASSERT_GT(EVP_PKEY_keygen_init(pctx), 0);
    ASSERT_GT(EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048), 0);
    ASSERT_GT(EVP_PKEY_keygen(pctx, &pkey), 0);
    EVP_PKEY_CTX_free(pctx);

    // Create self-signed cert
    cert = X509_new();
    ASSERT_NE(cert, nullptr);
    X509_set_version(cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 42);
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 31536000L);
    X509_set_pubkey(cert, pkey);

    X509_NAME* name = X509_NAME_new();
    ASSERT_NE(name, nullptr);
    X509_NAME_add_entry_by_NID(name, NID_commonName, MBSTRING_ASC, (unsigned char*)"WrongPW Cert", -1, -1, 0);
    X509_set_subject_name(cert, name);
    X509_set_issuer_name(cert, name);
    X509_NAME_free(name);

    ASSERT_GT(X509_sign(cert, pkey, EVP_sha256()), 0);

    p12 = PKCS12_create(goodpw,
                        "pkitool test wrongpw",
                        pkey,
                        cert,
                        NULL,
                        NID_pbe_WithSHA1And3_Key_TripleDES_CBC,
                        0,
                        PKCS12_DEFAULT_ITER,
                        PKCS12_DEFAULT_ITER,
                        0);
    ASSERT_NE(p12, nullptr);

    bio = BIO_new_file(filename, "wb");
    ASSERT_NE(bio, nullptr);
    ASSERT_GT(i2d_PKCS12_bio(bio, p12), 0);
    BIO_free(bio);
    PKCS12_free(p12);

    CCertificate certObj;
    std::string wrong(badpw);
    int r = certObj.ReadPfx(std::string(filename), wrong);
    EXPECT_NE(r, 1);

    // cleanup
    if (pkey)
        EVP_PKEY_free(pkey);
    if (cert)
        X509_free(cert);
    remove(filename);
}

TEST_F(OpenSSLFixture, ReadPfx_CorruptedFileFails)
{
    EVP_PKEY* pkey       = nullptr;
    X509* cert           = nullptr;
    PKCS12* p12          = nullptr;
    BIO* bio             = nullptr;
    const char* password = "testpass";
    const char* filename = "test_output_corrupt.pfx";

    // Generate RSA key and cert (reuse pattern)
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    ASSERT_NE(pctx, nullptr);
    ASSERT_GT(EVP_PKEY_keygen_init(pctx), 0);
    ASSERT_GT(EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048), 0);
    ASSERT_GT(EVP_PKEY_keygen(pctx, &pkey), 0);
    EVP_PKEY_CTX_free(pctx);

    cert = X509_new();
    ASSERT_NE(cert, nullptr);
    X509_set_version(cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 7);
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 31536000L);
    X509_set_pubkey(cert, pkey);

    X509_NAME* name = X509_NAME_new();
    ASSERT_NE(name, nullptr);
    X509_NAME_add_entry_by_NID(name, NID_commonName, MBSTRING_ASC, (unsigned char*)"Corrupt Cert", -1, -1, 0);
    X509_set_subject_name(cert, name);
    X509_set_issuer_name(cert, name);
    X509_NAME_free(name);

    ASSERT_GT(X509_sign(cert, pkey, EVP_sha256()), 0);

    p12 = PKCS12_create(password,
                        "pkitool test corrupt",
                        pkey,
                        cert,
                        NULL,
                        NID_pbe_WithSHA1And3_Key_TripleDES_CBC,
                        0,
                        PKCS12_DEFAULT_ITER,
                        PKCS12_DEFAULT_ITER,
                        0);
    ASSERT_NE(p12, nullptr);

    bio = BIO_new_file(filename, "wb");
    ASSERT_NE(bio, nullptr);
    ASSERT_GT(i2d_PKCS12_bio(bio, p12), 0);
    BIO_free(bio);
    PKCS12_free(p12);

    // Corrupt the file by truncating it
    FILE* f = fopen(filename, "r+b");
    ASSERT_NE(f, nullptr);
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    long cut = (len > 10) ? (len - 10) : 0;
    ASSERT_EQ(0, ftruncate(fileno(f), cut));
    fclose(f);

    CCertificate certObj;
    std::string pwd(password);
    int r = certObj.ReadPfx(std::string(filename), pwd);
    EXPECT_NE(r, 1);

    // cleanup
    if (pkey)
        EVP_PKEY_free(pkey);
    if (cert)
        X509_free(cert);
    remove(filename);
}

TEST_F(OpenSSLFixture, ReadPfxParallel_MixedRSA_ECDSA)
{
    const char* password = "testpass";
    const int threads    = 8;
    std::vector<int> results(threads, 0);
    std::vector<std::thread> ths;

    auto worker = [&](int idx) {
        EVP_PKEY* pkey = nullptr;
        X509* cert     = nullptr;
        PKCS12* p12    = nullptr;
        BIO* bio       = nullptr;
        char filename[64];
        std::snprintf(filename, sizeof(filename), "test_output_mix_%d.pfx", idx);

        if (idx % 2 == 0)
        {
            // RSA
            printf("Testing with RSA key, output file = %s\n", filename);
            EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
            if (!pctx)
            {
                results[idx] = 0;
                return;
            }
            if (!(EVP_PKEY_keygen_init(pctx) > 0))
            {
                EVP_PKEY_CTX_free(pctx);
                results[idx] = 0;
                return;
            }
            if (!(EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048) > 0))
            {
                EVP_PKEY_CTX_free(pctx);
                results[idx] = 0;
                return;
            }
            if (!(EVP_PKEY_keygen(pctx, &pkey) > 0))
            {
                EVP_PKEY_CTX_free(pctx);
                results[idx] = 0;
                return;
            }
            EVP_PKEY_CTX_free(pctx);
        }
        else
        {
            // ECDSA P-256
            printf("Testing with ECDSA key, output file = %s\n", filename);
            EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
            if (!pctx)
            {
                results[idx] = 0;
                return;
            }
            if (!(EVP_PKEY_keygen_init(pctx) > 0))
            {
                EVP_PKEY_CTX_free(pctx);
                results[idx] = 0;
                return;
            }
            if (!(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) > 0))
            {
                EVP_PKEY_CTX_free(pctx);
                results[idx] = 0;
                return;
            }
            if (!(EVP_PKEY_keygen(pctx, &pkey) > 0))
            {
                EVP_PKEY_CTX_free(pctx);
                results[idx] = 0;
                return;
            }
            EVP_PKEY_CTX_free(pctx);
        }

        // Create self-signed cert
        cert = X509_new();
        if (!cert)
        {
            if (pkey)
                EVP_PKEY_free(pkey);
            results[idx] = 0;
            return;
        }
        X509_set_version(cert, 2);
        ASN1_INTEGER_set(X509_get_serialNumber(cert), idx + 100);
        X509_gmtime_adj(X509_get_notBefore(cert), 0);
        X509_gmtime_adj(X509_get_notAfter(cert), 31536000L);
        X509_set_pubkey(cert, pkey);

        X509_NAME* name = X509_NAME_new();
        if (!name)
        {
            X509_free(cert);
            if (pkey)
                EVP_PKEY_free(pkey);
            results[idx] = 0;
            return;
        }
        X509_NAME_add_entry_by_NID(name, NID_commonName, MBSTRING_ASC, (unsigned char*)"Mixed Test Cert", -1, -1, 0);
        X509_set_subject_name(cert, name);
        X509_set_issuer_name(cert, name);
        X509_NAME_free(name);

        if (!(X509_sign(cert, pkey, EVP_sha256()) > 0))
        {
            X509_free(cert);
            if (pkey)
                EVP_PKEY_free(pkey);
            results[idx] = 0;
            return;
        }

        p12 = PKCS12_create(password,
                            "pkitool mix test",
                            pkey,
                            cert,
                            NULL,
                            NID_pbe_WithSHA1And3_Key_TripleDES_CBC,
                            0,
                            PKCS12_DEFAULT_ITER,
                            PKCS12_DEFAULT_ITER,
                            0);
        if (!p12)
        {
            X509_free(cert);
            if (pkey)
                EVP_PKEY_free(pkey);
            results[idx] = 0;
            return;
        }

        bio = BIO_new_file(filename, "wb");
        if (!bio)
        {
            PKCS12_free(p12);
            X509_free(cert);
            if (pkey)
                EVP_PKEY_free(pkey);
            results[idx] = 0;
            return;
        }
        if (!(i2d_PKCS12_bio(bio, p12) > 0))
        {
            BIO_free(bio);
            PKCS12_free(p12);
            X509_free(cert);
            if (pkey)
                EVP_PKEY_free(pkey);
            results[idx] = 0;
            return;
        }
        BIO_free(bio);
        PKCS12_free(p12);

        CCertificate certObj;
        std::string pwd(password);
        int r = certObj.ReadPfx(std::string(filename), pwd);
        if (r != 1)
        {
            if (cert)
                X509_free(cert);
            if (pkey)
                EVP_PKEY_free(pkey);
            remove(filename);
            results[idx] = 0;
            return;
        }
        if (!certObj.HasKey() || certObj.CertX509() == nullptr)
        {
            if (cert)
                X509_free(cert);
            if (pkey)
                EVP_PKEY_free(pkey);
            remove(filename);
            results[idx] = 0;
            return;
        }

        // cleanup
        if (pkey)
            EVP_PKEY_free(pkey);
        if (cert)
            X509_free(cert);
        printf("Removing %s\n", filename);
        remove(filename);
        results[idx] = 1;
    };

    for (int i = 0; i < threads; ++i)
        ths.emplace_back(worker, i);

    for (auto& t : ths)
        t.join();

    for (int i = 0; i < threads; ++i)
        EXPECT_EQ(results[i], 1);
}

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
