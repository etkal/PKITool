#include "COpenSSL.h"
#include "CCertificate.h"

#include <gtest/gtest.h>

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pkcs12.h>
#include <openssl/bio.h>

#include <cstdio>
#include <string>

using namespace std;

class OpenSSLFixture : public ::testing::Test {
protected:
    void SetUp() override { new COpenSSL(); }
};

TEST_F(OpenSSLFixture, ReadPfxSucceeds)
{
    EVP_PKEY* pkey = nullptr;
    X509* cert = nullptr;
    PKCS12* p12 = nullptr;
    BIO* bio = nullptr;
    const char* password = "testpass";
    const char* filename = "test_output.pfx";

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

    p12 = PKCS12_create(password, "pkitool test", pkey, cert, NULL,
                        NID_pbe_WithSHA1And3_Key_TripleDES_CBC, 0,
                        PKCS12_DEFAULT_ITER, PKCS12_DEFAULT_ITER, 0);
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
    remove(filename);
}

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
