// COpenSSL.cpp
//
//  Copyright (c) 2018-2022 Erik Tkal. All rights reserved.
//

#include "COpenSSL.h"

COpenSSL*    COpenSSL::m_pSingleton = NULL;
unsigned int COpenSSL::m_nUsers = 0;
BIO*         COpenSSL::m_oStdout = NULL;

COpenSSL::COpenSSL()
{
    if ( m_nUsers++ == 0 ) {
        Initialize();
    }
}

COpenSSL::~COpenSSL()
{
    if ( --m_nUsers == 0 ) {
        Terminate();
    }
}

void COpenSSL::Initialize()
{
    printf("\n");
    //printf("InitOpenSSL()...\n\n");

    m_oStdout = NULL;
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
    OpenSSL_add_all_algorithms();
    ERR_load_ERR_strings();
    ERR_load_crypto_strings();
    m_oStdout = BIO_new_fp(stdout, BIO_NOCLOSE);

    int oRand[256];
    srand( ( unsigned )time( NULL ) );
    for ( int i=0; i<256; ++i ) {
        oRand[i] = rand()<<16 | rand();
    }
    RAND_seed((void*)oRand, sizeof(oRand));
}

void COpenSSL::Terminate()
{
    if (0 != ERR_peek_error())
    {
        printf("\n");
        printf("Errors:\n");
        printf("=======\n");
        ERR_print_errors(m_oStdout);
        printf("\n\n");
    }
    if (m_oStdout)
    {
        BIO_free(m_oStdout);
    }

    RAND_cleanup();
    OBJ_cleanup();
    EVP_cleanup(); 
    ERR_clear_error();
    ERR_free_strings();
    CRYPTO_cleanup_all_ex_data();

#if defined(_DEBUG)
    CRYPTO_mem_leaks_fp(stdout);
//    FILE* fp = fopen("MemLeaks.txt", "w");
//    if (fp)
//    {
//        CRYPTO_mem_leaks_fp(fp);
//        fclose(fp);
//    }
#endif
    printf("\n\n");
}


void COpenSSL::PrintError()
{
    char err_msg[256] = "";
    unsigned long err = ERR_get_error();
    ERR_error_string(err, err_msg);
    BIO_printf(m_oStdout, "Error Description:\n%s\n", err_msg);
    BIO_printf(m_oStdout, "\n");
}

