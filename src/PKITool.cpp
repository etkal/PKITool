//
// PKITool.cpp : Defines the entry point for the console application.
//
//  PKITool
//
//  This version created by Erik Tkal on 2020.02.12.
//  Copyright (c) 2018-2022 Erik Tkal. All rights reserved.
//
//  Built with OpenSSL 1.1.1n
//  See buildOpenSSL script (places in ~/ssl and ~/ssl-debug)
//
//  ./Configure no-shared darwin64-x86_64-cc -mmacosx-version-min=10.12
//  ./Configure no-shared enable-crypto-mdebug enable-crypto-mdebug-backtrace darwin64-x86_64-cc -mmacosx-version-min=10.12
//
//  ./Configure no-shared darwin64-x86_64-cc -mmacosx-version-min=10.12 --prefix=`pwd`/out-x86_64 -openssldir=`pwd`/out-x86_64
//  make all
//  make install
//  make clean
//  ./Configure no-shared darwin64-arm64-cc -mmacosx-version-min=10.12 --prefix=`pwd`/out-arm64 -openssldir=`pwd`/out-arm64
//  make all
//  make install
//  make clean
//

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "PKITool.h"

int main(int argc, const char * argv[])
{
    COpenSSL oOpenSSL;

    CCertOperation oOp;
    if ( oOp.ReadParameters(argc, argv) <= 0 )
        return 1;
    if ( oOp.LoadConf() <= 0 )
        return 1;
    if ( oOp.Execute() <= 0 )
        return 1;

	return 0;
}

