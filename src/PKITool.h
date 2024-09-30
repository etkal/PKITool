//
//  This version created by Erik Tkal on 2018.02.05.
//  Copyright (c) 2018-2024 Erik Tkal. All rights reserved.
//
#pragma once

#include "COpenSSL.h"
#include "CCertificate.h"
#include "CCertOperation.h"

inline int fopen_s(FILE** fp, const char* file, const char* mode)
{
    if (!fp)
    {
        return 0;
    }
    *fp = fopen(file, mode);
    return (*fp == 0);
}
