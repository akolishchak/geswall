//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _commonlib_crypto_pack_h_
 #define _commonlib_crypto_pack_h_

#include <stdio.h>
#include <string>

#include <zlib.h>

namespace commonlib {
namespace crypto {

typedef std::wstring                    wstring;

enum pack_level
{
  pack_default = Z_DEFAULT_COMPRESSION
};

void deflate (const wstring& source_file_mask, const wstring& dest_file_name, pack_level level);
void inflate (const wstring& source_file_name, const wstring& dest_dir_name);

void deflate (FILE* source, FILE* dest, pack_level level);
void inflate (FILE* source, FILE* dest, size_t size = -1);

} // namespace crypto {
} // namespace commonlib {

#endif // _commonlib_crypto_crypto_h_