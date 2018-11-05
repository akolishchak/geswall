//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _commonlib_crypto_crypto_h_
 #define _commonlib_crypto_crypto_h_

#include <string>
#include <tomcrypt.h>

#include "commonlib/commondefs.h"
#include "cryptoexception.h"

namespace commonlib {
namespace crypto {

typedef std::wstring                    wstring;
typedef ::rsa_key                       key;

enum key_type
{
  private_key,
  public_key
};

key&   importKey (const wstring& fileName, key& key, size_t& keyLength);
key&   importKey (const unsigned char *buffer, const unsigned long bufferLen, key& key, size_t& keyLength);
void   exportKey (const wstring& fileName, key& key, key_type type);

key&   makeKey (size_t keyLength, key& key);
void   freeKey (key& key);

void   verifyData (const wstring& dataFile, const wstring& resultFile, key& key, bool usePack, bool useDir);
void   signingData (const wstring& dataFile, const wstring& resultFile, key& key, bool usePack, bool useDir);

void   verifyHash (const unsigned char* buffer, size_t buffer_size, const unsigned char* hash, size_t hash_size, key& key);
PtrToUCharArray getHash (const unsigned char* buffer, size_t buffer_size, key& key, size_t& hash_size);
} // namespace crypto {
} // namespace commonlib {

#endif // _commonlib_crypto_crypto_h_