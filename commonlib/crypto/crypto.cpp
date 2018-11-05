//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "crypto.h"
#include "pack.h"

#include <stdio.h>

#include "commonlib/argumentexception.h"
#include "commonlib/ioexception.h"
#include "commonlib/outofmemoryexception.h"

#include "commonlib/filemmapw32.h"

namespace commonlib {
namespace crypto {

typedef ltc_prng_descriptor             prng_descriptor;
typedef ltc_hash_descriptor             hash_descriptor;

typedef commonlib::mmap::FileMMapW32    FileMMapW32;

using commonlib::sguard::scope_guard;
using commonlib::sguard::make_guard_chk;
using commonlib::sguard::is_null_non_equal;
using commonlib::sguard::is_null_equal;

#define ERROR_NS_PREFIX L"commonlib::crypto::"

key& importKey (const unsigned char *buffer, const unsigned long bufferLen, key& key, size_t& keyLength)
{
  if (CRYPT_OK != rsa_import (buffer, bufferLen, &key))
    throw CryptoException (ERROR_NS_PREFIX L"importKey (from buffer): error rsa_import");
  //
  // import key from buffer end
  //  
  
  keyLength = mp_count_bits (&key.N) / 8;
  
  return key;
}

key& importKey (const wstring& fileName, key& key, size_t& keyLength)
{
  keyLength = 0;
  
  //
  // import key from file
  //  
  FILE*   file = ::_wfopen (fileName.c_str (), L"rb");
  scope_guard file_guard = make_guard_chk (file, &::fclose, is_null_equal<FILE*, NULL> ());
  if (true == file_guard.is_free ())
    throw IOException (ERROR_NS_PREFIX L"importKey (from file): error open key file");
  
  fseek (file, 0, SEEK_END);
  size_t key_length = ftell (file);
  fseek (file, 0, SEEK_SET);
  
  PtrToUCharArray buffer (new unsigned char [key_length]);
  if (NULL == buffer.get ())
    throw OutOfMemoryException (ERROR_NS_PREFIX L"importKey (from file): no memory for key");
    
  if (0 >= fread (buffer.get (), sizeof (unsigned char), key_length, file))
    throw IOException (ERROR_NS_PREFIX L"importKey (from file): error read key file");
    
  file_guard.free ();  
  
  unsigned long bufLen = static_cast <unsigned long> (key_length);
  return importKey (buffer.get (), bufLen, key, keyLength);
} // importKey

void exportKey (const wstring& fileName, key& key, key_type type)
{
  int pk_type = PK_PRIVATE;
  
  if (public_key == type)
    pk_type = PK_PUBLIC;
    
  unsigned long   bufLen = 256;
  PtrToUCharArray buffer;
  int             res;
  
  do
  {
    buffer = PtrToUCharArray (new unsigned char [bufLen]);
    if (NULL == buffer.get ())
      throw OutOfMemoryException (ERROR_NS_PREFIX L"doKeys (): no memory for export key");
  
    unsigned long len = bufLen;
    res = rsa_export (buffer.get (), &len, pk_type, &key);
    if (CRYPT_BUFFER_OVERFLOW == res)
      bufLen = bufLen * 2;
    else
      bufLen = len;
  }
  while (CRYPT_BUFFER_OVERFLOW == res);
  
  if (CRYPT_OK != res)
    throw CryptoException (ERROR_NS_PREFIX L"exportKey (): error rsa_export key");
    
  FILE*   file = ::_wfopen (fileName.c_str (), L"wb");
  scope_guard file_guard = make_guard_chk (file, &::fclose, is_null_equal<FILE*, NULL> ());
  if (true == file_guard.is_free ())
    throw IOException (ERROR_NS_PREFIX L"exportKey (to file): error open key file");
      
  if (bufLen != fwrite (buffer.get (), sizeof (unsigned char), bufLen, file))
    throw IOException (ERROR_NS_PREFIX L"exportKey (to file): error write key file");
} // exportKey

key& makeKey (size_t keyLength, key& key)
{
  int        prng_idx = -1;
  int        hash_idx = -1;
  
  if (-1 == (prng_idx = register_prng (&sprng_desc)))
    throw CryptoException (ERROR_NS_PREFIX L"makeKey (): error register_prng"); //return result;
    
  scope_guard hprng = make_guard_chk (&sprng_desc, &::unregister_prng, is_null_equal<const prng_descriptor*, NULL> ());
    
  if (-1 == (hash_idx = register_hash (&sha1_desc)))
    throw CryptoException (ERROR_NS_PREFIX L"makeKey (): error register_hash"); //return result;
    
  scope_guard hhash = make_guard_chk (&sha1_desc, &::unregister_hash, is_null_equal<const hash_descriptor*, NULL> ());
    
  prng_state sprng_prng;
  
  if (CRYPT_OK != rsa_make_key (&sprng_prng, prng_idx, static_cast <int> (keyLength)/8, 65537, &key))
    throw CryptoException (ERROR_NS_PREFIX L"makeKey (): error rsa_make_key"); //return result;
  
  //key_handle hkey (&key, rsa_free);
  
  if (keyLength != mp_count_bits (&key.N))
  {
    freeKey (key);
    throw CryptoException (ERROR_NS_PREFIX L"makeKey (): generate key size is not equal that required"); //return result;
  }  
    
  return key;  
} // makeKey

void freeKey (key& key)
{
  rsa_free (&key);
} // freeKey

void verifyData (const wstring& dataFile, const wstring& resultFile, key& key, bool usePack, bool useDir)
{
  if (0 >= dataFile.size ())
    throw ArgumentException (ERROR_NS_PREFIX L"verifyData (): bad data file");
    
  if (0 >= resultFile.size ())
    throw ArgumentException (ERROR_NS_PREFIX L"verifyData (): bad result file");
    
  size_t key_length = mp_count_bits (&key.N) / 8;
  if (0 >= key_length)
    throw ArgumentException (ERROR_NS_PREFIX L"verifyData (): bad key length");
    
  //
  // register some params
  //  
  int        prng_idx = -1;
  int        hash_idx = -1;
  
  if (-1 == (prng_idx = register_prng (&sprng_desc)))
    throw CryptoException (ERROR_NS_PREFIX L"verifyData (): error register_prng"); //return result;
    
  scope_guard hprng = make_guard_chk (&sprng_desc, &::unregister_prng, is_null_equal<const prng_descriptor*, NULL> ());
    
  if (-1 == (hash_idx = register_hash (&sha1_desc)))
    throw CryptoException (ERROR_NS_PREFIX L"verifyData (): error register_hash"); //return result;
    
  scope_guard hhash = make_guard_chk (&sha1_desc, &::unregister_hash, is_null_equal<const hash_descriptor*, NULL> ());

  //
  // register some params end
  //  
  
  FileMMapW32    mapData (dataFile, GENERIC_READ, FILE_SHARE_READ);
  unsigned char* view = reinterpret_cast <unsigned char*> (mapData.map ());
  
  if (NULL == view || mapData.viewSize () <= key_length)
    throw IOException (ERROR_NS_PREFIX L"verifyData (): error mapping data file into memory or bad content data file"); //return result;
    
  int        stat;
  if (CRYPT_OK != rsa_verify_hash (view + (mapData.viewSize () - key_length), static_cast <unsigned long> (key_length), view, static_cast <unsigned long> (mapData.viewSize () - key_length), hash_idx, 0, &stat, &key))
    throw CryptoException (ERROR_NS_PREFIX L"verifyData (): error rsa_verify_hash"); //return result;
   
  if (1 != stat) // stat = 1 if hash verify is OK
    throw CryptoException (ERROR_NS_PREFIX L"verifyData (): error verify signing data (bad sign)"); //return result;

  if (false == usePack)
  {
    FILE* result_file = ::_wfopen (resultFile.c_str (), L"wb");
    scope_guard result_file_guard = make_guard_chk (result_file, &::fclose, is_null_equal <FILE*, NULL> ());
    if (true == result_file_guard.is_free ())
      throw IOException (ERROR_NS_PREFIX L"verifyData (): error open result file"); //return result;
    
    if ((mapData.viewSize () - key_length) != fwrite (view, sizeof (unsigned char), mapData.viewSize () - key_length, result_file))
      throw IOException (ERROR_NS_PREFIX L"verifyData (): error write result file (data)");
      
    result_file_guard.free ();  
  }
  else
  {
    wstring packFileName = (resultFile + wstring (L".unpack"));
    FILE*   pack_file    = ::_wfopen (packFileName.c_str (), L"wb");
    scope_guard pack_file_guard = make_guard_chk (pack_file, &::fclose, is_null_equal <FILE*, NULL> ());
    if (true == pack_file_guard.is_free ())
      throw IOException (ERROR_NS_PREFIX L"verifyData (): error open unpack file"); //return result;
    
    if ((mapData.viewSize () - key_length) != fwrite (view, sizeof (unsigned char), mapData.viewSize () - key_length, pack_file))
      throw IOException (ERROR_NS_PREFIX L"verifyData (): error write unpack file (data)");
      
    pack_file_guard.free ();  
    
    try
    {
      if (true == useDir)
      {
        inflate (packFileName, resultFile);
      }  
      else
      {
        FILE*       src_file = ::_wfopen (packFileName.c_str (), L"rb");
        scope_guard src_file_guard = make_guard_chk (src_file, &::fclose, is_null_equal <FILE*, NULL> ());
        FILE*       dst_file = ::_wfopen (resultFile.c_str (), L"wb");
        scope_guard dst_file_guard = make_guard_chk (dst_file, &::fclose, is_null_equal <FILE*, NULL> ());
        
        inflate (src_file, dst_file);
      }  
    }  
    catch (Exception& e)
    {
      _wunlink (packFileName.c_str ());
      _wunlink (resultFile.c_str ());
      throw e;
    }
    
    _wunlink (packFileName.c_str ());
  }  
} // verifyData

void signingData (const wstring& dataFile, const wstring& resultFile, key& key, bool usePack, bool useDir)
{
  if (0 >= dataFile.size ())
    throw ArgumentException (ERROR_NS_PREFIX L"signingData (): bad data file");
    
  if (0 >= resultFile.size ())
    throw ArgumentException (ERROR_NS_PREFIX L"signingData (): bad result file");
    
  size_t key_length = mp_count_bits (&key.N) / 8;
  if (0 >= key_length)
    throw ArgumentException (ERROR_NS_PREFIX L"signingData (): bad key length");  

  //
  // register some params
  //  
  int        prng_idx = -1;
  int        hash_idx = -1;
  
  if (-1 == (prng_idx = register_prng (&sprng_desc)))
    throw CryptoException (ERROR_NS_PREFIX L"doSigning (): error register_prng"); //return result;
    
  scope_guard hprng = make_guard_chk (&sprng_desc, &::unregister_prng, is_null_equal<const prng_descriptor*, NULL> ());
    
  if (-1 == (hash_idx = register_hash (&sha1_desc)))
    throw CryptoException (ERROR_NS_PREFIX L"doSigning (): error register_hash"); //return result;
    
  scope_guard hhash = make_guard_chk (&sha1_desc, &::unregister_hash, is_null_equal<const hash_descriptor*, NULL> ());

  //
  // register some params end
  //  
  
  wstring _dataFile = dataFile;
  
  if (true == usePack)
  {
    if (false == useDir)
    {
      _dataFile = (dataFile + wstring (L".pack"));
      FILE*       src_file = ::_wfopen (dataFile.c_str (), L"rb");
      scope_guard src_file_guard = make_guard_chk (src_file, &::fclose, is_null_equal <FILE*, NULL> ());
      FILE*       dst_file = ::_wfopen (_dataFile.c_str (), L"wb");
      scope_guard dst_file_guard = make_guard_chk (dst_file, &::fclose, is_null_equal <FILE*, NULL> ());
    
      deflate (src_file, dst_file, pack_default);
    }
    else
    {
      _dataFile = (resultFile + wstring (L".pack"));
      deflate (dataFile, _dataFile, pack_default);
    }
  } // if (true == usePack)
  
  FileMMapW32    mapData (_dataFile, GENERIC_READ, FILE_SHARE_READ);
  unsigned char* view = reinterpret_cast <unsigned char*> (mapData.map ());
  
  if (NULL == view)
    throw IOException (ERROR_NS_PREFIX L"signingData (): error mapping data file into memory");
    
  unsigned long bufLen = static_cast <unsigned long> (key_length);
  PtrToUCharArray buffer = PtrToUCharArray (new unsigned char [bufLen]);
  if (NULL == buffer.get ())
    throw OutOfMemoryException (ERROR_NS_PREFIX L"signingData (): no memory for sign");
  
  prng_state sprng_prng;
  if (CRYPT_OK != rsa_sign_hash (view, static_cast <unsigned long> (mapData.viewSize ()), buffer.get (), &bufLen, &sprng_prng, prng_idx, hash_idx, 0, &key))
    throw CryptoException (ERROR_NS_PREFIX L"signingData (): error rsa_sign_hash");
  
  FILE*   result_file = ::_wfopen (resultFile.c_str (), L"wb");
  scope_guard result_file_guard = make_guard_chk (result_file, &::fclose, is_null_equal <FILE*, NULL> ());
  if (true == result_file_guard.is_free ())
    throw IOException (ERROR_NS_PREFIX L"signingData (): error open result file");
    
  if (mapData.viewSize () != fwrite (view, sizeof (unsigned char), mapData.viewSize (), result_file))
    throw IOException (ERROR_NS_PREFIX L"signingData (): error write result file (data)");
  if (bufLen != fwrite (buffer.get (), sizeof (unsigned char), bufLen, result_file))
    throw IOException (ERROR_NS_PREFIX L"signingData (): error write result file (sign)");
  
  result_file_guard.free ();
  mapData.close ();
  
  if (true == usePack)
    _wunlink (_dataFile.c_str ());
} // signingData

PtrToUCharArray getHash (const unsigned char* buffer, size_t buffer_size, key& key, size_t& hash_size)
{
  if (NULL == buffer)
    throw ArgumentException (ERROR_NS_PREFIX L"buffer is NULL");
    
  if (0 >= buffer_size)
    throw ArgumentException (ERROR_NS_PREFIX L"buffer is 0");
    
  size_t key_length = mp_count_bits (&key.N) / 8;
  if (0 >= key_length)
    throw ArgumentException (ERROR_NS_PREFIX L"verifyData (): bad key length");
    
  //
  // register some params
  //  
  int        prng_idx = -1;
  int        hash_idx = -1;
  
  if (-1 == (prng_idx = register_prng (&sprng_desc)))
    throw CryptoException (ERROR_NS_PREFIX L"verifyData (): error register_prng"); //return result;
    
  scope_guard hprng = make_guard_chk (&sprng_desc, &::unregister_prng, is_null_equal<const prng_descriptor*, NULL> ());
    
  if (-1 == (hash_idx = register_hash (&sha1_desc)))
    throw CryptoException (ERROR_NS_PREFIX L"verifyData (): error register_hash"); //return result;
    
  scope_guard hhash = make_guard_chk (&sha1_desc, &::unregister_hash, is_null_equal<const hash_descriptor*, NULL> ());

  //
  // register some params end
  //  
  
  unsigned long   _hash_size = static_cast <unsigned long> (key_length);
  PtrToUCharArray hash      = PtrToUCharArray (new unsigned char [_hash_size]);
  if (NULL == hash.get ())
    throw OutOfMemoryException (ERROR_NS_PREFIX L"getHash (): no memory for sign");
  
  prng_state sprng_prng;
  if (CRYPT_OK != rsa_sign_hash (buffer, static_cast <unsigned long> (buffer_size), hash.get (), &_hash_size, &sprng_prng, prng_idx, hash_idx, 0, &key))
    throw CryptoException (ERROR_NS_PREFIX L"getHash (): error rsa_sign_hash");

  hash_size = _hash_size;
  return hash;
} // getHash

void verifyHash (const unsigned char* buffer, size_t buffer_size, const unsigned char* hash, size_t hash_size, key& key)
{
  if (NULL == buffer)
    throw ArgumentException (ERROR_NS_PREFIX L"buffer is NULL");
    
  if (0 >= buffer_size)
    throw ArgumentException (ERROR_NS_PREFIX L"buffer is 0");
    
  if (NULL == hash)
    throw ArgumentException (ERROR_NS_PREFIX L"hash is NULL");
    
  if (0 >= hash_size)
    throw ArgumentException (ERROR_NS_PREFIX L"hash is 0");  
    
  size_t key_length = mp_count_bits (&key.N) / 8;
  if (0 >= key_length)
    throw ArgumentException (ERROR_NS_PREFIX L"verifyData (): bad key length");
    
  //
  // register some params
  //  
  int        prng_idx = -1;
  int        hash_idx = -1;
  
  if (-1 == (prng_idx = register_prng (&sprng_desc)))
    throw CryptoException (ERROR_NS_PREFIX L"verifyData (): error register_prng"); //return result;
    
  scope_guard hprng = make_guard_chk (&sprng_desc, &::unregister_prng, is_null_equal<const prng_descriptor*, NULL> ());
    
  if (-1 == (hash_idx = register_hash (&sha1_desc)))
    throw CryptoException (ERROR_NS_PREFIX L"verifyData (): error register_hash"); //return result;
    
  scope_guard hhash = make_guard_chk (&sha1_desc, &::unregister_hash, is_null_equal<const hash_descriptor*, NULL> ());

  //
  // register some params end
  //  
  
  int        stat;
  if (CRYPT_OK != rsa_verify_hash (hash, static_cast <unsigned long> (hash_size), buffer, static_cast <unsigned long> (buffer_size), hash_idx, 0, &stat, &key))
    throw CryptoException (ERROR_NS_PREFIX L"verifyHash (): error rsa_verify_hash"); //return result;
    
  if (1 != stat) // stat = 1 if hash verify is OK
    throw CryptoException (ERROR_NS_PREFIX L"verifyHash (): error verify signing data (bad sign)");
} // verifyHash

} // namespace crypto {
} // namespace commonlib {
