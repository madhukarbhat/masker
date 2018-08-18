#ifndef ENCODE_HEADER_INCLUDED__
#define ENCODE_HEADER_INCLUDED__

#include "globals.h"

#include <cstdlib>
#include <iostream>
#include <string>

#include "pwmanager.h"

#include "cryptopp/secblock.h"
using CryptoPP::SecByteBlock;

#include "cryptopp/filters.h"
using CryptoPP::ArraySource;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::RandomNumberSource;
using CryptoPP::Redirector;

#include <cryptopp/files.h>
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include "cryptopp/aes.h"
using CryptoPP::AES;

#include "cryptopp/gcm.h"
using CryptoPP::GCM;

class Encode {

public:
  Encode (
	  SecByteBlock inKey,
	  SecByteBlock inIV,
	  SecByteBlock inSalt,
	  std::string inFileName
	  ): key(inKey),
	     iv(inIV),
	     salt(inSalt),
	     fileName(inFileName),
             TAG_SIZE(AES::BLOCKSIZE) {
  }

  int execute();

protected:
  void prettyPrint();

private:
  SecByteBlock key;
  SecByteBlock iv;
  SecByteBlock salt;
  std::string  fileName;
  const int TAG_SIZE;
};

#endif /*ENCODE_HEADER_INCLUDED__*/
