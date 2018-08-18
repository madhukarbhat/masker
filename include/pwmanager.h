#ifndef PWMANAGER_HEADER_INCLUDED__
#define PWMANAGER_HEADER_INCLUDED__

#include "globals.h"

#include <termios.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>

#include <iostream>
#include <string>

#include "cryptopp/secblock.h"
using CryptoPP::SecByteBlock;

#include "cryptopp/algparam.h"
using CryptoPP::ConstByteArrayParameter;

#include "cryptopp/pwdbased.h"
using CryptoPP::PKCS5_PBKDF2_HMAC;

#include "cryptopp/sha.h"
using CryptoPP::SHA256;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "cryptopp/filters.h"
using CryptoPP::ArraySink;
using CryptoPP::Redirector;
using CryptoPP::StringSource;
using CryptoPP::StringSink;

#include "cryptopp/hex.h"
using CryptoPP::HexEncoder;

#include <cryptopp/files.h>
using CryptoPP::FileSource;

#include "cryptopp/aes.h"
using CryptoPP::AES;


class PwManager {

public:
  std::string getPass(const char *prompt, bool show_asterisk=true);
  void generateKey ();
  void extractKey (std::string inFileName);
  SecByteBlock getKey();
  SecByteBlock getIv();
  SecByteBlock getSalt();

protected:
  int getch();
  void prettyPrint();

private:
  SecByteBlock password;
  SecByteBlock key;
  SecByteBlock iv;
  SecByteBlock salt;
};

#endif /*PWMANAGER_HEADER_INCLUDED__*/
