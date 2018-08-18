#include "pwmanager.h"

// ------------------------------------------------------------------------

int PwManager::getch() {
    int ch;
    struct termios t_old, t_new;

    tcgetattr(STDIN_FILENO, &t_old);
    t_new = t_old;
    t_new.c_lflag &= ~(ICANON | ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &t_new);

    ch = getchar();

    tcsetattr(STDIN_FILENO, TCSANOW, &t_old);
    return ch;
}

// ------------------------------------------------------------------------

std::string PwManager::getPass(const char* prompt, bool show_asterisk) {
  const char BACKSPACE=0x7f; // ASCII 127
  const char RETURN=0xa;     // ASCII  10

  unsigned char ch=0;
  std::string user_input;

  std::cout << prompt << std::endl;

  while((ch = getch())!= RETURN) {
    if(ch == BACKSPACE) {
      if(user_input.length()!= 0) {
	if(show_asterisk)
	  std::cout << "\b \b";
	user_input.resize( user_input.length() - 1);
      }
    } else {
      user_input += ch;
      if (show_asterisk)
	std::cout <<'*';
    }
  }
  std::cout << std::endl;
  SecByteBlock pwd(
		   reinterpret_cast<const unsigned char*>(user_input.data()),
		   user_input.size()
		   );
  this->password = pwd;
  return user_input;
}

// ------------------------------------------------------------------------

void PwManager::generateKey () {
  AutoSeededRandomPool prng;

  this->iv.resize(AES::BLOCKSIZE);
  prng.GenerateBlock(this->iv, this->iv.size());

  this->salt.resize(AES::BLOCKSIZE);
  prng.GenerateBlock(this->salt, this->salt.size());

  PKCS5_PBKDF2_HMAC< SHA256 > kdf;
  this->key.resize(AES::DEFAULT_KEYLENGTH);
  kdf.DeriveKey(key.data(), key.size(), 0,
		this->salt.data(), this->salt.size(),
		this->password, this->password.size(),
		MASKER_PBKDF_ITERATIONS);

  std::cout << "Encoding ... " << std::endl;
}

// ------------------------------------------------------------------------

void PwManager::extractKey (std::string inFileName) {
  FileSource fs(inFileName.c_str(), false);

  // Attach new filter for IV
  this->iv.resize(AES::BLOCKSIZE);
  ArraySink asIV(iv, iv.size());
  fs.Attach(new Redirector(asIV));
  fs.Pump(AES::BLOCKSIZE);  // Pump first 16 bytes

  // Attach new filter for Salt
  this->salt.resize(AES::BLOCKSIZE);
  ArraySink asSalt(salt, salt.size());
  fs.Attach(new Redirector(asSalt));
  fs.Pump(AES::BLOCKSIZE);  // Pump next 16 bytes
  
  PKCS5_PBKDF2_HMAC< SHA256 > kdf;
  this->key.resize(AES::DEFAULT_KEYLENGTH);
  kdf.DeriveKey(key.data(), key.size(), 0,
		this->salt.data(), this->salt.size(),
		this->password, this->password.size(),
		MASKER_PBKDF_ITERATIONS);

  std::cout << "Decoding ... " << std::endl;
}

// ------------------------------------------------------------------------

void PwManager::prettyPrint () {
  std::string prettyPrint;
  std::cout << "[pwmanager] Blocksize: " << AES::BLOCKSIZE << std::endl;

  // Pretty print IV
  prettyPrint.clear();
  StringSource(iv, iv.size(), true,
	       new HexEncoder(
			      new StringSink(prettyPrint)
			      ) // HexEncoder
	       ); // StringSource
  std::cout << "IV: " << prettyPrint << std::endl;

  // Pretty print salt
  prettyPrint.clear();
  StringSource(salt, salt.size(), true,
	       new HexEncoder(
			      new StringSink(prettyPrint)
			      ) // HexEncoder
	       ); // StringSource
  std::cout << "Salt: " << prettyPrint << std::endl;

  // Pretty print key
  prettyPrint.clear();
  StringSource(key, key.size(), true,
	       new HexEncoder(
			      new StringSink(prettyPrint)
			      ) // HexEncoder
	       ); // StringSource
  std::cout << "key: " << prettyPrint << std::endl;
}

// ------------------------------------------------------------------------

SecByteBlock PwManager::getKey() {
  return this->key;
}
// ------------------------------------------------------------------------

SecByteBlock PwManager::getIv() {
  return this->iv;
}
// ------------------------------------------------------------------------

SecByteBlock PwManager::getSalt() {
  return this->salt;
}
// ------------------------------------------------------------------------
