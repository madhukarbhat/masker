#include "encode.h"


// ------------------------------------------------------------------------

int Encode::execute() {
  std::string outFileName  = fileName + ".enc";
  std::string outCredName  = fileName + ".bin";

  std::cout << "[Encode]: Executing ... " << std::endl;  
  try {
    GCM< AES >::Encryption enc;
    enc.SetKeyWithIV(key, key.size(), iv, iv.size());

    FileSink outFile(outFileName.c_str());
    FileSink outCred(outCredName.c_str());
    
    // Source wrappers
    ArraySource asIV(iv, iv.size(), true, new Redirector(outCred));
    ArraySource asSalt(salt, salt.size(), true, new Redirector(outCred));

    FileSource inFile(fileName.c_str(), true,
		      new AuthenticatedEncryptionFilter (enc,
							 new Redirector(outFile),
							 false,
							 TAG_SIZE
							 ));
  }  catch(const CryptoPP::Exception& ex) {
    std::cerr << ex.what() << std::endl;
    exit(EXIT_FAILURE);
  }

  return EXIT_SUCCESS;
}

// ------------------------------------------------------------------------

void Encode::prettyPrint () {
  std::string prettyPrint;
  std::cout << "[Encode] Blocksize: " << AES::BLOCKSIZE << std::endl;

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
