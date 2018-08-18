#include "decode.h"

// ------------------------------------------------------------------------

int Decode::execute() {
  std::string outFileName  = remove_extn(fileName);

  try {
    GCM< AES >::Decryption dec;
    dec.SetKeyWithIV(key, key.size(), iv, iv.size());

    FileSink outFile(outFileName.c_str());
    FileSource inFile(fileName.c_str(), false,
		      new AuthenticatedDecryptionFilter
		      (
		       dec,
		       new Redirector(outFile),
		       AuthenticatedDecryptionFilter::DEFAULT_FLAGS,
		       TAG_SIZE
		       )
		      );
    //inFile.Skip(AES::DEFAULT_BLOCKSIZE * 2 - 1);
    inFile.PumpAll();
  }  catch(const CryptoPP::Exception& ex) {
    std::cerr << ex.what() << std::endl;
    exit(EXIT_FAILURE);
  }

  return EXIT_SUCCESS;
}

// ------------------------------------------------------------------------
