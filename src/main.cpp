#include "main.h"

// ------------------------------------------------------------------------

int main (int argc, char* argv[]) {
  std::string inProgName = argv[0];
  if (argc != 3) {
    std::cerr << "[Error] Unexpected number of command-line parameters."
	      << std::endl << std::endl;
    print_usage(inProgName);
    return EXIT_FAILURE;
  }
  std::string option     = argv[1];
  std::string inFileName = argv[2];
  PwManager pwm;

  std::string password = pwm.getPass("Enter password: ");
  if (option == "en") {
    pwm.generateKey();
    Encode ec(pwm.getKey(), pwm.getIv(), pwm.getSalt(), inFileName);
    ec.execute();
  } else {
    if (option == "de") {
      // Validate that the encrypted file name ends with
      // '.enc'. Expected values:
      //
      //   std::string inFileName = "data/data.txt.enc";
      //   std::string inCredName = "data/data.txt.bin";
      const std::string encExtn = MASKER_CODED_FILE_EXTN;
      if ( inFileName != encExtn &&
	   inFileName.size() > encExtn.size() &&
	   inFileName.substr(inFileName.size() - encExtn.size()) == encExtn ) {

	std::string inCredName = remove_extn(inFileName) + ".bin";
	pwm.extractKey(inCredName);
	Decode dec(pwm.getKey(), pwm.getIv(), pwm.getSalt(), inFileName);
	dec.execute();
      } else {
	std::cerr << "[Error] Unexpected filename extension."
		  << std::endl << std::endl;
	 print_usage(inProgName);
	return EXIT_FAILURE;
      }
    } else {
      std::cerr << "[Error] Unexpected execution mode."
		<< std::endl << std::endl ;
      print_usage(inProgName);
      return EXIT_FAILURE;
    }
  }
  
  return EXIT_SUCCESS;
}

// ------------------------------------------------------------------------
