#include "globals.h"

// ------------------------------------------------------------------------

std::string remove_extn (std::string inFname) {
  std::string fname = inFname;
  const std::string extn = MASKER_CODED_FILE_EXTN;
  if ( fname != extn &&
       fname.size() > extn.size() &&
       fname.substr(fname.size() - extn.size()) == extn )
    {
      // if so then strip them off
      fname = fname.substr(0, fname.size() - extn.size());
    }
  return fname;
}

// ------------------------------------------------------------------------

void print_usage (std::string inProgName) {
  std::string usage (inProgName);
  usage += " <en|de> <file name>\n";
  usage += "Where:\n";
  usage += "    <en|de>     : Execution mode, 'en' to encrypt and 'de' to decrypt\n";
  usage += "    <file name> : The file to be processed";
  
  std::cerr << "Usage : " << std::endl
	    << usage      << std::endl;
  return;
}

// ------------------------------------------------------------------------
