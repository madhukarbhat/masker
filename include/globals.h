#ifndef GLOBALS_HEADER_INCLUDED__
#define GLOBALS_HEADER_INCLUDED__

#define MASKER_BLOCK_SIZE          0x50
#define MASKER_PBKDF_ITERATIONS 1000000
#define MASKER_CODED_FILE_EXTN   ".enc"

#include <iostream>
#include <string>

std::string remove_extn(std::string inFname);
void print_usage (std::string inProgName);

#endif /*GLOBALS_HEADER_INCLUDED__*/
