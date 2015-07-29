#ifndef TFTOTP_H
#define TFTOTP_H

#include "libs/Base32.h"
#include <string>
#include <iostream>
#include <sstream>
#include <vector>
#include <iomanip>
#include <time.h>

#include <openssl/hmac.h>
#include <openssl/sha.h>

// TOTP will return 6-digits code
#define TFTOTP_DIGITS 6
// TOTP period in seconds
#define TFTOTP_PERIOD 30
// Length for raw seed from /dev/random
#define TFTOTP_SEED_LEN 16
// Length for hash result
#define TFTOTP_SHA_LEN 20
// Length for blocks which used in hashing
#define TFTOTP_SHA_BLOCK 64

// TOTP inner digits char (for XORing)
#define TFTOTP_IN_DIG 0x36
// TOTP outer digits char (for XORing)
#define TFTOTP_OUT_DIG 0x5c

// Base32 alphabet
#define alphabet (unsigned char *)"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

// Define errors
#define TFTOTP_SUCCESS 0


using namespace std;


class TFTOTP
{
public:
    // =======
    // Methods

    // Constructor
    TFTOTP(string token);

    // Destructor
//    ~TFTOTP();

    // Get OTP code
    string generateCode();

    // Generate random token
    static string getRandomToken();

private:
    // ==========
    // Attributes
    string token32;
    unsigned int token32_len;
    vector<unsigned char> token;
    unsigned int token_len;


    // =======
    // Methods

    // HMAC-SHA1
    int hmacSHA1(int date);

    // XOR for vectors
    vector<unsigned char> vxor(vector<unsigned char> a, vector<unsigned char> b);

    // Decode token
    //   result: attribute token will get decoded value of token_raw
    int decodeToken();

    // Encode token
    //   result: attribute token32 will get base32 value of token_raw
    int encodeToken();

    // Vector to string
    string vtos(vector<unsigned char> input);

    // String to vector
    vector<unsigned char> stov(string input);

    // Vector to unsigned char array
    unsigned char *vtoc(vector<unsigned char> input);

    // Unsigned char array to vector
    vector<unsigned char> ctov(unsigned char *input);

    // Debug: output vector in HEX format
    void printHex(string name, vector<unsigned char> input);
};

#endif // TFTOTP_H
