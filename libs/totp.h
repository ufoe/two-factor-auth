/*
 * This code is an rewrited version of https://github.com/gonrada/TOTP-Generator
 * Thanks to Sean Easton, which allowed me to use it.
 */

#ifndef TOTP_H
#define TOTP_H

#include "libs/Base32.h"

#include <stdint-gcc.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <cstring>
#include <iostream>
#include <time.h>
#include <sstream>
#include <math.h>


#define TOTP_SEED_LEN 16
#define TOTP_DIGITS 6
#define TOTP_PERIOD 30
#define TOTP_SHA_LEN 20
#define TOTP_SHA_BLOCK 64

#define TOTP_IN_DIG 0x36
#define TOTP_OUT_DIG 0x5c

#define alpha (unsigned char *)"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

using namespace std;

class TOTP
{
public:
    TOTP();
    ~TOTP();

    static unsigned char * get_random_seed32(void);
    static string get_totp32(string);

private:
    static unsigned int dynamic_truncation(uint8_t *input);
    static void hmac_sha1(uint8_t * key, int key_len, uint8_t * data, int data_len, uint8_t *result);

};

#endif // TOTP_H
