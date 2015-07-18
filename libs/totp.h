/*
 * This code is an rewrited version of https://github.com/gonrada/TOTP-Generator
 * Thanks to Sean Easton, which allowed me to use it.
 */

#ifndef TOTP_H
#define TOTP_H

#include <stdint-gcc.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <cstring>

//#include <inttypes.h>
//#include <math.h>
//#include <stdint.h>
//#include <stdbool.h>
//#include <stdio.h>
//#include <stdlib.h>
//#include <string.h>
//#include <termios.h>
//#include <time.h>
//#include <unistd.h>

#define SEED_LEN 32

class totp
{
public:
    totp();
    ~totp();

    static uint8_t * base64_encode(uint8_t *input, int length);
    static uint8_t * base64_decode(uint8_t *input, int length);
    static uint8_t * get_random_seed(void);

};

#endif // TOTP_H
