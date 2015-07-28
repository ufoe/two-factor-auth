/*
 * This code is an rewrited version of https://github.com/gonrada/TOTP-Generator
 * Thanks to Sean Easton, which allowed me to use it.
 */

#include "totp.h"
#include <iomanip>


unsigned char * TOTP::get_random_seed32(void) {
    unsigned char *seed = (unsigned char *)malloc(TOTP_SEED_LEN);

    FILE *seedSrc = fopen("/dev/urandom", "r");
    if(!seedSrc)
        cerr << "[TOTP::get_random_seed] Error opening /dev/random for read" << endl;
    else {
        fread(seed, TOTP_SEED_LEN, 1, seedSrc);
        fclose(seedSrc);
    }

    int length = Base32::GetEncode32Length(TOTP_SEED_LEN);
    unsigned char *token = new unsigned char[length];

    if (Base32::Encode32(seed, TOTP_SEED_LEN, token)) {
        if (Base32::Map32(token, length, alpha)) {
            return token;
        }
    }

    return (unsigned char *)"error";
}

unsigned char * memxor (unsigned char *dst, unsigned char* src, int src_len)
{
    const char *s = (const char *)src;
    char *d = (char *)dst;

    while (src_len > 0) {
        *d++ ^= *s++;
        src_len--;
    }

    return dst;
}

string TOTP::get_totp32(string stoken) {

    // Decoding from base32
    uint8_t *token32 = (uint8_t*)stoken.c_str();
    if (!Base32::Unmap32(token32, stoken.size(), alpha)) {
        cerr << "[TOTP::get_totp32] error on unmapping input string" << endl;
        return "error";
    }
    int length = Base32::GetDecode32Length(stoken.size());
    uint8_t *useed = new uint8_t[length];
    if (!Base32::Decode32(token32, length, useed)) {
        cerr << "[TOTP::get_totp32] error on decoding input string" << endl;
        return "error";
    }

    // Copy decoded token to required data type
    uint8_t *seed = (uint8_t*)malloc(length);
    memset(seed, 0, length);
    memcpy(seed, useed, length);

    // Get unix timestamp divided by period (30 sec is default)
    uint64_t date = floor(time(NULL) / TOTP_PERIOD);
    cout << "Date: " << date << endl;

    // Generate HMAC-SHA1
    uint8_t *result = new uint8_t [TOTP_SHA_LEN];
    memcpy(result, hmac_sha1(seed, length, (uint8_t *) &date, sizeof(uint64_t)), TOTP_SHA_LEN);

    // Dynamic truncation
    int bin = dynamic_truncation(result);
    cout << "Bin code  (hex): \t"
         << (bin >>24 & 0xff) << ":"
         << (bin >>16 & 0xff) << ":"
         << (bin >>8 & 0xff) << ":"
         << (bin & 0xff) << endl;

    int totp = dynamic_truncation(result);

    // Return results ... why stream? Just for fun
    ostringstream res;
    res << totp;

    // If code shorter than required amount
    if (res.str().size() < TOTP_DIGITS) {
        string sres = res.str();
        while (sres.size() < TOTP_DIGITS)
            sres.insert(sres.begin(), '0');

        return sres;
    }

    return res.str();
}

unsigned int TOTP::dynamic_truncation(uint8_t *input)
{
        unsigned int bin_code;
        unsigned int offset;

        // Offset used to get special item number to get TOTP code
        offset = input[TOTP_SHA_LEN - 1] & 0xf;

        // Cut code
        bin_code = (input[offset] & 0x7f) << 24
                | (input[offset+1] & 0xff) << 16
                | (input[offset+2] & 0xff) << 8
                | (input[offset+3] & 0xff) ;

        // Return last TOTP_DIGITS digits
        return bin_code % (int) pow(10, TOTP_DIGITS);
}

uint8_t * TOTP::hmac_sha1(uint8_t * key, int key_len, uint8_t * data, int data_len) {

    // Adjusting key length
    if ( key_len != TOTP_SHA_BLOCK ) {
        uint8_t *temp_key = new uint8_t [TOTP_SHA_BLOCK];

        if (key_len > TOTP_SHA_BLOCK) {
            SHA1(key, key_len, temp_key);
        } else {
            memset(temp_key, 0, TOTP_SHA_BLOCK);
            memcpy(temp_key, key, key_len);
        }

        key = new unsigned char[TOTP_SHA_LEN];
        memcpy(key, temp_key, TOTP_SHA_LEN);
        key_len = TOTP_SHA_LEN;
    }

    uint8_t *result = new uint8_t [TOTP_SHA_LEN];
    memset(result, 0, TOTP_SHA_LEN);

    cout << setfill('0');
    cout << "Result #0 (hex):\t";
    for (int i=0; i< TOTP_SHA_LEN; i++)
        cout << (i==0?"":":") << hex << setw(2) << (int)result[i];
    cout << endl;

    // Calculate with inner digits
    uint8_t *ipad = new uint8_t [TOTP_SHA_BLOCK];
    memset(ipad, TOTP_IN_DIG, TOTP_SHA_BLOCK);
    ipad = memxor(ipad, key, key_len);
    uint8_t *buffer = new uint8_t [TOTP_SHA_BLOCK + data_len];
    memset(buffer, 0, TOTP_SHA_BLOCK + data_len);
    memcpy(buffer, ipad, TOTP_SHA_BLOCK);
    memcpy(&buffer[TOTP_SHA_BLOCK], data, data_len);
    SHA1(buffer, TOTP_SHA_BLOCK + data_len, result);

    cout << "Result #1 (hex):\t";
    for (int i=0; i< TOTP_SHA_LEN; i++)
        cout << (i==0?"":":") << hex << setw(2) << (int)result[i];
    cout << endl;

    // Calculate with outer digits
    uint8_t *opad = new uint8_t [TOTP_SHA_BLOCK];
    memset(opad, TOTP_OUT_DIG, TOTP_SHA_BLOCK);
    opad = memxor(opad, key, key_len);
    buffer = new uint8_t [TOTP_SHA_BLOCK + TOTP_SHA_LEN];
    memset(buffer, 0, TOTP_SHA_BLOCK + TOTP_SHA_LEN);
    memcpy(buffer, opad, TOTP_SHA_BLOCK);
    memcpy(&buffer[TOTP_SHA_BLOCK], result, TOTP_SHA_LEN);
    SHA1(buffer, TOTP_SHA_BLOCK + TOTP_SHA_LEN, result);

    cout << "Result #2 (hex):\t";
    for (int i=0; i< TOTP_SHA_LEN; i++)
        cout << (i==0?"":":") << hex << setw(2) << (int)result[i];
    cout << endl;

    return result;
}
