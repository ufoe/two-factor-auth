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

string TOTP::get_totp32(string stoken) {

    // Get unix timestamp divided by period (30 sec is default)
    unsigned long date = floor(time(NULL) / TOTP_PERIOD);
    cout << "Date: " << date << endl;

    // Divide by blocks
    uint8_t challenge[8];
    for (int i = 8; i--; date >>= 8) {
      challenge[i] = date;
    }

    // Decoding from base32
    uint8_t token32[stoken.size()];
    memcpy(token32, stoken.c_str(), stoken.size());
    if (!Base32::Unmap32(token32, stoken.size(), alpha)) {
        cerr << "[TOTP::get_totp32] error on unmapping input string" << endl;
        return "error";
    }
    int length = (stoken.size() + 7)/8*5;
    //int length = Base32::GetDecode32Length(stoken.size());
    uint8_t useed[length];
    memset(useed, 0 , length);
    if (!Base32::Decode32(token32, length, useed)) {
        cerr << "[TOTP::get_totp32] error on decoding input string" << endl;
        return "error";
    }

    // Copy decoded token to required data type
    uint8_t seed[length];
    memset(seed, 0, length);
    memcpy(seed, useed, length);

    // Generate HMAC-SHA1
    uint8_t *result[TOTP_SHA_LEN];
    hmac_sha1(seed, length, challenge, 8, result[0]);

/*
    // Test for HMAC-SHA1
    hmac_sha1((uint8_t *) "1", 1, (uint8_t *) "2", 1, result[0]);
    // Result must be equal "fb:db:1d:1b:18:aa:6c:08:32:4b:7d:64:b7:1f:b7:63:70:69:0e:1d"
    hmac_sha1((uint8_t *) "1", 1, (uint8_t *) "2", 1, result[0]);
    // Result must be equal "d0:75:ca:12:b8:25:9a:0b:27:43:8f:07:53:14:a3:bb:88:a9:27:b5"
*/

    // Return last TOTP_DIGITS digits
    unsigned int totp = dynamic_truncation(result[0]);
    cout << "Bin code  (hex): \t"
         << (totp >>24 & 0xff) << ":"
         << (totp >>16 & 0xff) << ":"
         << (totp >>8 & 0xff) << ":"
         << (totp & 0xff) << endl;


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
    // Offset used to get special item number to get TOTP code
    int offset = input[TOTP_SHA_LEN - 1] & 0xf;

    // Cut code
    unsigned int bin_code = 0;
    for (int i = 0; i < 4; ++i) {
        bin_code <<= 8;
        bin_code  |= input[offset + i];
    }

    // Return last TOTP_DIGITS digits
    bin_code &= 0x7FFFFFFF;
    bin_code %= (int) pow(10.0, TOTP_DIGITS);

    return bin_code;
}

void TOTP::hmac_sha1(uint8_t * key, int key_len, uint8_t * data, int data_len, uint8_t *ressha) {

    // Adjusting key length
    uint8_t adj_key[TOTP_SHA_BLOCK];
    memset(adj_key, 0, TOTP_SHA_BLOCK);

    // If key is too long - will use hash instead of
    if (key_len > TOTP_SHA_BLOCK)
        SHA1(key, key_len, adj_key);
    else
        memcpy(adj_key, key, key_len);

    // Debug output
    cout << setfill('0');
    cout << "Result #0 (hex):\t";
    for (int i=0; i< TOTP_SHA_LEN; i++)
        cout << (i==0?"":":") << hex << setw(2) << (int)ressha[i];
    cout << endl;

    // Calculate with inner digits
    uint8_t ipad[TOTP_SHA_BLOCK];
    memset(ipad, TOTP_IN_DIG, TOTP_SHA_BLOCK);
    for (int i=0; i<TOTP_SHA_BLOCK; i++)
        ipad[i] ^= adj_key[i];

    uint8_t in_buffer[TOTP_SHA_BLOCK + data_len];
    memset(in_buffer, 0, TOTP_SHA_BLOCK + data_len);
    memcpy(in_buffer, ipad, TOTP_SHA_BLOCK);
    memcpy(&in_buffer[TOTP_SHA_BLOCK], data, data_len);
    SHA1(in_buffer, TOTP_SHA_BLOCK + data_len, ressha);

    // Debug output
    cout << "Result #1 (hex):\t";
    for (int i=0; i< TOTP_SHA_LEN; i++)
        cout << (i==0?"":":") << hex << setw(2) << (int)ressha[i];
    cout << endl;

    // Calculate with outer digits
    uint8_t opad[TOTP_SHA_BLOCK];
    memset(opad, TOTP_OUT_DIG, TOTP_SHA_BLOCK);
    for (int i=0; i<TOTP_SHA_BLOCK; i++)
        opad[i] ^= adj_key[i];

    uint8_t out_buffer[TOTP_SHA_BLOCK + TOTP_SHA_LEN];
    memset(out_buffer, 0, TOTP_SHA_BLOCK + TOTP_SHA_LEN);
    memcpy(out_buffer, opad, TOTP_SHA_BLOCK);
    memcpy(&out_buffer[TOTP_SHA_BLOCK], ressha, TOTP_SHA_LEN);
    SHA1(out_buffer, TOTP_SHA_BLOCK + TOTP_SHA_LEN, ressha);

    // Debug output
    cout << "Result #2 (hex):\t";
    for (int i=0; i< TOTP_SHA_LEN; i++)
        cout << (i==0?"":":") << hex << setw(2) << (int)ressha[i];
    cout << endl;

}
