/*
 * This code is an rewrited version of https://github.com/gonrada/TOTP-Generator
 * Thanks to Sean Easton, which allowed me to use it.
 */

#include "totp.h"

totp::totp()
{

}

uint8_t * totp::base64_encode(uint8_t *input, int length) {
    BIO *bmem, *b64;
    BUF_MEM *bptr;

    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, input, length);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);

    uint8_t *buff = (uint8_t *)malloc(bptr->length);
    memcpy(buff, bptr->data, bptr->length-1);
    buff[bptr->length-1] = 0;

    BIO_free_all(b64);

    return buff;
}

uint8_t * totp::base64_decode(uint8_t *input, int length) {
    BIO *b64, *bmem;

    uint8_t *buffer = (uint8_t *)malloc(length);
    memset(buffer, 0, length);

    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new_mem_buf(input, length);
    bmem = BIO_push(b64, bmem);

    BIO_read(bmem, buffer, length);

    BIO_free_all(bmem);

    return buffer;
}

uint8_t * totp::get_random_seed(void) {
    uint8_t *seed = (uint8_t *) malloc(SEED_LEN);

    FILE *seedSrc = fopen("/dev/urandom", "r");
    if(!seedSrc)
        printf("[totp::get_random_seed()] Error opening [%s] for r","/dev/urandom");
    else {
        fread(seed, SEED_LEN, 1, seedSrc);
        fclose(seedSrc);
    }
    return base64_encode(seed, SEED_LEN);
}
