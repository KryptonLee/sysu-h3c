/*
 * Filename: h3c_encrypt.c
 * Author: KryptonLee
 * Creation Time: 2018.11.24
 * 
 * Function:
 *      Methods for H3C encryption.
 * 
 */

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <netinet/in.h>

#include "h3c_encrypt.h"
#include "base64.h"

/*
 * Using the key to carry XOR operation with data, in forward and inverse
 * oder once. If the key is shorter than data, recycle the key.
 * 
 * Parameters:
 *      data: pointer to the buffer where the data is to be stored
 *      data_len: the length of data in bytes
 *      key: pointer to the buffer where the key is stored
 *      key_len: the length of key in bytes
 * 
 * Return Value:
 *      data (after XOR) is returned
 */
static inline uint8_t *h3c_xor(uint8_t *data, size_t data_len,
    const uint8_t *key, size_t key_len)
{
    int i = 0;
    // Forward order XOR
    for(i = 0; i < data_len; i++)
        data[i] ^= key[i % key_len];
    
    // Inverse order XOR
    for(i = 0; i < data_len; i++)
        data[data_len - 1 - i] ^= key[i % key_len];
    
    return data;
}

/*
 * Method to encrypt the version info in the EAP identifier packet
 * 
 * Parameters:
 *      cipher: pointer to the buffer where the ciphertext is to be stored
 *      cipher_len: the length of ciphertext in bytes
 *      plaint: pointer to the buffer where the plaintext is stored
 *      plain_len: the length of plaintext in bytes
 *      key: pointer to the buffer where the key is stored
 *      key_len: the length of key in bytes
 * 
 * Return Value:
 *      cipher is returned
 */
uint8_t *encrypt_h3c_ver(uint8_t *cipher, size_t *cipher_len,
    const uint8_t *plain, size_t plain_len,
    const uint8_t *key, size_t key_len)
{
    char prefix[] = {0x06, 0x07};
    char postfix[] = {0x20, 0x20};
    uint32_t rand_int;
    uint8_t rand_key[sizeof(uint32_t) * 2 + 1];
    uint8_t *rand_key_enbuf, *h3c_key_enbuf;
    size_t rand_key_enbuf_len, h3c_key_enbuf_len;

    rand_key_enbuf_len = plain_len + sizeof(uint32_t);
    rand_key_enbuf = (uint8_t *)malloc(rand_key_enbuf_len);
    h3c_key_enbuf_len = ((rand_key_enbuf_len + 2) / 3) * 4;
    h3c_key_enbuf = (uint8_t *)malloc(h3c_key_enbuf_len);


    // Get a random int (32 bits) value
    srand((unsigned int)time(NULL));
    rand_int = rand();
    // Print the hex value of the random int, got 8 characters,
    // store the ASCII value of those 8 characters.
    sprintf(rand_key, "%08x", rand_int);

    // Use rand_key to XOR plaintext
    memcpy(rand_key_enbuf, plain, plain_len);
    h3c_xor(rand_key_enbuf, plain_len, rand_key, sizeof(uint32_t) * 2);

    rand_int = htonl(rand_int);
    memcpy(rand_key_enbuf + plain_len, &rand_int, sizeof(uint32_t));
    h3c_xor(rand_key_enbuf, rand_key_enbuf_len, key, key_len);

    base64_encode(h3c_key_enbuf, rand_key_enbuf, rand_key_enbuf_len);

    memcpy(cipher, prefix, sizeof(prefix));
    memcpy(cipher + sizeof(prefix), h3c_key_enbuf, h3c_key_enbuf_len);
    memcpy(cipher + sizeof(prefix) + h3c_key_enbuf_len, postfix, sizeof(postfix));
    *cipher_len = sizeof(prefix) + h3c_key_enbuf_len + sizeof(postfix);

    free(rand_key_enbuf);
    free(h3c_key_enbuf);

    return cipher;
}