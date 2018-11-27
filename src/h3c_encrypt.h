/*
 * Filename: h3c_encrypt.h
 * Author: KryptonLee
 * Creation Time: 2018.11.24
 * 
 * Function:
 *      Methods for H3C encryption.
 */

#ifndef H3C_ENCRYPT_H
#define H3C_ENCRYPT_H

#include <stdint.h>
#include <stdlib.h>

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
    const uint8_t *key, size_t key_len);

#endif