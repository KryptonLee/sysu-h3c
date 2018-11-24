/*
 * Filename: base64.h
 * Author: KryptonLee
 * Creation Time: 2018.11.23
 * 
 * Function:
 *      Base64 encode and decode method.
 *
 */

#ifndef BASE64_H
#define BASE64_H

#include <stdint.h>
#include <stdlib.h>

/*
 * Base64 encode method
 * 
 * Parameters:
 *      endata: pointer to the array where the encoded data is to be store
 *      src: pointer to the source data to be encoded
 *      len: the length of source data in bytes
 * Return Value:
 *      endata is returned
 */
char *base64_encode(char *endata, const char *src, size_t len);

/*
 * Base64 decode method
 * 
 * Parameters:
 *      dedata: pointer to the array where the decoded data is to be store
 *      src: pointer to the source data to be decoded
 *      len: the length of source data in bytes
 * Return Value:
 *      dedata is returned
 */
char *base64_decode(char *dedata, const char *src, size_t len);

#endif /* BASE64_H_ */