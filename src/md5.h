/*
 * Filename: md5.h
 * Author: KryptonLee
 * Creation Time: 2018.11.24
 * 
 * Function:
 *      MD5 hash method.
 */

#ifndef MD5_H
#define MD5_H

#include <stdint.h>
#include <stdlib.h>

/*
 * Calculate the MD5 hash value of src
 * 
 * Parameters:
 *      md5_buf: pointer to the buffer where the MD5 hash value is to be stored
 *      src: pointer to the source data
 *      src_len: the length of source data in bytes
 * 
 * Return Value:
 *      md5_buf is returned
 */
uint8_t * get_md5(uint8_t *md5_buf, uint8_t *src, size_t src_len);

#endif