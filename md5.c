/*
 * Filename: md5.c
 * Author: KryptonLee
 * Creation Time: 2018.11.24
 * 
 * Function:
 *      MD5 hash method.
 * 
 * Algorithm reference: 
 *      https://baike.baidu.com/item/MD5%E5%8A%A0%E5%AF%86/5706230?fr=aladdin
 */

#include <stdio.h>
#include <string.h>

#include "md5.h"

// Define the base operation in MD5
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))

// Chaining variables initial value
#define A 0x67452301
#define B 0xefcdab89
#define C 0x98badcfe
#define D 0x10325476

// Constants Ti (abs(sin(i + 1)) * (2pow32))
static const uint32_t T[] = {
    0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,
    0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,0x698098d8,
    0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,
    0xa679438e,0x49b40821,0xf61e2562,0xc040b340,0x265e5a51,
    0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
    0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,
    0xfcefa3f8,0x676f02d9,0x8d2a4c8a,0xfffa3942,0x8771f681,
    0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,
    0xbebfbc70,0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,
    0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,0xf4292244,
    0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,
    0xffeff47d,0x85845dd1,0x6fa87e4f,0xfe2ce6e0,0xa3014314,
    0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391};

// Rotate left step Si
static const uint32_t S[] = {
    7, 12, 17, 22, 7,12, 17, 22, 7, 12, 17, 22, 7, 12, 17,
    22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14,
    20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11,
    16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6,
    10, 15, 21};

/*
 * The main loop operation for a block (512 bits) in MD5 hash method
 * 
 * 
 * Parameters:
 *      M: 16 groups in a block
 *      a_stat: pointer to the chaining variable A
 *      b_stat: pointer to the chaining variable B
 *      c_stat: pointer to the chaining variable C
 *      d_stat: pointer to the chaining variable D
 * 
 */
static void main_loop(uint32_t M[], uint32_t *a_stat, 
    uint32_t *b_stat, uint32_t *c_stat,  uint32_t *d_stat)
{
    uint32_t f, g, tmp;
    uint32_t a = *a_stat;
    uint32_t b = *b_stat;
    uint32_t c = *c_stat;
    uint32_t d = *d_stat;
    int i = 0;

    for(i = 0; i < 64; i++)
    {
        if (i < 16)
        {
            f = F(b, c, d);
            g = i;
        }
        else if (i < 32)
        {
            f = G(b, c, d);
            g = (5 * i + 1) % 16;
        }
        else if (i < 48)
        {
            f = H(b, c, d);
            g = (3 * i + 5) % 16;
        }
        else
        {
            f = I(b, c, d);
            g = (7 * i) % 16;
        }
        tmp = d;
        d = c;
        c = b;
        b += ROTATE_LEFT((a + f + T[i] + M[g]), S[i]);
        a = tmp;
    }
    *a_stat += a;
    *b_stat += b;
    *c_stat += c;
    *d_stat += d;
}

/*
 * Calculate the length of the data after padding in bytes
 * 
 * 
 * Parameters:
 *      src_len: the length of source data in bytes
 * 
 * Return Value:
 *      the length of the data after padding in bytes is returned
 */
static inline size_t get_padding_len(size_t src_len)
{
    return ((src_len + 8) / 64 + 1) * 16;
}

/*
 * Padding the source to make sure its length equals (N * 512 bit), to
 * achieve such operation, a bit 1 will follow to the source data,
 * followed by other bits 0, until the length equals (M * 512 bit + 448
 * bit). The last 64 bits will be filled by the original length in bits
 * of the source data (before padding), in LITTLE ENDIAN.
 * 
 * 
 * Parameters:
 *      pad_buf: pointer to the buffer where the data after padding is
 *               to be stored
 *      src: pointer to the source data
 *      src_len: the length of source data in bytes
 * 
 * Return Value:
 *      pad_buf is returned
 */
static uint32_t *padding(uint32_t *pad_buf, const uint8_t *src, size_t src_len)
{
    size_t i = 0;
    size_t pad_len = get_padding_len(src_len);
    // Pointer to the beginning of the last 8 bytes
    uint8_t *ptr_len = ((uint8_t *)(pad_buf + pad_len)) - sizeof(uint64_t);

    memset(pad_buf, 0, pad_len * sizeof(uint32_t));
    // Cannot copy the memory from src to pad_buf directly as
    // different platforms have different byte order
    for(i = 0; i < src_len; i++)
        pad_buf[i >> 2] |= src[i] << ((i % sizeof(uint32_t)) * 8);

    pad_buf[src_len >> 2] |= 0x80 << ((src_len % sizeof(uint32_t)) * 8);

    // The length of data before padding should be stored in LITTLE ENDIAN
    for(i = 0; i < sizeof(uint64_t); i++)
        ptr_len[i] = ((src_len * 8) >> (i * 8)) & 0xff;

    return pad_buf;
}

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
uint8_t * get_md5(uint8_t *md5_buf, uint8_t *src, size_t src_len)
{
    // Initialize the chaining variables
    uint32_t stat[] = {A, B, C, D};
    size_t i = 0, j = 0, pad_len = 0;
    uint32_t *groups;
    pad_len = get_padding_len(src_len);
    // Allocate the memory for padding data
    groups = (uint32_t *)malloc(pad_len * sizeof(uint32_t));

    // Main loop
    groups = padding(groups, src, src_len);
    for(i = 0; i < pad_len; i += 16)
        main_loop(groups + i, &stat[0], &stat[1], &stat[2], &stat[3]);

    free(groups);
    
    // Cannot copy the memory from stat to md5_buf directly as
    // different platforms have different byte order
    for(i = 0; i < 4; i++)
        for(j = 0; j < 4; j++)
            md5_buf[i * 4 + j] = (stat[i] >> (j * 8)) & 0xff;

    return md5_buf;
}