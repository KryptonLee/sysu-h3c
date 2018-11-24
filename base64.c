/*
 * Filename: base64.c
 * Author: KryptonLee
 * Creation Time: 2018.11.23
 * 
 * Function:
 *      Base64 encode and decode method.
 *
 */

#include <string.h>
#include "base64.h"


// Constants
const static char *base64_char = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const static char padding_char = '=';

/*
 * Search the index of the first occurance of c in a C string str
 *
 * Parameters:
 *      str: a C string
 * Return Value:
 *      The index of the first occurrence of c in str
 *      If the character is not found, the function returns 
 */
static inline int index_strchr(const char *str, char c) {
    const char *ptr = strchr(str, c);
    if (NULL == ptr)
        return -1;
    
    return ptr - str;
}

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
char *base64_encode(char *endata, const char *src, size_t len)
{
    int i = 0, j = 0;
    int char_index = 0; // index of a character in base64_char
    for(; i < len; i += 3)
    {
        // Each encoding action will encode 3 bytes from src
        // Encoding the first byte
        char_index = ((src[i] >> 2) & 0x3f);
        endata[j++] = base64_char[char_index];
        // Encoding the second byte
        char_index = ((src[i] << 4) & 0x30);
        if (i + 1 < len)
        {
            char_index |= ((src[i + 1] >> 4) & 0x0f);
            endata[j++] = base64_char[char_index];
        }
        else // Meets endding of src
        {
            endata[j++] = base64_char[char_index];
            endata[j++] = padding_char;
            endata[j++] = padding_char;
            break;
        }
        // Encoding the third byte
        char_index = ((src[i + 1] << 2) & 0x3c);
        if (i + 2 < len)
        {
            char_index |= ((src[i + 2] >> 6) & 0x03);
            endata[j++] = base64_char[char_index];

            char_index = src[i + 2] & 0x3f;
            endata[j++] = base64_char[char_index];
        }
        else // Meets endding of src
        {
            endata[j++] = base64_char[char_index];
            endata[j++] = padding_char;
            break;
        }
    }

    return endata;
}

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
char *base64_decode(char *dedata, const char *src, size_t len)
{
    int i = 0, j = 0;
    int trans[4] = {0, 0, 0, 0};
    for(i = 0; i < len; i += 4)
    {
        // Each decode action will decode 4 bytes into 3 characters
        trans[0] = index_strchr(base64_char, src[i]);
        trans[1] = index_strchr(base64_char, src[i + 1]);
        // First character
        dedata[j++] = ((trans[0] << 2) & 0xfc) | ((trans[1] >> 4) & 0x03);

        if (src[i + 2] == padding_char)
            continue;
        else
            trans[2] = index_strchr(base64_char, src[i + 2]);
            
        // Second character
        dedata[j++] = ((trans[1] << 4) & 0xf0) | ((trans[2] >> 2) & 0x0f);

        if (src[i + 3] == padding_char)
            continue;
        else
            trans[3] = index_strchr(base64_char, src[i + 3]);

        // Third character
        dedata[j++] = ((trans[2] << 6) & 0xc0) | (trans[3] & 0x3f);
    }

    return dedata;
}