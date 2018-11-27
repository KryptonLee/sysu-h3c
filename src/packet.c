/*
 * Filename: packet.c
 * Author: KryptonLee
 * Creation Time: 2018.11.23
 * 
 * Function:
 *      Define the message values of fields and fixed-header structures
 *      (fixed: means contained in every packet) specified in the EAPOL,
 *      EAP and H3C private protocol. 
 */

#include "packet.h"

/*
 * Set the identifier info (type-data field) of a EAP identifier packet
 * 
 * Parameters:
 *      pkt: pointer to the packet
 *      ver_cipher: pointer to the buffer where the H3C version
 *                  ciphertext is stored
 *      ver_cipher_len: the length of the H3C version ciphertext
 *      usr: pointer to the buffer where the username is stored
 *      usr_len: the length of the username
 */
void set_eap_id_info(void *pkt, const uint8_t *ver_cipher,
    size_t ver_cipher_len, const char *usr, size_t usr_len)
{
    // Pointer to EAP Type field
    uint8_t *ptr = get_eap_type(pkt);
    *ptr = EAP_TYPE_ID;
    
    // Pointer to encrypted version info in the EAP identifier field
    ptr += EAP_TYPE_SIZE;
    memcpy(ptr, ver_cipher, ver_cipher_len);
    // Pointer to username in the EAP identifier field
    ptr += ver_cipher_len;
    memcpy(ptr, usr, usr_len);
}

/*
 * Set the MD5 info (type-data field) of a EAP-MD5-Challenge packet
 * 
 * Parameters:
 *      pkt: pointer to the packet
 *      md5_value: pointer to the buffer where the MD5 value is stored
 *      usr: pointer to the buffer where the username is stored
 *      usr_len: the length of the username
 */
void set_eap_md5_info(void *pkt, const uint8_t *md5_value,
    const char *usr, size_t usr_len)
{
    // Pointer to EAP Type field
    uint8_t *ptr = get_eap_type(pkt);
    *ptr = EAP_TYPE_MD5;

    // Pointer to MD5-Value Length field
    ptr += EAP_TYPE_SIZE;
    *ptr = EAP_MD5_VALUE_SIZE;
    // Pointer to MD5-Value field
    ptr += EAP_MD5_LEN_SIZE;
    memcpy(ptr, md5_value, EAP_MD5_VALUE_SIZE);
    // Pointer to MD5 extra data field
    ptr += EAP_MD5_VALUE_SIZE;
    memcpy(ptr, usr, usr_len);
}

/*
 * Set the H3C info (type-data field) of a EAP H3C packet
 * 
 * Parameters:
 *      pkt: pointer to the packet
 *      psw: pointer to the buffer where the password is stored
 *      psw_len: the length of the password
 *      usr: pointer to the buffer where the username is stored
 *      usr_len: the length of the username
 */
void set_eap_h3c_info(void *pkt, const char *psw,
    size_t psw_len, const char *usr, size_t usr_len)
{
    // Pointer to EAP Type field
    uint8_t *ptr = get_eap_type(pkt);
    *ptr = EAP_TYPE_H3C;

    // Pointer to H3C password length field
    ptr += EAP_TYPE_SIZE;
    *ptr = psw_len;
    // Pointer to H3C password field
    ptr += EAP_H3C_PWLEN_SIZE;
    memcpy(ptr, psw, psw_len);
    // Pointer to H3C username field
    ptr += psw_len;
    memcpy(ptr, usr, usr_len);
}