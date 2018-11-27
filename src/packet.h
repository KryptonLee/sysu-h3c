/*
 * Filename: packet.h
 * Author: KryptonLee
 * Creation Time: 2018.11.23
 * 
 * Function:
 *      Define the message values of fields and fixed-header structures
 *      (fixed: means contained in every packet) specified in the EAPOL,
 *      EAP and H3C private protocol. 
 */

#ifndef PACKET_H
#define PACKET_H

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <net/ethernet.h>
#include <netinet/in.h>

// Define the message values
// PAE Ethernet Type (802.1X protoco)
#define ETHER_TYPE_PAE 0x888e

// Version of EAPOL
#define EAPOL_VER 1

// Values for Type field of EAPOL header
#define EAPOL_TYPE_EAPPACKET 0
#define EAPOL_TYPE_START 1
#define EAPOL_TYPE_LOGOFF 2
#define EAPOL_TYPE_KEY 3
#define EAPOL_TYPE_ASF 4
// Size of each field of EAPOL header
#define EAPOL_VER_SIZE 1
#define EAPOL_TYPE_SIZE 1
#define EAPOL_LEN_SIZE 2

// Values for Code field of EAP header
#define EAP_CODE_REQUEST 1
#define EAP_CODE_RESPONSE 2
#define EAP_CODE_SUCCESS 3
#define EAP_CODE_FAILURE 4
// Values for Type field of EAP header
#define EAP_TYPE_ID 1
#define EAP_TYPE_MD5 4
#define EAP_TYPE_H3C 7
// Size of each field of EAP header in byte
#define EAP_CODE_SIZE 1
#define EAP_ID_SIZE 1
#define EAP_LEN_SIZE 2
#define EAP_TYPE_SIZE 1

// Size of each field of H3C content in byte
#define EAP_MD5_VALUE_SIZE 16
#define EAP_MD5_LEN_SIZE 1
#define EAP_H3C_PWLEN_SIZE 1

// Size of some packet type
#define ETHER_HEADER_SIZE sizeof(struct ether_header)
#define EAPOL_HEADER_SIZE sizeof(struct eapol_header)
#define EAP_HEADER_SIZE sizeof(struct eap_header)
#define EAPOL_START_PKT_SIZE (sizeof(struct ether_header) + sizeof(struct eapol_header))
#define EAPOL_LOGOFF_PKT_SIZE (sizeof(struct ether_header) + sizeof(struct eapol_header))

// PAE broadcast MAC address
static const uint8_t PAE_GROUP_ADDR[] = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x03};

// Struct EAPOL header
typedef struct eapol_header
{
    uint8_t version;
    uint8_t type;
    uint16_t length;
} __attribute__((packed)) eapol_header;

// Struct for fixed part in EAP header
typedef struct eap_header
{
    uint8_t code;
    uint8_t id;
    uint16_t length;
} __attribute__((packed)) eap_header;

// Struct for fixed part in header of H3C 802.1X packet
// include ethernet header, EAPOL header, and EAP header
typedef struct packet_header
{
    struct ether_header ether_header;
    struct eapol_header eapol_header;
    struct eap_header eap_header;
} __attribute__((packed)) packet_header;

/*
 * Use dhost and shost to set ethernet header in a packet_header
 * struct, the type field is fixed to ETHER_TYPE_PAE
 * 
 * Parameters:
 *      pkt_h: pointer to the packet_header struct
 *      dhost: pointer to dhost string
 *      shost: pointer to shost string
 */
static inline void set_ether_header(struct packet_header *pkt_h,
    const uint8_t *dhost, const uint8_t *shost)
{
    memcpy(pkt_h->ether_header.ether_dhost, dhost, ETHER_ADDR_LEN);
    memcpy(pkt_h->ether_header.ether_shost, shost, ETHER_ADDR_LEN);
    pkt_h->ether_header.ether_type = htons(ETHER_TYPE_PAE);
}

/*
 * Use type and length to set EAPOL header in a packet_header
 * struct, the version field is fixed to EAPOL_VER
 * 
 * Parameters:
 *      pkt_h: pointer to the packet_header struct
 *      type: EAPOL type value
 *      length: EAPOL length (data only, not include header)
 */
static inline void set_eapol_header(struct packet_header *pkt_h, 
    uint8_t type, uint16_t length)
{
    pkt_h->eapol_header.version = EAPOL_VER;
    pkt_h->eapol_header.type = type;
    pkt_h->eapol_header.length = htons(length);
}

/*
 * Use code, id and length to set EAP header in a packet_header struct
 * 
 * Parameters:
 *      pkt_h: pointer to the packet_header struct
 *      code: EAP code value
 *      id : packet id
 *      length: EAP length (include header and data)
 */
static inline void set_eap_header(struct packet_header *pkt_h,
    uint8_t code, uint8_t id, uint16_t length)
{
    pkt_h->eap_header.code = code;
    pkt_h->eap_header.id = id;
    pkt_h->eap_header.length = htons(length);
}


/*
 * Get EAP type value of a packet
 * 
 * Parameters:
 *      pkt: pointer to the packet
 * 
 * Return Value:
 *      EAP type value of the packet
 */
static inline uint8_t *get_eap_type(void *pkt)
{
    return (uint8_t *)pkt + sizeof(struct packet_header);
}
/*
 * Get MD5-Value in EAP type-data of a packet
 * 
 * Parameters:
 *      pkt: pointer to the packet
 * 
 * Return Value:
 *      Pointer to the MD5-Value
 */
static inline uint8_t *get_eap_md5_value(void *pkt)
{
    return get_eap_type(pkt) + EAP_TYPE_SIZE + EAP_MD5_LEN_SIZE;
}

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
    size_t ver_cipher_len, const char *usr, size_t usr_len);
/*
 * Set the MD5 info (type-data field) of a EAP MD5-Challenge packet
 * 
 * Parameters:
 *      pkt: pointer to the packet
 *      md5_value: pointer to the buffer where the MD5 value is stored
 *      usr: pointer to the buffer where the username is stored
 *      usr_len: the length of the username
 */
void set_eap_md5_info(void *pkt, const uint8_t *md5_value,
    const char *usr, size_t usr_len);
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
    size_t psw_len, const char *usr, size_t usr_len);

#endif // PACKET_H