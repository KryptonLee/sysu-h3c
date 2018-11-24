/*
 * Filename: packet.h
 * Author: KryptonLee
 * Creation Time: 2018.11.23
 * 
 * Function:
 *      Define the message values of fields and fixed-header structures
 *      (fixed: means contained in every packet) specified in the EAPOL,
 *      EAP and H3C private protocol. 
 * 
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
#define ENCRY_VER_INFO_SIZE 32
#define IP_ADDR_INFO_SIZE 6

// Size of some packet type
#define ETHER_HEADER_SIZE sizeof(struct ether_header)
#define EAPOL_HEADER_SIZE sizeof(struct eapol_header)
#define EAP_HEADER_SIZE sizeof(struct eap_header)
#define EAPOL_START_PKT_SIZE (sizeof(struct ether_header) + sizeof(struct eapol_header))
#define EAPOL_LOGOFF_PKT_SIZE (sizeof(struct ether_header) + sizeof(struct eapol_header))

// PAE broadcast MAC address
static const uint8_t PAE_GROUP_ADDR[] = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x03};

typedef struct eapol_header
{
    uint8_t version;
    uint8_t type;
    uint16_t length;
} __attribute__((packed)) eapol_header;

typedef struct eap_header
{
    uint8_t code;
    uint8_t id;
    uint16_t length;
} __attribute__((packed)) eap_header;

typedef struct packet_header
{
    struct ether_header ether_header;
    struct eapol_header eapol_header;
    struct eap_header eap_header;
} __attribute__((packed)) packet_header;

static inline void set_ether_header(struct packet_header *pkt_h,
    const uint8_t *dhost, const uint8_t *shost)
{
    memcpy(pkt_h->ether_header.ether_dhost, dhost, ETHER_ADDR_LEN);
    memcpy(pkt_h->ether_header.ether_shost, shost, ETHER_ADDR_LEN);
    pkt_h->ether_header.ether_type = htons(ETHER_TYPE_PAE);
}    

static inline void set_eapol_header(struct packet_header *pkt_h, 
    uint8_t type, uint16_t length)
{
    pkt_h->eapol_header.version = EAPOL_VER;
    pkt_h->eapol_header.type = type;
    pkt_h->eapol_header.length = htons(length);
}

static inline void set_eap_header(struct packet_header *pkt_h,
    uint8_t code, uint8_t id, uint16_t length)
{
    pkt_h->eap_header.code = code;
    pkt_h->eap_header.id = id;
    pkt_h->eap_header.length = htons(length);
}

static inline uint8_t *get_eap_type(struct packet_header *pkt_h)
{
    return (uint8_t *)pkt_h + sizeof(struct packet_header);
}

static inline uint8_t *get_eap_md5_value(struct packet_header * pkt_h)
{
    return get_eap_type(pkt_h) + EAP_TYPE_SIZE + EAP_MD5_LEN_SIZE;
}

void set_eap_id_info(struct packet_header *pkt_h, const uint8_t *encry_ver_info,
    const char *usr, size_t usr_len);

void set_eap_md5_info(struct packet_header *pkt_h, const uint8_t *md5_value,
    const char *usr, size_t usr_len);

void set_eap_h3c_info(struct packet_header *pkt_h, const char *psw,
    size_t psw_len, const char *usr, size_t usr_len);

#endif // PACKET_H