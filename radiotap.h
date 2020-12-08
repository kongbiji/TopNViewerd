#pragma once
#include "include.h"

enum radiotap_presence {
    TSFT = 0,
    FLAGS = 1,
    RATE = 2,
    CHANNEL = 3,
    FHSS = 4,
    DBM_ANTSIGNAL = 5,
    DBM_ANTNOISE = 6,
    LOCK_QUALITY = 7,
    TX_ATTENUATION = 8,
    DB_TX_ATTENUATION = 9,
    DBM_TX_POWER = 10,
    ANTENNA = 11,
    DB_ANTSIGNAL = 12,
    DB_ANTNOISE = 13,
    RX_FLAGS = 14,
    TX_FLAGS = 15,
    RTS_RETRIES = 16,
    DATA_RETRIES = 17,
    XCHANNEL = 18,    /* 18 is XChannel, but it's not defined yet */
    MCS = 19,
    AMPDU_STATUS = 20,
    VHT = 21,
    TIMESTAMP = 22,

    /* valid in every it_present bitmap, even vendor namespaces */
    RADIOTAP_NAMESPACE = 29,
    VENDOR_NAMESPACE = 30,
    EXT = 31
};

struct radiotap_align_size {
    uint8_t align:4, size:4;
};

#pragma pack(push, 1)
typedef struct radiotap_header {

    uint8_t        it_version;     /* set to 0 */
    uint8_t        it_pad;
    uint16_t       it_len;         /* entire length */
    uint32_t       it_present;     /* fields present */


    uint8_t* radiotap_present_flag(radiotap_presence ps);

}radiotap_header;

#pragma pack(pop)

#pragma pack(push, 1)
typedef struct present_flags{
    uint8_t tsft:1;
    uint8_t flags:1;
    uint8_t rate:1;
    uint8_t channel:1;
    uint8_t fhss:1;
    uint8_t dbm_antenna_sig:1; // antenna signal awlays 5th bits
    uint8_t dbm_antenna_noise:1;
    uint8_t lock_quality:1;
    uint8_t tx_attenuation:1;
    uint8_t db_tx_attenuation:1;
    uint8_t dbm_tx_power:1;
    uint8_t antenna:1;
    uint8_t db_antenna_sig:1;
    uint8_t db_antenna_noise:1;
    uint8_t rx_flags:1;
    uint8_t padding:3;
    uint8_t channel_plus:1;
    uint8_t mcs_info:1;
    uint8_t a_mpdu_stat:1;
    uint8_t vht_info:1;
    uint8_t frame_timestamp:1;
    uint8_t he_info:1;
    uint8_t he_mu_info:1;
    uint8_t padding2:1;
    uint8_t zero_len_psdu:1;
    uint8_t l_sig:1;
    uint8_t reserved:1;
    uint8_t radiotap_ns_next:1;
    uint8_t vendor_ns_next:1;
    uint8_t ext:1;
}Present_flags;

typedef struct radiotap_header_tmp{ 
    uint8_t h_revision;
    uint8_t h_pad;
    uint16_t h_len;
    Present_flags presnt_flags;
}radiotap_header_tmp;

#pragma pack(pop)