#pragma once

#include "include.h"


#pragma pack(push, 1)

namespace dot11_fc
{
    namespace type
    {
        enum : uint8_t // type
        {
            MANAGEMENT = 0x0,
            CONTROL = 0x1,
            DATA = 0x2
        };
    };

    namespace subtype
    {
        enum : uint8_t // type = MANAGEMENT
        {
            ASSO_REQ = 0x0,
            ASSO_RES = 0x1,
            REASSO_REQ = 0x2,
            REASSO_RES = 0x3,
            PROBE_REQ = 0x4,
            PROBE_RES = 0x5,
            TIMING_ADV = 0x6,
            RESERVERD_1 = 0x7,
            BEACON = 0x8,
            ATIM = 0x9,
            DISASSO = 0xa,
            AUTH = 0xb,
            DEAUTH = 0xc,
            ACTION = 0xd,
            NACK = 0xe,
            RESERVED_2 = 0xf
        };

        enum : uint8_t // type = CONTROL
        {
            RTS = 0xb,
            CTS = 0xc
        };

        enum : uint8_t // type = DATA
        {
            _NO_DATA = 0x4,
            QOS_DATA = 0xc
        };

    };


    namespace flags
    {
        enum : uint8_t // flags
        {
            TO_DS = 0x1,
            FROM_DS = 0x2,
            MORE_FRAG = 0x4,
            RETRY = 0x8,
            PWR_MGT = 0x10,
            MORE_DATA = 0x20,
            PROTECTED_FLAG = 0x40,
            ORDER_FLAG = 0x80
        };
    };
};

struct frame_control
{
    uint8_t version: 2,
        type: 2,
        subtype: 4;

    uint8_t flags;

};
typedef struct dot11_frame
{
    struct frame_control fc;
    uint16_t dur;
    MAC addr1;  //receiver addr
}dot11_frame;

typedef struct dot11_data_frame : dot11_frame
{
    MAC addr2;  //Transmitter address
    MAC addr3;
    uint16_t frag_num: 4,
        seq_num: 12;
    uint8_t * get_BSSID(void);

}dot11_data_frame;

typedef struct dot11_mgt_frame : dot11_frame
{
    MAC addr2;  //Transmitter address
    MAC addr3;
    uint16_t frag_num: 4,
        seq_num: 12;
    uint8_t * get_tag(uint8_t tag, int tags_len);
    uint8_t * get_BSSID(void);
}dot11_mgt_frame;

struct fixed_param
{
    uint64_t timestamp;
    uint16_t beacon_interval;
    uint16_t capabilities_info;
};

typedef struct dot11_beacon_frame : dot11_mgt_frame
{
    struct fixed_param fp;
    uint8_t * get_tag(uint8_t tag, int tags_len);

}dot11_beacon_frame;


typedef struct dot11_tagged_param
{
    uint8_t num;
    uint8_t len;
    uint8_t data;

    uint8_t * get_data(void) { return &data; }
    std::string get_ssid(void) {return std::string(&data, &data + len); }

}dot11_tagged_param;

typedef struct ap_info
{
    std::string BSSID; //key
    uint8_t antsignal;
    uint8_t channel;
    uint32_t cnt;
    std::string ESSID;



    void Print(void);
    std::string String(void);
}ap_info;

typedef struct station_info
{
    std::string BSSID;
    std::string STATION; // key
    uint8_t antsignal;
    uint32_t cnt;
    std::string probe;

    void Print(void);
}station_info;


typedef struct data_station_info
{
    std::string BSSID;
    std::string STATION;
    uint8_t antsignal;
    bool isAttack;

    void Print(void);
    std::string String(void);
}data_station_info;


typedef struct deauth
{

    uint8_t        it_version;     /* set to 0 */
    uint8_t        it_pad;
    uint16_t       it_len;         /* entire length */
    uint32_t       it_present;     /* fields present */

}Deauth;

uint8_t * set_deauth(uint8_t * target, uint8_t * addr);

struct auth_fixed_param
{
    uint16_t algorithm;
    uint16_t SEQ;
    uint16_t stat;
};



uint8_t* set_beacon(uint8_t * addr);

typedef struct dot11_authentication : dot11_mgt_frame
{
    struct auth_fixed_param fp;
    uint8_t * get_tag(uint8_t tag, int tags_len);

}dot11_authentication;

std::string mac_to_string(uint8_t * addr);
uint8_t * string_to_mac(uint8_t * addr);

bool check_dev(char *dev);

bool send_data(int client_sock, char *data);
bool recv_data(int client_sock, char *data);

#pragma pack(pop)


