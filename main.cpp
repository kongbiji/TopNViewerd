#include "include.h"

typedef struct ap_map_info
{
    int channel;
    std::map<Mac, data_station_info> map_station;
} ap_map_info;

int debug_num;

static std::map<Mac, ap_map_info> ap_map;
static std::map<Mac, bool> ap_map_broadcast;

pcap_t *handle;
char dev[BUF_SIZE] = {0};
char errbuf[PCAP_ERRBUF_SIZE];

int client_sock;
int server_sock;
bool ap_active;
bool hopping_active;
bool staion_active;
std::vector<int> channel_list;

bool get_channel()
{
    char temp[BUF_SIZE] = {0};
    FILE *stream = popen("iwlist wlan0 channel", "r");

    std::string s = "";

    while (fgets(temp, BUF_SIZE, stream) != NULL)
    {
        s += temp;
    }

    // Check Network
    if (strcmp(temp, "") == 0)
    {
        return false;
    }

    std::regex re("(Channel) ([0-9]*)");
    std::sregex_iterator it(s.begin(), s.end(), re);
    std::sregex_iterator end;

    int i = 0;
    while (it != end)
    {
        std::smatch m = *it;
        channel_list.push_back(std::stoi(m.str(2)));
        // printf("%s\n", m.str(2).c_str());
        ++it;
        i++;
    }

    channel_list.pop_back();
    int k = 0;
    for(auto iter = channel_list.begin(); iter != channel_list.end(); ++iter){
        printf("channel >> %d\n", channel_list[k]);
        k++;
    }

    auto rng = std::default_random_engine{};
    std::shuffle(std::begin(channel_list), std::end(channel_list), rng);

    return true;
}

void hopping_func()
{
    std::string system_string;

    while (true)
    {
        for (int channel : channel_list)
        {
            if (hopping_active)
            {
                system_string = "iwconfig wlan0 channel " + std::to_string(channel);
                //printf("set channel >> %d\n", channel);
                system(system_string.c_str());
                usleep(1000000);
            }
        }
    }
}

void get_ap()
{

    while (ap_active)
    {
        struct pcap_pkthdr *header;
        const u_char *packet;
        int res = pcap_next_ex(handle, &header, &packet);

        if (res == 0)
            continue;
        if (res == -1 || res == -2)
            break;

        radiotap_header *rt_header = (radiotap_header *)(packet);
        dot11_mgt_frame *frame = (dot11_mgt_frame *)(packet + rt_header->it_len);

        if (frame->fc.type == dot11_fc::type::CONTROL)
        {
            continue;
        }

        //get station info
        if ((frame->fc.type == dot11_fc::type::DATA) &&
         (frame->fc.subtype == dot11_fc::subtype::_NO_DATA || frame->fc.subtype == dot11_fc::subtype::QOS_DATA))
        {
            dot11_data_frame *data_frame = (dot11_data_frame *)(packet + rt_header->it_len);

            if (ap_map.find(data_frame->get_BSSID()) == ap_map.end())
            {
                continue;
            }

            uint8_t selected_ap[6] = {0};

            memcpy(selected_ap, data_frame->get_BSSID(), 6);

            Mac BSSID = selected_ap;
            Mac STATION = data_frame->addr2;
            uint8_t antsignal = *rt_header->radiotap_present_flag(DBM_ANTSIGNAL);

            //append ap_map_broadcast
            if (ap_map_broadcast.find(data_frame->get_BSSID()) == ap_map_broadcast.end())
            {
                ap_map_broadcast[selected_ap] = false;
            }

            data_station_info d_s_info;
            d_s_info.BSSID = BSSID;
            d_s_info.STATION = STATION;
            d_s_info.antsignal = antsignal;
            d_s_info.isAttack = false;

            //            if (ap_map[selected_ap].map_station.find(STATION) == ap_map[selected_ap].map_station.end())
            {
                ap_map[selected_ap].map_station[STATION] = d_s_info;

                std::string buf_string;
                char data[BUF_SIZE] = {0};
                buf_string = d_s_info.String();

                memcpy(data, buf_string.c_str(), buf_string.length());

                send_data(client_sock, data);

                printf("send Station info %s\n", data);
            }
        }

        // AP
        if ((frame->fc.subtype == dot11_fc::subtype::BEACON) || (frame->fc.subtype == dot11_fc::subtype::PROBE_RES))
        {
            dot11_beacon_frame *beacon_frame = (dot11_beacon_frame *)(frame);
            int dot11_tags_len = header->len - (rt_header->it_len + sizeof(dot11_beacon_frame));

            Mac BSSID = frame->get_BSSID(); //key
            uint8_t antsignal = *rt_header->radiotap_present_flag(DBM_ANTSIGNAL);
            uint8_t channel = *((dot11_tagged_param *)beacon_frame->get_tag(3, dot11_tags_len))->get_data();
            //cnt
            std::string ESSID = ((dot11_tagged_param *)beacon_frame->get_tag(0, dot11_tags_len))->get_ssid();

            ap_info temp_ap_info;
            temp_ap_info.BSSID = BSSID;
            temp_ap_info.antsignal = antsignal;
            temp_ap_info.channel = channel;
            temp_ap_info.ESSID = ESSID;

            //            if (ap_map.find(BSSID) == ap_map.end())
            {
                temp_ap_info.cnt = 1;

                std::string buf_string = "";
                char data[BUF_SIZE] = {0};

                buf_string = temp_ap_info.String();
                memset(data, 0x00, BUF_SIZE);
                memcpy(data, buf_string.c_str(), BUF_SIZE);

                std::vector<int>::iterator it;
                it = find(channel_list.begin(), channel_list.end(), channel);

                if (it != channel_list.end())
                {
                    send_data(client_sock, data);
                    ap_map[BSSID].channel = channel;
                }
            }

            // send TIM.aid
            if (frame->fc.subtype == dot11_fc::subtype::BEACON)
            {
                if (*(beacon_frame->get_tag(5, dot11_tags_len) + 5) == 0)
                {
                    memset(beacon_frame->get_tag(5, dot11_tags_len) + 5, 0xFF, 1);
                    beacon_frame->seq_num += 0b1;

                    usleep(90000); // 9000 10 2000
                    for (int i = 0; i < 10; i++)
                    {
                        if (pcap_sendpacket(handle, packet, header->caplen) != 0)
                        {
                            printf("error\n");
                        }
                        usleep(2000);
                    }
                }
            }
        }
    }
}

int main(int argc, char *argv[])
{
    int server_port = 9998;

    //socket connection
    {
        if ((server_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
        {
            printf("socket create error\n");
            return -1;
        }

        int option = 1;
        if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option)) < 0)
        {
            printf("socket option set error\n");
            return -1;
        }

        struct sockaddr_in server_addr, client_addr;
        memset(&server_addr, 0x00, sizeof(server_addr));
        memset(&client_addr, 0x00, sizeof(client_addr));
        int client_addr_size = sizeof(client_addr);
        server_addr.sin_addr.s_addr = INADDR_ANY;
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(server_port);

        if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
        {
            printf("bind error\n");
            return -1;
        }

        if (listen(server_sock, 5) < 0)
        {
            printf("listen error\n");
            return -1;
        }

        if ((client_sock = accept(server_sock, (struct sockaddr *)&client_addr, (socklen_t *)&client_addr_size)) < 0)
        {
            printf("accept error\n");
        }

        printf("connection ok\n");
    }

    //pcap open
    {
        memcpy(dev, "wlan0", 5);
        handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

        if (handle == NULL)
        {
            printf("fail open_offline...%s\n", errbuf);
            return -1;
        }
    }

    //switch
    {
        char buf[BUF_SIZE] = {0};
        char data[BUF_SIZE] = {0};

        //channel hopping
        get_channel();

        hopping_active = false;
        std::thread t = std::thread(hopping_func);
        t.detach();

        sleep(1);

        while (true)
        {
            memset(buf, 0x00, BUF_SIZE);
            recv_data(client_sock, buf);

            if (strlen(buf) == 0)
            {
                continue;
            }

            printf("recv data >> %s\n", buf);

            memset(data, 0x00, BUF_SIZE);

            if (!memcmp(buf, "1", 1)) // scan start
            {
                // ap_active = true;
                // hopping_active = true;
                // std::thread t = std::thread(get_ap);
                // t.detach();
            }
            else if (!memcmp(buf, "2", 1)) // hopping start
            {
                hopping_active = true;
                ap_active = true;
                hopping_active = true;
                std::thread t = std::thread(get_ap);
                t.detach();
            }
            else if (!memcmp(buf, "3", 1)) // hopping stop
            {
                hopping_active = false;
            }
            else if (!memcmp(buf, "4", 1)) // set channel
            {
                memset(buf, 0x00, BUF_SIZE);
                recv_data(client_sock, buf);
                std::string system_string;
                std::string channel = buf;
                printf("check channel >> %s\n", channel.c_str());
                system_string = "iwconfig wlan0 channel " + channel;
                usleep(1000000);
                system(system_string.c_str());
            }
            else
            {
                printf("switch error\n");
                break;
            }
        }
    }

    pcap_close(handle);

    return 0;
}
