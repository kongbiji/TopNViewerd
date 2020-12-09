#include "include.h"

typedef struct ap_map_info
{
    int channel;
    std::map<MAC, data_station_info> map_station;
} ap_map_info;

int debug_num;

static std::map<MAC, ap_map_info> ap_map;
static std::map<MAC, bool> ap_map_broadcast;

int client_sock;
int server_sock;
volatile bool ap_active;
volatile bool hopping_active;
volatile bool station_active;
volatile bool set_channel_active;

int current_channel;

pcap_t *ap_handle;
pcap_t *station_handle;

std::vector<int> channel_list;
std::string apmac;
int channel_index = 0;

std::thread * t_hopping_chan {nullptr};
std::thread * t_get_ap {nullptr};
std::thread * t_get_station {nullptr};
std::thread * t_set_channel {nullptr};

bool get_channel()
{
    char temp[BUF_SIZE] = {0};
    FILE *stream = popen("./iwlist wlan0 channel", "r");

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
        ++it;
        i++;
    }

    channel_list.pop_back();

    if(channel_list.size() % 5 == 0){
        channel_list.push_back(1);
    }

    int k = 0;
    char channel_str[1024] = {0,};
    for(auto iter = channel_list.begin(); iter != channel_list.end(); ++iter){
        char tmp_channel[5] = {0};
        sprintf(tmp_channel, "%d/", channel_list[k]);
        strcat(channel_str, tmp_channel);
        k++;
    }
    GTRACE("channel list : %s", channel_str);
    
    return true;
}

void set_channel(){
    GTRACE("set channel thread start.");
    std::string system_string;

    system_string = "./iwconfig wlan0 channel " + std::to_string(current_channel);

    while (hopping_active)
    {
        system(system_string.c_str());
        usleep(1000000);
    }
    GTRACE("set channel thread end.");
}

void hopping_func()
{
    GTRACE("hopping thread start.");
    std::string system_string;

    int index = channel_index;

    while (hopping_active)
    {
        system_string = "./iwconfig wlan0 channel " + std::to_string(channel_list[index]);
        system(system_string.c_str());
        GTRACE("%s", system_string.c_str());
        index = (index + 5) % channel_list.size();
        usleep(600000);
    }
    GTRACE("hopping thread end.");
}

void get_station(){
    char dev[BUF_SIZE] = {0};
    char errbuf[PCAP_ERRBUF_SIZE];
    memcpy(dev, "wlan0", 5);
    station_handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    char buf[1024];
    memset(buf, 0x00, BUF_SIZE);
    if (station_handle == NULL)
    {
        memcpy(buf, "5", 1);
        send_data(client_sock, buf);
        GTRACE("pcap_open_live() failed.");
        exit(1);
    }
    GTRACE("pcap_open_live() success.");
    memcpy(buf, "6", 1);
    send_data(client_sock, buf);

    Ssg ssg;
    ssg.interface_ = "wlan0";
    ssg.filter_ = "ether host " + apmac;
    ssg.open();


    while (station_active)
    {
        struct pcap_pkthdr *header;
        const u_char *packet;
        int res = pcap_next_ex(station_handle, &header, &packet);

        if (res == 0)
            continue;
        if (res == -1 || res == -2){
            GTRACE("pcap_next_ex() failed.");
            system("su -c \"ifconfig wlan0 down\"");
            system("export LD_PRELOAD=/system/lib/libfakeioctl.so");
            system("su -c \"nexutil -m2\"");
            system("su -c \"ifconfig wlan0 up\"");
            GTRACE("set monitor mode again.");
            continue;
        }

        radiotap_header *rt_header = (radiotap_header *)(packet);
        if(rt_header->it_len < sizeof(radiotap_header) || rt_header->it_len > header->caplen){
            continue;
        }

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

            MAC BSSID = selected_ap;
            MAC STATION = data_frame->addr2;
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

            {
                ap_map[selected_ap].map_station[STATION] = d_s_info;

                std::string buf_string;
                char data[BUF_SIZE] = {0};
                buf_string = d_s_info.String();

                memcpy(data, buf_string.c_str(), buf_string.length());

                send_data(client_sock, data);
            }
        }

    }
    ssg.close();
    pcap_close(station_handle);
    GTRACE("pcap_close().");

}

void get_ap()
{
    char dev[BUF_SIZE] = {0};
    char errbuf[PCAP_ERRBUF_SIZE];
    memcpy(dev, "wlan0", 5);
    ap_handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    char buf[1024];
    memset(buf, 0x00, BUF_SIZE);
    if (ap_handle == NULL)
    {
        memcpy(buf, "5", 1);
        send_data(client_sock, buf);
        GTRACE("pcap_open_live() failed.");
        exit(1);
    }
    GTRACE("pcap_open_live() success.");
    memcpy(buf, "6", 1);
    send_data(client_sock, buf);

    while (ap_active)
    {
        struct pcap_pkthdr *header;
        const u_char *packet;
        int res = pcap_next_ex(ap_handle, &header, &packet);

        if (res == 0)
            continue;
        if (res == -1 || res == -2){
            GTRACE("pcap_next_ex() failed.");
            system("su -c \"ifconfig wlan0 down\"");
            system("export LD_PRELOAD=/system/lib/libfakeioctl.so");
            system("su -c \"nexutil -m2\"");
            system("su -c \"ifconfig wlan0 up\"");
            GTRACE("set monitor mode again.");
            continue;
        }
            

        radiotap_header *rt_header = (radiotap_header *)(packet);
        if(rt_header->it_len < sizeof(radiotap_header) || rt_header->it_len > header->caplen){
            continue;
        }

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

            MAC BSSID = selected_ap;
            MAC STATION = data_frame->addr2;
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

            {
                ap_map[selected_ap].map_station[STATION] = d_s_info;

                std::string buf_string;
                char data[BUF_SIZE] = {0};
                buf_string = d_s_info.String();

                memcpy(data, buf_string.c_str(), buf_string.length());

                send_data(client_sock, data);
            }
        }

        // AP
        if ((frame->fc.subtype == dot11_fc::subtype::BEACON) || (frame->fc.subtype == dot11_fc::subtype::PROBE_RES))
        {
            dot11_beacon_frame *beacon_frame = (dot11_beacon_frame *)(frame);
            int dot11_tags_len = header->len - (rt_header->it_len + sizeof(dot11_beacon_frame));

            MAC BSSID = frame->get_BSSID(); //key
            uint8_t antsignal = *rt_header->radiotap_present_flag(DBM_ANTSIGNAL);
            uint8_t channel = *((dot11_tagged_param *)beacon_frame->get_tag(3, dot11_tags_len))->get_data();
            //cnt
            std::string ESSID = ((dot11_tagged_param *)beacon_frame->get_tag(0, dot11_tags_len))->get_ssid();

            ap_info temp_ap_info;
            temp_ap_info.BSSID = BSSID;
            temp_ap_info.antsignal = antsignal;
            temp_ap_info.channel = channel;
            temp_ap_info.ESSID = ESSID;

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
                        if (pcap_sendpacket(ap_handle, packet, header->caplen) != 0)
                        {
                        }
                        usleep(2000);
                    }
                }
            }
        }
    }
    ap_active = false;
    pcap_close(ap_handle);
    GTRACE("pcap_close().");
}

int main(int argc, char *argv[])
{
    gtrace_close();
    gtrace_open("127.0.0.1", 8908, false, "topnviewerd.log");
    int server_port = 2345;

    GTRACE("topnviewerd start.");
    system("su -c \"ifconfig wlan0 down\"");
    system("export LD_PRELOAD=/system/lib/libfakeioctl.so");
    system("su -c \"nexutil -m2\"");
    system("su -c \"ifconfig wlan0 up\"");
    GTRACE("set monitor mode.");

    //socket connection
    {
        if ((server_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
        {
            GTRACE("socket() failed.");
            return -1;
        }
        GTRACE("socket() success.");

        int option = 1;
        if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option)) < 0)
        {
            GTRACE("setsockopt() failed.");
            return -1;
        }
        GTRACE("setsockopt() success.");

        struct sockaddr_in server_addr, client_addr;
        memset(&server_addr, 0x00, sizeof(server_addr));
        memset(&client_addr, 0x00, sizeof(client_addr));
        int client_addr_size = sizeof(client_addr);
        server_addr.sin_addr.s_addr = INADDR_ANY;
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(server_port);

        if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
        {
            GTRACE("bind() failed.");
            return -1;
        }
        GTRACE("bind() success.");

        if (listen(server_sock, 5) < 0)
        {
            GTRACE("listen() failed.");
            return -1;
        }
        GTRACE("listen() success.");

        if ((client_sock = accept(server_sock, (struct sockaddr *)&client_addr, (socklen_t *)&client_addr_size)) < 0)
        {
            GTRACE("accept() failed.");
            return -1;
        }
        GTRACE("accept() success.");

    }

    //switch
    {
        char buf[BUF_SIZE] = {0};
        char data[BUF_SIZE] = {0};

        //channel hopping
        get_channel();

        hopping_active = false;

        while (true)
        {
            memset(buf, 0x00, BUF_SIZE);
            recv_data(client_sock, buf);

            if (strlen(buf) == 0)
            {
                continue;
            }

            memset(data, 0x00, BUF_SIZE);
            if (!memcmp(buf, "1", 1)) // hopping start
            {}
            else if (!memcmp(buf, "2", 1)) // hopping start
            {
                station_active = false;
                if(t_get_station == nullptr){
                    GTRACE("t_get_station (nullptr)");
                }else{
                    t_get_station->join();
                    delete t_get_station;
                    t_get_station = nullptr;
                }

                set_channel_active = false;
                if(t_set_channel == nullptr){
                    GTRACE("t_get_station (nullptr)");
                }else{
                    t_set_channel->join();
                    delete t_set_channel;
                    t_set_channel = nullptr;
                }

                hopping_active = true;
                ap_active = true;
                if(t_hopping_chan != nullptr){
                    GTRACE("Failed to create hopping thread.(nullptr)");
                    hopping_active = false;
                }
                else t_hopping_chan = new std::thread(hopping_func);

                if(t_get_ap != nullptr){
                    GTRACE("Failed to create get_ap thread.(nullptr)");
                    ap_active = false;
                }
                else t_get_ap = new std::thread(get_ap);
            }
            else if (!memcmp(buf, "3", 1)) // hopping stop
            {
                hopping_active = false;
                if(t_hopping_chan == nullptr){
                    GTRACE("Failed to join hopping thread.(nullptr)");
                }else{
                    t_hopping_chan->join();
                    delete t_hopping_chan;
                    t_hopping_chan = nullptr;
                }

                ap_active = false;
                if(t_get_ap == nullptr){
                    GTRACE("Failed to join get_ap thread.(nullptr)");
                }else{
                    t_get_ap->join();
                    delete t_get_ap;
                    t_get_ap = nullptr;
                }
            }
            else if (!memcmp(buf, "4", 1)) // set channel
            {
                memset(buf, 0x00, BUF_SIZE);
                recv_data(client_sock, buf);
                std::string system_string;
                std::string channel = buf;
                current_channel = atoi(buf);
                recv_data(client_sock, buf);
                std::string str(buf);
                apmac = buf;
                system_string = "./iwconfig wlan0 channel " + channel;
                usleep(1000000);
                system(system_string.c_str());
                station_active = true;
                set_channel_active = true;

                if(t_get_station != nullptr){
                    GTRACE("Failed to create get_station thread.(nullptr)");
                    station_active = false;
                }
                else t_get_station = new std::thread(get_station);

                if(t_set_channel != nullptr){
                    GTRACE("Failed to create get_station thread.(nullptr)");
                    set_channel_active = false;
                }
                else t_set_channel = new std::thread(set_channel);
            }
            else
            {
                break;
            }
        }
    }
    close(client_sock);
    close(server_sock);
    GTRACE("End of program.");
    return 0;
}
