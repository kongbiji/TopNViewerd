#pragma once

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <iostream>
#include <list>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <thread>
#include <unistd.h>
#include <set>
#include <string>
#include <vector>
#include <pcap.h>
#include <map>
#include <regex>
#include <algorithm>
#include <random>
#include "gtrace.h"
#include "mac.h"
#include "radiotap.h"
#include "dot11.h"

static const int BUF_SIZE=1024;
