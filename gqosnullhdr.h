#pragma once

#include "gdot11hdr.h"

struct QosNullHdr : Dot11Hdr {
	Mac addr1_;
	Mac addr2_;
	Mac addr3_;
	le8_t frag_:4;
	le16_t seq_:12;
	le16_t qosControl_;

	Mac ra() { return addr1_; }
	Mac ta() { return addr2_; }
	Mac da() { return addr3_; }
	Mac sa() { return addr2_; }
	Mac bssid() { return addr1_; }
	Mac sta() { return addr2_; }

	static QosNullHdr* check(Dot11Hdr* dot11Hdr, uint32_t size);
} __attribute__((packed));
typedef QosNullHdr *PQosNullHdr;
