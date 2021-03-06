#pragma once

#include "gdot11hdr.h"

struct BeaconHdr : Dot11Hdr {
	Mac addr1_;
	Mac addr2_;
	Mac addr3_;
	le8_t frag_:4;
	le16_t seq_:12;

	Mac ra() { return addr1_;}
	Mac da() { return addr1_; }
	Mac ta() { return addr2_; }
	Mac sa() { return addr2_; }
	Mac bssid() { return addr3_; }

	//#pragma pack(push, 1)
	struct __attribute__((packed)) Fix {
		le64_t timestamp_; // microsecond
		le16_t beaconInterval_; // millisecond
		le16_t capabilities_;
	} fix_;
	//#pragma pack(pop)

	struct Tag {
		le8_t num_;
		le8_t len_;
		Tag* next() {
			char* res = (char*)this;
			res += sizeof(Tag) + this->len_;
			return PTag(res);
		}
	};
	typedef Tag *PTag;
	Tag* tag() {
		char* p = pchar(this);
		p += sizeof(BeaconHdr);
		return PTag(p);
	}

	// tagged parameter number
	enum: le8_t {
		tagSsidParameterSet = 0,
		tagSupportedRated = 1,
		tagTrafficIndicationMap = 5
	};

	struct TrafficIndicationMap : Tag {
		le8_t count_;
		le8_t period_;
		le8_t control_;
		le8_t bitmap_;
	};
	typedef TrafficIndicationMap *PTrafficIndicationMap;

	static BeaconHdr* check(Dot11Hdr* dot11Hdr, uint32_t size);
	TrafficIndicationMap* getTim(uint32_t size);
} __attribute__((packed));
typedef BeaconHdr *PBeaconHdr;

