#pragma once

#include "gradiotaphdr.h"

struct Dot11Hdr {
	le8_t ver_:2;
	le8_t type_:2;
	le8_t subtype_:4;
	le8_t flags_;
	le16_t duration_;

	le8_t typeSubtype() { return type_ << 4 | subtype_; }

	// type
	enum: le8_t {
		Manage = 0,
		Control = 1,
		Data = 2
	};

	// typeSubtype
	enum: le8_t {
		Beacon = 0x08,
		QosNull = 0x2C,
		Acknowledgement = 0x1D
	};

	static Dot11Hdr* check(RadiotapHdr* radiotapHdr, uint32_t size);
} __attribute__((packed));
typedef Dot11Hdr *PDot11Hdr;
