#include "gqosnullhdr.h"

QosNullHdr* QosNullHdr::check(Dot11Hdr* dot11Hdr, uint32_t size) {
	assert(dot11Hdr->typeSubtype() == Dot11Hdr::QosNull);
	if (size < sizeof(QosNullHdr)) {
		GTRACE("invalid size %u\n", size);
		dump(puchar(dot11Hdr), size);
		return nullptr;
	}
	return PQosNullHdr(dot11Hdr);
}
