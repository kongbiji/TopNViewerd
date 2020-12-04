#include "gssg.h"

int debug = 0;

bool Ssg::BeaconFrame::init(BeaconHdr* beaconHdr, uint32_t size) {
	if (size > DummySize) {
		GTRACE("Too big beacon frame size(%d)\n", size);
		return false;
	}
	radiotapHdr_.len_ = sizeof(RadiotapHdr);
	radiotapHdr_.pad_ = 0;
	radiotapHdr_.ver_ = 0;
	radiotapHdr_.present_ = 0;
	memcpy((void*)&beaconHdr_, (void*)beaconHdr, size);
	size_ = size;
	return true;
}

void Ssg::BeaconFrame::send(pcap_t* handle) {
	int res = pcap_sendpacket(handle, (const u_char*)&radiotapHdr_, size_);
	static int count = 0;
	if (count++ % 100 == 0) GTRACE("pcap_sendpacket %u return %d\n", size_, res); // gilgil temp 2020.11.09
	if (res != 0) {
		GTRACE("pcap_sendpacket return %d - %s handle=%p size_=%u\n", res, pcap_geterr(handle), handle, size_);
	}
}

void Ssg::ApInfo::adjustOffset(Diff adjustOffset) {
	adjustOffset_ = adjustOffset;
}

void Ssg::ApInfo::adjustInterval(Diff adjustInterval) {
	adjustInterval_ = adjustInterval;
}

bool Ssg::open() {
	if (active_) return false;

	scanThread_ = new std::thread(_scanThread, this);
	if (!option_.checkOnly_)
		sendThread_ = new std::thread(_sendThread, this);
	deleteThread_ = new std::thread(_deleteThread, this);

	active_ = true;
	return true;
}

bool Ssg::close() {
	if (!active_) return false;
	active_ = false;

	wait();

	if (scanThread_ != nullptr) {
		delete scanThread_;
		scanThread_ = nullptr;
	}
	if (sendThread_ != nullptr) {
		delete sendThread_;
		sendThread_ = nullptr;
	}
	if (deleteThread_ != nullptr) {
		delete deleteThread_;
		deleteThread_ = nullptr;
	}

	return true;
}

void Ssg::wait() {
	if (scanThread_ != nullptr)
		scanThread_->join();
	if (sendThread_ != nullptr)
		sendThread_->join();
	if (deleteThread_ != nullptr)
		deleteThread_->join();
}

void Ssg::_scanThread(Ssg* ssg) {
	ssg->scanThread();
	ssg->active_ = false;
}

void Ssg::scanThread() {
	GTRACE("scanThread beg\n");
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(interface_.c_str(), 11000, 1, 1, errbuf);
	if (handle == nullptr) {
		GTRACE("pcap_open_live(%s) return null - %s\n", interface_.c_str(), errbuf);
		return;
	}

	if (filter_ != "") {
		u_int uNetMask = 0xFFFFFFFF;;
		bpf_program code;

		if (pcap_compile(handle, &code, filter_.c_str(), 1, uNetMask) < 0) {
			GTRACE("error in pcap_compile(%s)\n", pcap_geterr(handle));
			pcap_close(handle);
			return;
		}
		if (pcap_setfilter(handle, &code) < 0) {
			GTRACE("error in pcap_setfilter(%s)\n", pcap_geterr(handle));
			pcap_close(handle);
			return;
		}
	}

	while (active_) {
		pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == -1 || res == -2) {
			GTRACE("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}

		uint32_t size = header->caplen;
		RadiotapHdr* radiotapHdr = RadiotapHdr::check(pchar(packet), size);
		if (radiotapHdr == nullptr) continue;
		le16_t rlen = radiotapHdr->len_;
		// ----- gilgil temp -----
		//GTRACE("radiotapHdr->len_=%u\n", rlen);
		//if (rlen == option_.rt_.send_) {
		//	GTRACE("my sending\n");
		//}
		// -----------------------
		if (radiotapHdr->isShortPreamble()) continue; // if (rlen == lc_.ignore_) continue; // gilgil temp 2020.11.07
		size -= radiotapHdr->len_;

		Dot11Hdr* dot11Hdr = Dot11Hdr::check(radiotapHdr, size);
		if (dot11Hdr == nullptr) continue;

		//
		// QosNull check
		//
		le8_t typeSubtype = dot11Hdr->typeSubtype();
		if (typeSubtype == Dot11Hdr::QosNull) {
			if (!option_.debugQosNull_) continue;
			QosNullHdr* qosNullHdr = QosNullHdr::check(dot11Hdr, size);
			if (qosNullHdr == nullptr) continue;
				processQosNull(qosNullHdr);
			continue;
		}

		if (typeSubtype != Dot11Hdr::Beacon) continue;
		BeaconHdr* beaconHdr = BeaconHdr::check(dot11Hdr, size);
		if (beaconHdr == nullptr) continue;
		Mac bssid = beaconHdr->bssid();

		BeaconHdr::TrafficIndicationMap* tim = beaconHdr->getTim(size);
		if (tim == nullptr) continue;

		{
			std::lock_guard<std::mutex> guard(apMap_.mutex_);
			ApMap::iterator it = apMap_.find(bssid);

			if (it == apMap_.end()) {
				GTRACE("New AP(%s) added\n", std::string(bssid).c_str());
				tim->control_ = option_.tim_.control_;
				tim->bitmap_ = option_.tim_.bitmap_;
				ApInfo apInfo;
				if (!apInfo.beaconFrame_.init(beaconHdr, sizeof(RadiotapHdr) + size)) continue;
				apInfo.sendInterval_ = Diff(beaconHdr->fix_.beaconInterval_ * 1024000);
				apInfo.nextFrameSent_ = Timer::now() + apInfo.sendInterval_;
				apMap_.insert({bssid, apInfo});
				it = apMap_.find(bssid);
				assert(it != apMap_.end());
			}
			ApInfo& apInfo = it->second;
			SeqInfo seqInfo;
			seqInfo.seq_ = beaconHdr->seq_;
			seqInfo.ok_ = true;
			seqInfo.tv_ = header->ts;
			seqInfo.rlen_ = rlen;
			seqInfo.control_ = tim->control_;
			seqInfo.bitmap_ = tim->bitmap_;
			if (rlen != sizeof(RadiotapHdr)) apInfo.lastAccess_ = Timer::now();
			processAp(apInfo, beaconHdr->seq_, seqInfo);
		}
	}
	pcap_close(handle);
	GTRACE("scanThread end\n");
}

void Ssg::_sendThread(Ssg* ssg) {
	ssg->sendThread();
	ssg->active_ = false;
}

void Ssg::sendThread() {
	GTRACE("sendThread beg\n");
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(interface_.c_str(), 11000, 1, 1, errbuf);
	if (handle == nullptr) {
		GTRACE("pcap_open_live(%s) return null - %s\n", interface_.c_str(), errbuf);
		return;
	}

	while (active_) {
		Clock now = Timer::now();
		apMap_.mutex_.lock();
		for (ApMap::iterator it = apMap_.begin(); it != apMap_.end(); it++) {
			ApInfo& apInfo = it->second;
			if (apInfo.adjustOffset_ != Diff(0)) {
				apInfo.nextFrameSent_+= apInfo.adjustOffset_;
				apInfo.adjustOffset_ = Diff(0);
			}
			if (apInfo.adjustInterval_ != Diff(0)) {
				apInfo.sendInterval_ += apInfo.adjustInterval_;
				std::string bssid = std::string(it->first);
				printf("%s sendInterval=%f\n", bssid.c_str(), double(apInfo.sendInterval_.count()) / 1000000);
				apInfo.adjustInterval_ = Diff(0);
			}
			if (now >= apInfo.nextFrameSent_ + option_.sendOffset_) {
				le16_t seq = apInfo.beaconFrame_.beaconHdr_.seq_;
				seq++;
				apInfo.beaconFrame_.beaconHdr_.seq_ = seq;
				apInfo.beaconFrame_.send(handle);
				// ----- gilgil temp -----
				//{
				//	std::string bssid = std::string(it->first);
				//	GTRACE("sending beacon %s seq=%d\n", bssid.c_str(), seq); // gilgil temp
				//	apInfo.nextFrameSent_ = now + apInfo.sendInterval_;
				//}
				// -----------------------
				apInfo.nextFrameSent_ += apInfo.sendInterval_;
			}
		}

		now = Timer::now();
		Diff minWaitTime = option_.sendPollingTime_ * 2;
		for (ApMap::iterator it = apMap_.begin(); it != apMap_.end(); it++) {
			ApInfo& apInfo = it->second;
			Diff diff = apInfo.nextFrameSent_ - now;
			if (minWaitTime < diff)
				minWaitTime = diff;
		}
		apMap_.mutex_.unlock();

		minWaitTime /= 2;
		minWaitTime -= option_.sendPollingTime_;
		if (minWaitTime > Diff(0))
			std::this_thread::sleep_for(minWaitTime);
	}
	pcap_close(handle);
	GTRACE("sendThread end\n");
}

void Ssg::_deleteThread(Ssg* ssg) {
	ssg->deleteThread();
	ssg->active_ = false;
}

void Ssg::deleteThread() {
	GTRACE("deleteThread beg\n");
	while (active_) {
		std::this_thread::sleep_for(std::chrono::seconds(1));
		Clock now = Timer::now();
		apMap_.mutex_.lock();
		ApMap::iterator it = apMap_.begin();
		while (true) {
			if (it == apMap_.end()) break;
			ApInfo& apInfo = it->second;
			Diff diff = now - apInfo.lastAccess_;
			// std::string bssid = std::string(it->first); GTRACE("%s diff=%f\n", bssid.c_str(), double(diff.count()) / 100000); // gilgil temp
			if (diff > option_.tooOldApDiff_) {
				std::string bssid = std::string(it->first);
				GTRACE("%s Delete old AP\n", bssid.c_str());
				it = apMap_.erase(it);
			} else
				it++;
		}
		apMap_.mutex_.unlock();
	}
	GTRACE("deleteThread end\n");
}

void Ssg::processQosNull(QosNullHdr* qosNullHdr) {
	apMap_.mutex_.lock();
	Mac bssid = qosNullHdr->bssid();
	if (apMap_.find(bssid) != apMap_.end()) {
		printf("                                                                 QosNull bssid=%s sta=%s\n",
			std::string(qosNullHdr->bssid()).c_str(),
			std::string(qosNullHdr->sta()).c_str());
	}
	apMap_.mutex_.unlock();
}

void Ssg::processAp(ApInfo& apInfo, le16_t seq, SeqInfo seqInfo) {
	SeqMap& seqMap = apInfo.seqMap_;
	SeqMap::iterator it = seqMap.find(seq);
	if (it == seqMap.end()) {
		SeqInfoPair seqInfos;
		seqMap.insert({seq, seqInfos});
		it = seqMap.find(seq);
		assert(it != seqMap.end());
	}
	SeqInfoPair& seqInfoPair = it->second;

	bool sendPacket = seqInfo.control_ == option_.tim_.control_ && seqInfo.bitmap_ == option_.tim_.bitmap_;
	if (sendPacket) {
		seqInfo.tv_ = getAddTime(seqInfo.tv_, -option_.sendOffset_.count());
		seqInfoPair.sendInfo_ = seqInfo;
	} else
		seqInfoPair.realInfo_ = seqInfo;

	if (!seqInfoPair.isOk()) return;

	int64_t diffTime = getDiffTime(seqInfoPair.realInfo_.tv_, seqInfoPair.sendInfo_.tv_);
	if (diffTime > option_.tooOldSeqDiff_) { // send is too old
		GTRACE("send is too old(%f us)\n", double(diffTime) / 1000000);
		seqInfoPair.sendInfo_.clear();
		return;
	}
	if (diffTime < -option_.tooOldSeqDiff_) { // real is too old
		GTRACE("real is too old(%f us)\n", double(diffTime) / 100000);
		seqInfoPair.realInfo_.clear();
		return;
	}
	if (!seqMap.firstOk_) {
		seqMap.firstOk_ = true;
		seqMap.firstIterator_ = it;
	}

	if (option_.checkOnly_) {
		std::string bssid = std::string(apInfo.beaconFrame_.beaconHdr_.bssid());
		timeval sendTv = seqInfoPair.sendInfo_.tv_;
		timeval realTv = seqInfoPair.realInfo_.tv_;
		int64_t diff = getDiffTime(sendTv, realTv);
		le8_t control = seqInfoPair.sendInfo_.control_;
		le8_t bitmap = seqInfoPair.sendInfo_.bitmap_;
		printf("%s seq=%4d diff=%f(ms) ctl=%02X bitmap=%02X\n", bssid.c_str(), seq, double(diff) / 1000, control, bitmap);
		seqMap.erase(it);
		return;
	}

	if (!seqMap.firstOk_) return;
	assert(seqMap.firstIterator_ != seqMap.end());
	SeqInfoPair& first = seqMap.firstIterator_->second;
	SeqInfoPair& last = seqInfoPair;

	bool adjust = false;
	if (first.isOk() && last.isOk()) {
		int64_t diff = getDiffTime(last.sendInfo_.tv_, first.sendInfo_.tv_);
		if (diff > option_.adjustInterval_)
			adjust = true;
	}
	if (!adjust) return;

	//
	// seq send real
	// 100 1010 1000
	// 101 1019 1011
	// 102 1030 1022
	// 103 1040 1033
	//
	// adjustOffset = -13 : (1033- 1040)
	// adjustInterval = -1 : ((1033 - 1000) - (1040 - 1010)) / 3
	//

	timeval firstRealTv = first.realInfo_.tv_;
	timeval firstSendTv = first.sendInfo_.tv_;
	timeval lastRealTv = last.realInfo_.tv_;
	timeval lastSendTv = last.sendInfo_.tv_;

	le16_t firstSeq = seqMap.firstIterator_->first;
	le16_t lastSeq = seq;
	int16_t seqDiff = int16_t(lastSeq - firstSeq);
	assert(seqDiff != 0);
	if (seqDiff < 0) { // if sequence nuber overflowed
		GTRACE("seq overflowed first=%d last=%d\n", firstSeq, lastSeq);
		seqDiff = -seqDiff;
		std::swap(firstSeq, lastSeq);
		std::swap(firstRealTv, lastRealTv);
		std::swap(firstSendTv, lastSendTv);
	}

	int64_t adjustOffset = getDiffTime(lastRealTv, lastSendTv) * 1000; // nsec

	int64_t realDiff = getDiffTime(lastRealTv, firstRealTv) * 1000; // nsec
	int64_t sendDiff = getDiffTime(lastSendTv, firstSendTv) * 1000; // nsec
	int64_t adjustInterval = (realDiff - sendDiff) / seqDiff; // nsec
	{
		std::string bssid = std::string(apInfo.beaconFrame_.beaconHdr_.bssid());
		printf("%s realDiff=%f(s) sendDiff=%f(s) seqDiff=%d adjustOffset=%f(ms) adjustInterval=%f(ms)\n",
			bssid.c_str(),
			double(realDiff) / 1000000000,
			double(sendDiff) / 1000000000,
			seqDiff,
			double(adjustOffset) / 1000000,
			double(adjustInterval) / 1000000);
	}
	adjustInterval *= option_.changeIntervalAlpha_;

	apInfo.adjustOffset(Diff(adjustOffset));
	apInfo.adjustInterval(Diff(adjustInterval));

	seqMap.clear();
}

int64_t Ssg::getDiffTime(timeval tv1, timeval tv2) {
	int64_t res = (tv1.tv_sec - tv2.tv_sec) * 1000000;
	res += (tv1.tv_usec - tv2.tv_usec);
	return res;
}

timeval Ssg::getAddTime(timeval tv, int64_t nsec) {
	timeval added;
	int64_t usec = nsec / 1000;
	added.tv_sec = usec / 1000000;
	added.tv_usec = usec % 1000000;
	tv.tv_sec += added.tv_sec;
	tv.tv_usec += added.tv_usec;
	if (tv.tv_usec > 1000000) {
		tv.tv_sec++;
		tv.tv_usec -= 1000000;
	} else if (tv.tv_sec < - 1000000) {
		tv.tv_sec--;
		tv.tv_usec += 1000000;
	}

	return tv;
}
