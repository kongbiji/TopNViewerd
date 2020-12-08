#pragma once

#include <atomic>
#include <chrono>
#include <mutex>
#include <thread>
#include <unordered_map>

#include <pcap.h>
#include "gbeaconhdr.h"
#include "gqosnullhdr.h"

struct Ssg { // Station Signal Generator
	struct {
		struct TrafficIndicationMapOption {
			le8_t control_{1};
			le8_t bitmap_{0xFF};
		} tim_;
		int64_t adjustInterval_{10000000}; // usec (10 sec)
		Diff sendOffset_{Diff(0)}; // nsec (0 msec)
		int64_t tooOldSeqDiff_{10000000}; // usec (10 sec)
		Diff sendPollingTime_{Diff(1000000)}; // nsec (1000 usec)
		Diff tooOldApDiff_{Diff(15000000000)}; // nsec (15 sec)
		double changeIntervalAlpha_{0}; // {0.1};
		bool debugQosNull_{false};
		bool checkOnly_{false};
		int fcsSize_{0}; // 0 byte
	} option_;

	struct BeaconFrame {
		static const int DummySize = 8192;
		RadiotapHdr radiotapHdr_;
		BeaconHdr beaconHdr_;
		char dummy_[DummySize];
		uint32_t size_;

		bool init(BeaconHdr* beaconHdr, uint32_t size);
		void send(pcap_t* handle);
	} __attribute__((packed));

	struct SeqInfo {
		SeqInfo() { clear(); }
		le16_t seq_;
		bool ok_;
		timeval tv_;
		le16_t rlen_; // radiotap len;
		le8_t control_;
		le8_t bitmap_;
		void clear() {
			ok_ = false;
			tv_.tv_sec = 0;
			tv_.tv_usec = 0;
			rlen_ = 0;
			control_ = 0;
			bitmap_ = 0;
		}
	};
	struct SeqInfoPair {
		bool isOk() { return realInfo_.ok_ && sendInfo_.ok_; }
		SeqInfo realInfo_;
		SeqInfo sendInfo_;
	};

	struct SeqMap : std::unordered_map<le16_t/*seq*/, SeqInfoPair> {
		bool firstOk_{false};
		SeqMap::iterator firstIterator_;
		void clear() {
			firstOk_ = false;
			firstIterator_ = end(); // meaningless
			std::unordered_map<le16_t , SeqInfoPair>::clear();
		}
	};

	struct ApInfo {
		BeaconFrame beaconFrame_;
		Diff sendInterval_{Diff(0)}; // atomic
		Clock nextFrameSent_{std::chrono::seconds(0)};
		Clock lastAccess_{std::chrono::seconds(0)};
		SeqMap seqMap_;

		Diff adjustOffset_{Diff(0)}; // atomic
		Diff adjustInterval_{Diff(0)}; // atomic
		void adjustOffset(Diff adjustOffset);
		void adjustInterval(Diff adjustInterval);
	};

	struct ApMap : std::unordered_map<Mac, ApInfo> {
		std::mutex mutex_;
	};
	ApMap apMap_;

	std::string interface_;
	std::string filter_;
	bool active_{false};
	bool open();
	bool close();
	void wait();

	std::thread* scanThread_{nullptr};
	static void _scanThread(Ssg* ssg);
	void scanThread();

	std::thread* sendThread_{nullptr};
	static void _sendThread(Ssg* ssg);
	void sendThread();

	std::thread* deleteThread_{nullptr};
	static void _deleteThread(Ssg* ssg);
	void deleteThread();

protected:
	void processQosNull(QosNullHdr* qosNullHdr);
	void processAp(ApInfo& apInfo, le16_t seq, SeqInfo seqInfo);
	static int64_t getDiffTime(timeval tv1, timeval tv2);
	static timeval getAddTime(timeval tv, int64_t nsec);
};
