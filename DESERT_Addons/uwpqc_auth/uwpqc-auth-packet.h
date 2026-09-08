#ifndef UWPQC_AUTH_PACKET_H
#define UWPQC_AUTH_PACKET_H

#include "uwpqc-auth-build-config.h"
#include <packet.h>
#include <stdint.h>

#define HDR_UWPQC_AUTH(p) (hdr_uwpqc_auth::access(p))
#define UWPQC_AUTH_FRAGMENT_SIZE 96

enum UwPqcAuthMessageType : uint8_t {
	PQC_CLIENT_HELLO = 1,
	PQC_SERVER_KEY = 2,
	PQC_CLIENT_FINISH = 3,
	PQC_SERVER_FINISH = 4,
	// Control packet: receiver -> sender, carrying a missing-fragment bitmap
	// (in payload_) so only the lost fragments need to be resent instead of
	// the whole logical message.
	PQC_FRAGMENT_NAK = 5
};

typedef struct hdr_uwpqc_auth {
	uint8_t version_;
	uint8_t type_;
	uint8_t sender_;
	uint8_t receiver_;
	uint64_t session_id_;
	uint32_t sequence_;
	uint16_t fragment_index_;
	uint16_t fragment_count_;
	uint16_t payload_length_;
	uint8_t payload_[UWPQC_AUTH_FRAGMENT_SIZE];

	static int offset_;

	static int &offset() { return offset_; }
	static hdr_uwpqc_auth *access(const Packet *packet)
	{
		return reinterpret_cast<hdr_uwpqc_auth *>(packet->access(offset_));
	}
} hdr_uwpqc_auth;

extern packet_t PT_UWPQC_AUTH;

#endif