#ifndef UWPQC_AUTH_MODULE_H
#define UWPQC_AUTH_MODULE_H

#include "uwpqc-auth-crypto.h"
#include "uwpqc-auth-packet.h"

#include <module.h>
#include <timer-handler.h>

#include <cstdint>
#include <map>
#include <string>
#include <vector>

class UwPqcAuthModule;

class UwPqcAuthRetransmitTimer : public TimerHandler
{
public:
	explicit UwPqcAuthRetransmitTimer(UwPqcAuthModule *module)
		: module_(module)
	{
	}

protected:
	void expire(Event *) override;

private:
	UwPqcAuthModule *module_;
};

// Fires when no new fragment has been received for a while on an incomplete
// reassembly, so the receiver can NAK the specific missing fragments instead
// of waiting for the sender's much longer whole-message retransmit timeout.
class UwPqcAuthGapTimer : public TimerHandler
{
public:
	explicit UwPqcAuthGapTimer(UwPqcAuthModule *module)
		: module_(module)
	{
	}

protected:
	void expire(Event *) override;

private:
	UwPqcAuthModule *module_;
};

class UwPqcAuthModule : public Module
{
	friend class UwPqcAuthRetransmitTimer;
	friend class UwPqcAuthGapTimer;

public:
	UwPqcAuthModule();
	~UwPqcAuthModule() override;

	int command(int argc, const char *const *argv) override;
	void recv(Packet *packet) override;

	void onRetransmitTimeout();
	void onGapTimeout();

private:
	enum State {
		IDLE,
		WAIT_SERVER_KEY,
		WAIT_CLIENT_FINISH,
		WAIT_SERVER_FINISH,
		AUTHENTICATED,
		FAILED
	};

	struct Reassembly {
		uint8_t type = 0;
		uint8_t sender = 0;
		uint8_t receiver = 0;
		uint64_t session_id = 0;
		uint32_t sequence = 0;
		uint16_t fragment_count = 0;
		std::vector<std::vector<uint8_t>> fragments;
		std::vector<bool> received;
	};

	bool createIdentity();
	bool trustPeer(uint8_t peer, const std::string &encoded_key);
	bool startHandshake(uint8_t peer);
	void sendLogical(uint8_t type, const std::vector<uint8_t> &message,
			bool expect_response);
	void sendFragment(uint8_t type, uint64_t session_id, uint32_t sequence,
			uint16_t index, uint16_t count, const uint8_t *payload, size_t length,
			double delay);
	void sendNak();
	void handleNak(const hdr_uwpqc_auth *header);
	void handleComplete(uint8_t type, uint8_t sender, uint8_t receiver,
			uint64_t session_id, const std::vector<uint8_t> &message);
	void handleClientHello(uint8_t sender, uint64_t session_id,
			const std::vector<uint8_t> &message);
	void handleServerKey(uint8_t sender, uint64_t session_id,
			const std::vector<uint8_t> &message);
	void handleClientFinish(uint8_t sender, uint64_t session_id,
			const std::vector<uint8_t> &message);
	void handleServerFinish(uint8_t sender, uint64_t session_id,
			const std::vector<uint8_t> &message);

	std::vector<uint8_t> signedData(uint8_t type, uint64_t session_id,
			uint8_t sender, uint8_t receiver,
			const std::vector<uint8_t> &body) const;
	bool parseSignature(const std::vector<uint8_t> &message, size_t body_length,
			std::vector<uint8_t> &body, std::vector<uint8_t> &signature) const;
	bool verifyPeer(uint8_t peer, uint8_t type, uint64_t session_id,
			uint8_t sender, uint8_t receiver, const std::vector<uint8_t> &message,
			size_t body_length, std::vector<uint8_t> &body) const;
	std::vector<uint8_t> appendSignature(uint8_t type, uint64_t session_id,
			uint8_t sender, uint8_t receiver, const std::vector<uint8_t> &body);
	std::vector<uint8_t> transcript() const;
	void fail(const char *reason);
	void resetSessionSecrets();
	const char *stateName() const;
	std::string stats() const;

	int dest_port_;
	int dest_addr_;
	int local_addr_;
	int debug_;
	int max_fragment_payload_;
	double retransmit_timeout_;
	int max_retries_;
	double gap_timeout_;
	int max_nak_retries_;
	State state_;
	uint8_t peer_;
	uint64_t session_id_;
	uint32_t next_sequence_;
	uint32_t active_sequence_;
	int uid_counter_;
	int retry_count_;
	int nak_retry_count_;
	double handshake_started_;
	UwPqcAuthRetransmitTimer retransmit_timer_;
	UwPqcAuthGapTimer gap_timer_;
	UwPqcAuthCrypto crypto_;
	std::vector<uint8_t> identity_public_key_;
	std::vector<uint8_t> identity_secret_key_;
	std::map<uint8_t, std::vector<uint8_t>> trusted_keys_;
	std::map<uint8_t, uint64_t> seen_session_ids_;
	std::vector<uint8_t> kem_secret_key_;
	std::vector<uint8_t> confirmation_key_;
	std::vector<uint8_t> client_hello_;
	std::vector<uint8_t> server_key_;
	std::vector<uint8_t> client_finish_;
	std::vector<uint8_t> server_finish_;
	std::vector<uint8_t> active_message_;
	uint8_t active_type_;
	Reassembly reassembly_;

	uint64_t tx_packets_;
	uint64_t rx_packets_;
	uint64_t tx_bytes_;
	uint64_t rx_bytes_;
	uint64_t tx_fragments_;
	uint64_t rx_fragments_;
	uint64_t retransmissions_;
	uint64_t selective_retransmissions_;
	uint64_t naks_sent_;
	uint64_t naks_received_;
	uint64_t signature_failures_;
	uint64_t malformed_packets_;
	uint64_t replayed_hellos_;
	uint64_t handshake_attempts_;
	uint64_t handshake_successes_;
	double handshake_elapsed_s_;
};

#endif