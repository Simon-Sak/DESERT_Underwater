#include "uwpqc-auth-module.h"

#include <arpa/inet.h>
#include <string>
#include <tclcl.h>

using std::string;

#include <uwip-module.h>
#include <uwudp-module.h>

#include <algorithm>
#include <cstring>
#include <iostream>
#include <sstream>
#include <strings.h>

namespace {
constexpr uint8_t kProtocolVersion = 1;
constexpr size_t kNonceLength = 32;
constexpr size_t kHmacLength = 32;
constexpr double kFragmentSpacing = 0.5;

uint64_t hostToNetwork64(uint64_t value)
{
	return (static_cast<uint64_t>(htonl(value & 0xffffffffULL)) << 32)
			| htonl(value >> 32);
}

uint64_t networkToHost64(uint64_t value)
{
	return (static_cast<uint64_t>(ntohl(value & 0xffffffffULL)) << 32)
			| ntohl(value >> 32);
}

void append16(std::vector<uint8_t> &out, uint16_t value)
{
	uint16_t network = htons(value);
	const uint8_t *bytes = reinterpret_cast<const uint8_t *>(&network);
	out.insert(out.end(), bytes, bytes + sizeof(network));
}

void append64(std::vector<uint8_t> &out, uint64_t value)
{
	uint64_t network = hostToNetwork64(value);
	const uint8_t *bytes = reinterpret_cast<const uint8_t *>(&network);
	out.insert(out.end(), bytes, bytes + sizeof(network));
}

bool read16(const std::vector<uint8_t> &data, size_t offset, uint16_t &value)
{
	if (offset + sizeof(uint16_t) > data.size())
		return false;
	uint16_t network = 0;
	memcpy(&network, data.data() + offset, sizeof(network));
	value = ntohs(network);
	return true;
}
} // namespace

int hdr_uwpqc_auth::offset_;

static class UwPqcAuthPacketClass : public PacketHeaderClass
{
public:
	UwPqcAuthPacketClass()
		: PacketHeaderClass("PacketHeader/UWPQC_AUTH", sizeof(hdr_uwpqc_auth))
	{
		bind();
		bind_offset(&hdr_uwpqc_auth::offset_);
	}
} class_uwpqc_auth_packet;

static class UwPqcAuthModuleClass : public TclClass
{
public:
	UwPqcAuthModuleClass()
		: TclClass("Module/UW/PQCAuth")
	{
	}

	TclObject *create(int, const char *const *) override
	{
		return new UwPqcAuthModule();
	}
} class_uwpqc_auth_module;

void
UwPqcAuthRetransmitTimer::expire(Event *)
{
	module_->onRetransmitTimeout();
}

UwPqcAuthModule::UwPqcAuthModule()
	: dest_port_(0)
	, dest_addr_(0)
	, local_addr_(0)
	, debug_(0)
	, max_fragment_payload_(UWPQC_AUTH_FRAGMENT_SIZE)
	, retransmit_timeout_(8.0)
	, max_retries_(3)
	, state_(IDLE)
	, peer_(0)
	, session_id_(0)
	, next_sequence_(1)
	, uid_counter_(0)
	, retry_count_(0)
	, handshake_started_(0.0)
	, retransmit_timer_(this)
	, active_type_(0)
	, tx_packets_(0)
	, rx_packets_(0)
	, tx_bytes_(0)
	, rx_bytes_(0)
	, tx_fragments_(0)
	, rx_fragments_(0)
	, retransmissions_(0)
	, signature_failures_(0)
	, malformed_packets_(0)
	, replayed_hellos_(0)
	, handshake_attempts_(0)
	, handshake_successes_(0)
	, handshake_elapsed_s_(0.0)
{
	bind("destPort_", &dest_port_);
	bind("destAddr_", &dest_addr_);
	bind("localAddr_", &local_addr_);
	bind("debug_", &debug_);
	bind("maxFragmentPayload_", &max_fragment_payload_);
	bind("retransmitTimeout_", &retransmit_timeout_);
	bind("maxRetries_", &max_retries_);
}

UwPqcAuthModule::~UwPqcAuthModule()
{
	retransmit_timer_.force_cancel();
	crypto_.cleanse(identity_secret_key_);
	resetSessionSecrets();
}

int
UwPqcAuthModule::command(int argc, const char *const *argv)
{
	Tcl &tcl = Tcl::instance();
	if (argc == 2) {
		if (strcasecmp(argv[1], "createIdentity") == 0) {
			if (!createIdentity()) {
				tcl.resultf("unable to create %s identity",
						crypto_.signatureAlgorithm().c_str());
				return TCL_ERROR;
			}
			tcl.resultf("%s", crypto_.base64Encode(identity_public_key_).c_str());
			return TCL_OK;
		}
		if (strcasecmp(argv[1], "getState") == 0) {
			tcl.result(stateName());
			return TCL_OK;
		}
		if (strcasecmp(argv[1], "getStats") == 0) {
			tcl.resultf("%s", stats().c_str());
			return TCL_OK;
		}
		if (strcasecmp(argv[1], "getAlgorithms") == 0) {
			tcl.resultf("kem %s signature %s", crypto_.kemAlgorithm().c_str(),
					crypto_.signatureAlgorithm().c_str());
			return TCL_OK;
		}
	} else if (argc == 4 && strcasecmp(argv[1], "trustPeer") == 0) {
		if (!trustPeer(static_cast<uint8_t>(atoi(argv[2])), argv[3])) {
			tcl.resultf("invalid %s peer public key", crypto_.signatureAlgorithm().c_str());
			return TCL_ERROR;
		}
		return TCL_OK;
	} else if (argc == 3 && strcasecmp(argv[1], "startHandshake") == 0) {
		if (!startHandshake(static_cast<uint8_t>(atoi(argv[2])))) {
			tcl.result("unable to start PQC authentication handshake");
			return TCL_ERROR;
		}
		return TCL_OK;
	} else if (argc == 3 && strcasecmp(argv[1], "setKemAlgorithm") == 0) {
		if (state_ != IDLE) {
			tcl.result("cannot change KEM algorithm while a handshake is active");
			return TCL_ERROR;
		}
		if (!crypto_.setKemAlgorithm(argv[2])) {
			tcl.result("unsupported KEM algorithm (expected an ML-KEM-*, HQC-*, or NTRU-* identifier)");
			return TCL_ERROR;
		}
		return TCL_OK;
	} else if (argc == 3 && strcasecmp(argv[1], "setSignatureAlgorithm") == 0) {
		if (state_ != IDLE) {
			tcl.result("cannot change signature algorithm while a handshake is active");
			return TCL_ERROR;
		}
		if (!crypto_.setSignatureAlgorithm(argv[2])) {
			tcl.result("unsupported signature algorithm (expected an ML-DSA-*, "
					"SLH-DSA*, or Falcon-* identifier)");
			return TCL_ERROR;
		}
		// Stale identity/trusted keys no longer match the new signature algorithm.
		crypto_.cleanse(identity_secret_key_);
		identity_public_key_.clear();
		trusted_keys_.clear();
		return TCL_OK;
	}
	return Module::command(argc, argv);
}

bool
UwPqcAuthModule::createIdentity()
{
	crypto_.cleanse(identity_secret_key_);
	identity_public_key_.clear();
	return crypto_.createIdentity(identity_public_key_, identity_secret_key_);
}

bool
UwPqcAuthModule::trustPeer(uint8_t peer, const std::string &encoded_key)
{
	std::vector<uint8_t> key;
	if (!crypto_.base64Decode(encoded_key, key) || crypto_.signature() == nullptr
			|| key.size() != crypto_.signature()->length_public_key)
		return false;
	trusted_keys_[peer] = key;
	return true;
}

bool
UwPqcAuthModule::startHandshake(uint8_t peer)
{
	if (!crypto_.available() || identity_secret_key_.empty()
			|| trusted_keys_.find(peer) == trusted_keys_.end() || local_addr_ == 0
			|| dest_port_ == 0 || dest_addr_ != peer)
		return false;
	resetSessionSecrets();
	peer_ = peer;
	crypto_.random(reinterpret_cast<uint8_t *>(&session_id_), sizeof(session_id_));
	if (session_id_ == 0)
		session_id_ = 1;
	std::vector<uint8_t> body(kNonceLength);
	crypto_.random(body.data(), body.size());
	client_hello_ = appendSignature(PQC_CLIENT_HELLO, session_id_,
			static_cast<uint8_t>(local_addr_), peer_, body);
	if (client_hello_.empty())
		return false;
	state_ = WAIT_SERVER_KEY;
	handshake_started_ = NOW;
	++handshake_attempts_;
	sendLogical(PQC_CLIENT_HELLO, client_hello_, true);
	return true;
}

void
UwPqcAuthModule::recv(Packet *packet)
{
	hdr_uwpqc_auth *header = HDR_UWPQC_AUTH(packet);
	uint64_t session = networkToHost64(header->session_id_);
	uint32_t sequence = ntohl(header->sequence_);
	uint16_t index = ntohs(header->fragment_index_);
	uint16_t count = ntohs(header->fragment_count_);
	uint16_t length = ntohs(header->payload_length_);
	if (header->version_ != kProtocolVersion || header->type_ < PQC_CLIENT_HELLO
			|| header->type_ > PQC_SERVER_FINISH || count == 0 || index >= count
			|| length > UWPQC_AUTH_FRAGMENT_SIZE || header->receiver_ != local_addr_) {
		++malformed_packets_;
		Packet::free(packet);
		return;
	}
	++rx_packets_;
	++rx_fragments_;
	rx_bytes_ += length;
	if (reassembly_.session_id != session || reassembly_.type != header->type_
			|| reassembly_.sender != header->sender_ || reassembly_.sequence != sequence) {
		reassembly_ = Reassembly();
		reassembly_.type = header->type_;
		reassembly_.sender = header->sender_;
		reassembly_.receiver = header->receiver_;
		reassembly_.session_id = session;
		reassembly_.sequence = sequence;
		reassembly_.fragment_count = count;
		reassembly_.fragments.resize(count);
		reassembly_.received.assign(count, false);
	}
	if (reassembly_.fragment_count != count || reassembly_.received[index]) {
		++malformed_packets_;
		Packet::free(packet);
		return;
	}
	reassembly_.fragments[index].assign(header->payload_, header->payload_ + length);
	reassembly_.received[index] = true;
	bool complete = std::all_of(reassembly_.received.begin(), reassembly_.received.end(),
			[](bool received) { return received; });
	if (complete) {
		std::vector<uint8_t> message;
		for (const auto &fragment : reassembly_.fragments)
			message.insert(message.end(), fragment.begin(), fragment.end());
		handleComplete(reassembly_.type, reassembly_.sender, reassembly_.receiver,
				reassembly_.session_id, message);
		reassembly_ = Reassembly();
	}
	Packet::free(packet);
}

void
UwPqcAuthModule::sendLogical(
		uint8_t type, const std::vector<uint8_t> &message, bool expect_response)
{
	if (message.empty() || max_fragment_payload_ < 1
			|| max_fragment_payload_ > UWPQC_AUTH_FRAGMENT_SIZE)
		return fail("invalid logical message");
	uint16_t count = static_cast<uint16_t>((message.size() + max_fragment_payload_ - 1)
			/ max_fragment_payload_);
	if (count == 0 || count > 1024)
		return fail("invalid fragment count");
	uint32_t sequence = ++next_sequence_;
	for (uint16_t index = 0; index < count; ++index) {
		size_t offset = index * max_fragment_payload_;
		size_t length = std::min<size_t>(max_fragment_payload_, message.size() - offset);
		sendFragment(type, session_id_, sequence, index, count, message.data() + offset, length,
				index * kFragmentSpacing);
	}
	if (expect_response) {
		active_message_ = message;
		active_type_ = type;
		retry_count_ = 0;
		retransmit_timer_.resched(retransmit_timeout_ + (count - 1) * kFragmentSpacing);
	}
}

void
UwPqcAuthModule::sendFragment(uint8_t type, uint64_t session_id, uint32_t sequence,
		uint16_t index, uint16_t count, const uint8_t *payload, size_t length, double delay)
{
	Packet *packet = Packet::alloc();
	hdr_cmn *common = HDR_CMN(packet);
	hdr_uwudp *udp = HDR_UWUDP(packet);
	hdr_uwip *ip = HDR_UWIP(packet);
	hdr_uwpqc_auth *header = HDR_UWPQC_AUTH(packet);
	common->uid() = uid_counter_++;
	common->ptype() = PT_UWPQC_AUTH;
	common->direction() = hdr_cmn::DOWN;
	common->timestamp() = NOW;
	common->size() = sizeof(hdr_uwpqc_auth);
	udp->dport() = static_cast<uint8_t>(dest_port_);
	ip->daddr() = static_cast<uint8_t>(dest_addr_);
	header->version_ = kProtocolVersion;
	header->type_ = type;
	header->sender_ = static_cast<uint8_t>(local_addr_);
	header->receiver_ = peer_;
	header->session_id_ = hostToNetwork64(session_id);
	header->sequence_ = htonl(sequence);
	header->fragment_index_ = htons(index);
	header->fragment_count_ = htons(count);
	header->payload_length_ = htons(static_cast<uint16_t>(length));
	memset(header->payload_, 0, sizeof(header->payload_));
	memcpy(header->payload_, payload, length);
	++tx_packets_;
	++tx_fragments_;
	tx_bytes_ += length;
	sendDown(packet, delay);
}

void
UwPqcAuthModule::onRetransmitTimeout()
{
	if (active_message_.empty() || retry_count_ >= max_retries_) {
		fail("handshake response timeout");
		return;
	}
	++retry_count_;
	++retransmissions_;
	uint16_t count = static_cast<uint16_t>((active_message_.size() + max_fragment_payload_ - 1)
			/ max_fragment_payload_);
	uint32_t sequence = ++next_sequence_;
	for (uint16_t index = 0; index < count; ++index) {
		size_t offset = index * max_fragment_payload_;
		size_t length = std::min<size_t>(max_fragment_payload_, active_message_.size() - offset);
		sendFragment(active_type_, session_id_, sequence, index, count,
				active_message_.data() + offset, length, index * kFragmentSpacing);
	}
	retransmit_timer_.resched(retransmit_timeout_ + (count - 1) * kFragmentSpacing);
}

void
UwPqcAuthModule::handleComplete(uint8_t type, uint8_t sender, uint8_t receiver,
		uint64_t session_id, const std::vector<uint8_t> &message)
{
	if (sender == 0 || sender == local_addr_ || receiver != local_addr_)
		return fail("invalid packet addresses");
	switch (type) {
	case PQC_CLIENT_HELLO:
		handleClientHello(sender, session_id, message);
		break;
	case PQC_SERVER_KEY:
		handleServerKey(sender, session_id, message);
		break;
	case PQC_CLIENT_FINISH:
		handleClientFinish(sender, session_id, message);
		break;
	case PQC_SERVER_FINISH:
		handleServerFinish(sender, session_id, message);
		break;
	default:
		++malformed_packets_;
	}
}

void
UwPqcAuthModule::handleClientHello(uint8_t sender, uint64_t session_id,
		const std::vector<uint8_t> &message)
{
	std::vector<uint8_t> body;
	if (!verifyPeer(sender, PQC_CLIENT_HELLO, session_id, sender,
				static_cast<uint8_t>(local_addr_), message, kNonceLength, body)) {
		++signature_failures_;
		return fail("invalid client hello signature");
	}
	if (state_ == WAIT_CLIENT_FINISH && sender == peer_ && session_id == session_id_) {
		sendLogical(PQC_SERVER_KEY, server_key_, true);
		return;
	}
	if (state_ != IDLE && state_ != FAILED)
		return;
	auto seen = seen_session_ids_.find(sender);
	if (seen != seen_session_ids_.end() && seen->second == session_id) {
		// Drop a replayed hello instead of redoing NTRU/Falcon work for it.
		++replayed_hellos_;
		return;
	}
	resetSessionSecrets();
	peer_ = sender;
	session_id_ = session_id;
	seen_session_ids_[sender] = session_id;
	client_hello_ = message;
	std::vector<uint8_t> kem_public_key;
	if (!crypto_.kemKeypair(kem_public_key, kem_secret_key_))
		return fail("unable to create NTRU keypair");
	std::vector<uint8_t> server_body(kNonceLength);
	crypto_.random(server_body.data(), server_body.size());
	append16(server_body, static_cast<uint16_t>(kem_public_key.size()));
	server_body.insert(server_body.end(), kem_public_key.begin(), kem_public_key.end());
	server_key_ = appendSignature(PQC_SERVER_KEY, session_id_,
			static_cast<uint8_t>(local_addr_), peer_, server_body);
	if (server_key_.empty())
		return fail("unable to sign server key");
	state_ = WAIT_CLIENT_FINISH;
	sendLogical(PQC_SERVER_KEY, server_key_, true);
}

void
UwPqcAuthModule::handleServerKey(uint8_t sender, uint64_t session_id,
		const std::vector<uint8_t> &message)
{
	if (state_ != WAIT_SERVER_KEY || sender != peer_ || session_id != session_id_)
		return;
	if (message.size() < kNonceLength + sizeof(uint16_t) + sizeof(uint16_t))
		return fail("truncated server key");
	uint16_t key_length = 0;
	if (!read16(message, kNonceLength, key_length)
			|| message.size() < kNonceLength + sizeof(uint16_t) + key_length + sizeof(uint16_t))
		return fail("invalid server key length");
	size_t body_length = kNonceLength + sizeof(uint16_t) + key_length;
	std::vector<uint8_t> body;
	if (!verifyPeer(sender, PQC_SERVER_KEY, session_id, sender,
				static_cast<uint8_t>(local_addr_), message, body_length, body)) {
		++signature_failures_;
		return fail("invalid server key signature");
	}
	retransmit_timer_.force_cancel();
	active_message_.clear();
	server_key_ = message;
	std::vector<uint8_t> kem_public_key(body.begin() + kNonceLength + sizeof(uint16_t), body.end());
	std::vector<uint8_t> ciphertext;
	std::vector<uint8_t> shared_secret;
	if (!crypto_.encapsulate(kem_public_key, ciphertext, shared_secret))
		return fail("NTRU encapsulation failed");
	std::vector<uint8_t> client_body;
	append16(client_body, static_cast<uint16_t>(ciphertext.size()));
	client_body.insert(client_body.end(), ciphertext.begin(), ciphertext.end());
	client_finish_ = appendSignature(PQC_CLIENT_FINISH, session_id_,
			static_cast<uint8_t>(local_addr_), peer_, client_body);
	if (client_finish_.empty()) {
		crypto_.cleanse(shared_secret);
		return fail("unable to sign client finish");
	}
	if (!crypto_.deriveConfirmationKey(shared_secret, transcript(), confirmation_key_)) {
		crypto_.cleanse(shared_secret);
		return fail("HKDF failed");
	}
	crypto_.cleanse(shared_secret);
	state_ = WAIT_SERVER_FINISH;
	sendLogical(PQC_CLIENT_FINISH, client_finish_, true);
}

void
UwPqcAuthModule::handleClientFinish(uint8_t sender, uint64_t session_id,
		const std::vector<uint8_t> &message)
{
	if (state_ == AUTHENTICATED && sender == peer_ && session_id == session_id_) {
		// Peer never saw our ServerFinish; resend the cached confirmation tag.
		sendLogical(PQC_SERVER_FINISH, server_finish_, false);
		return;
	}
	if (state_ != WAIT_CLIENT_FINISH || sender != peer_ || session_id != session_id_)
		return;
	if (message.size() < sizeof(uint16_t) * 2)
		return fail("truncated client finish");
	uint16_t ciphertext_length = 0;
	if (!read16(message, 0, ciphertext_length)
			|| message.size() < sizeof(uint16_t) + ciphertext_length + sizeof(uint16_t))
		return fail("invalid ciphertext length");
	size_t body_length = sizeof(uint16_t) + ciphertext_length;
	std::vector<uint8_t> body;
	if (!verifyPeer(sender, PQC_CLIENT_FINISH, session_id, sender,
				static_cast<uint8_t>(local_addr_), message, body_length, body)) {
		++signature_failures_;
		return fail("invalid client finish signature");
	}
	retransmit_timer_.force_cancel();
	active_message_.clear();
	client_finish_ = message;
	std::vector<uint8_t> ciphertext(body.begin() + sizeof(uint16_t), body.end());
	std::vector<uint8_t> shared_secret;
	if (!crypto_.decapsulate(kem_secret_key_, ciphertext, shared_secret))
		return fail("NTRU decapsulation failed");
	std::vector<uint8_t> confirmation_key;
	if (!crypto_.deriveConfirmationKey(shared_secret, transcript(), confirmation_key)) {
		crypto_.cleanse(shared_secret);
		return fail("HKDF failed");
	}
	crypto_.cleanse(shared_secret);
	std::vector<uint8_t> tag;
	if (!crypto_.hmac(confirmation_key, transcript(), tag)) {
		crypto_.cleanse(confirmation_key);
		return fail("confirmation HMAC failed");
	}
	crypto_.cleanse(confirmation_key);
	state_ = AUTHENTICATED;
	++handshake_successes_;
	handshake_elapsed_s_ = NOW - handshake_started_;
	server_finish_ = tag;
	sendLogical(PQC_SERVER_FINISH, tag, false);
}

void
UwPqcAuthModule::handleServerFinish(uint8_t sender, uint64_t session_id,
		const std::vector<uint8_t> &message)
{
	if (state_ != WAIT_SERVER_FINISH || sender != peer_ || session_id != session_id_
			|| message.size() != kHmacLength)
		return;
	retransmit_timer_.force_cancel();
	std::vector<uint8_t> expected;
	bool valid = crypto_.hmac(confirmation_key_, transcript(), expected)
			&& OQS_MEM_secure_bcmp(expected.data(), message.data(), kHmacLength) == 0;
	crypto_.cleanse(confirmation_key_);
	if (!valid)
		return fail("invalid server confirmation");
	active_message_.clear();
	state_ = AUTHENTICATED;
	++handshake_successes_;
	handshake_elapsed_s_ = NOW - handshake_started_;
}

std::vector<uint8_t>
UwPqcAuthModule::signedData(uint8_t type, uint64_t session_id, uint8_t sender,
		uint8_t receiver, const std::vector<uint8_t> &body) const
{
	std::vector<uint8_t> data;
	data.push_back(kProtocolVersion);
	data.push_back(type);
	append64(data, session_id);
	data.push_back(sender);
	data.push_back(receiver);
	if (type == PQC_SERVER_KEY || type == PQC_CLIENT_FINISH)
		data.insert(data.end(), client_hello_.begin(), client_hello_.end());
	if (type == PQC_CLIENT_FINISH)
		data.insert(data.end(), server_key_.begin(), server_key_.end());
	data.insert(data.end(), body.begin(), body.end());
	return data;
}

bool
UwPqcAuthModule::parseSignature(const std::vector<uint8_t> &message,
		size_t body_length, std::vector<uint8_t> &body,
		std::vector<uint8_t> &signature) const
{
	uint16_t signature_length = 0;
	if (message.size() < body_length + sizeof(uint16_t)
			|| !read16(message, body_length, signature_length)
			|| message.size() != body_length + sizeof(uint16_t) + signature_length)
		return false;
	body.assign(message.begin(), message.begin() + body_length);
	signature.assign(message.begin() + body_length + sizeof(uint16_t), message.end());
	return true;
}

bool
UwPqcAuthModule::verifyPeer(uint8_t peer, uint8_t type, uint64_t session_id,
		uint8_t sender, uint8_t receiver, const std::vector<uint8_t> &message,
		size_t body_length, std::vector<uint8_t> &body) const
{
	auto key = trusted_keys_.find(peer);
	std::vector<uint8_t> signature;
	if (key == trusted_keys_.end()
			|| !parseSignature(message, body_length, body, signature)
			|| !crypto_.verify(key->second, signedData(type, session_id, sender, receiver, body), signature)) {
		return false;
	}
	return true;
}

std::vector<uint8_t>
UwPqcAuthModule::appendSignature(uint8_t type, uint64_t session_id, uint8_t sender,
		uint8_t receiver, const std::vector<uint8_t> &body)
{
	std::vector<uint8_t> signature;
	if (!crypto_.sign(identity_secret_key_, signedData(type, session_id, sender, receiver, body), signature)
			|| signature.size() > UINT16_MAX)
		return {};
	std::vector<uint8_t> message = body;
	append16(message, static_cast<uint16_t>(signature.size()));
	message.insert(message.end(), signature.begin(), signature.end());
	return message;
}

std::vector<uint8_t>
UwPqcAuthModule::transcript() const
{
	std::vector<uint8_t> value;
	value.insert(value.end(), client_hello_.begin(), client_hello_.end());
	value.insert(value.end(), server_key_.begin(), server_key_.end());
	value.insert(value.end(), client_finish_.begin(), client_finish_.end());
	return value;
}

void
UwPqcAuthModule::fail(const char *reason)
{
	if (debug_) {
		std::cout << NOW << " UwPqcAuthModule(" << local_addr_ << ")::fail() peer "
				<< static_cast<int>(peer_) << " state " << stateName() << " reason "
				<< reason << std::endl;
	}
	retransmit_timer_.force_cancel();
	active_message_.clear();
	state_ = FAILED;
}

void
UwPqcAuthModule::resetSessionSecrets()
{
	crypto_.cleanse(kem_secret_key_);
	crypto_.cleanse(confirmation_key_);
	crypto_.cleanse(client_hello_);
	crypto_.cleanse(server_key_);
	crypto_.cleanse(client_finish_);
	crypto_.cleanse(server_finish_);
	active_message_.clear();
	reassembly_ = Reassembly();
	retry_count_ = 0;
}

const char *
UwPqcAuthModule::stateName() const
{
	switch (state_) {
	case IDLE: return "IDLE";
	case WAIT_SERVER_KEY: return "WAIT_SERVER_KEY";
	case WAIT_CLIENT_FINISH: return "WAIT_CLIENT_FINISH";
	case WAIT_SERVER_FINISH: return "WAIT_SERVER_FINISH";
	case AUTHENTICATED: return "AUTHENTICATED";
	case FAILED: return "FAILED";
	}
	return "FAILED";
}

std::string
UwPqcAuthModule::stats() const
{
	std::ostringstream out;
	out << "tx_packets " << tx_packets_ << " rx_packets " << rx_packets_
		<< " tx_bytes " << tx_bytes_ << " rx_bytes " << rx_bytes_
		<< " tx_fragments " << tx_fragments_ << " rx_fragments " << rx_fragments_
		<< " retransmissions " << retransmissions_
		<< " signature_failures " << signature_failures_
		<< " malformed_packets " << malformed_packets_
		<< " replayed_hellos " << replayed_hellos_
		<< " handshake_attempts " << handshake_attempts_
		<< " handshake_successes " << handshake_successes_
		<< " handshake_elapsed_s " << handshake_elapsed_s_;
	return out.str();
}