#include "tclcl.h"
#include "packer_uwpqc.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>

static class PackerUWPQCClass : public TclClass
{
public:
	PackerUWPQCClass()
		: TclClass("UW/PQC/Packer")
	{
	}

	TclObject *
	create(int, const char *const *)
	{
		return (new packerUWPQC());
	}
} class_module_packerUWPQC;

namespace {

std::string
bytesToHex(const std::vector<uint8_t>& data)
{
	std::ostringstream out;
	out << std::hex << std::setfill('0');
	for (uint8_t byte : data) {
		out << std::setw(2) << static_cast<int>(byte);
	}
	return out.str();
}

bool
hexToBytes(const char *text, std::vector<uint8_t>& data)
{
	data.clear();
	if (text == nullptr) {
		return false;
	}

	const size_t length = strlen(text);
	if ((length % 2) != 0) {
		return false;
	}

	data.reserve(length / 2);
	for (size_t index = 0; index < length; index += 2) {
		unsigned int value = 0;
		std::istringstream input(std::string(text + index, 2));
		input >> std::hex >> value;
		if (input.fail()) {
			return false;
		}
		data.push_back(static_cast<uint8_t>(value & 0xFF));
	}

	return true;
}

} // namespace

packerUWPQC::packerUWPQC()
	: packer(false)
	, version_bits_(8)
	, flags_bits_(8)
	, ct_len_bits_(16)
	, sig_len_bits_(16)
	, use_kem_(1)
	, use_sig_(false)
#ifdef HAVE_LIBOQS
	, kem_(nullptr), sig_(nullptr)
#endif
{
	bind("debug_", &debug_);
	bind("use_kem_", &use_kem_);
	bind("use_sig_", &use_sig_);
	this->init();
}

int
packerUWPQC::command(int argc, const char *const *argv)
{
	if (argc == 3 && strcmp(argv[1], "kemEncapsulate") == 0) {
#ifdef HAVE_LIBOQS
		std::vector<uint8_t> plaintext(argv[2], argv[2] + strlen(argv[2]));
		std::vector<uint8_t> ciphertext = encapsulate(plaintext);
		if (ciphertext.empty()) {
			return TCL_ERROR;
		}
		Tcl::instance().result(bytesToHex(ciphertext).c_str());
		return TCL_OK;
#else
		return TCL_ERROR;
#endif
	}
	else if (argc == 3 && strcmp(argv[1], "kemDecapsulate") == 0) {
#ifdef HAVE_LIBOQS
		std::vector<uint8_t> ciphertext;
		if (!hexToBytes(argv[2], ciphertext)) {
			return TCL_ERROR;
		}
		std::vector<uint8_t> shared_secret = decapsulate(ciphertext);
		if (shared_secret.empty()) {
			return TCL_ERROR;
		}
		Tcl::instance().result(bytesToHex(shared_secret).c_str());
		return TCL_OK;
#else
		return TCL_ERROR;
#endif
	}
	else if (argc == 3 && strcmp(argv[1], "sigSign") == 0) {
#ifdef HAVE_LIBOQS
		std::vector<uint8_t> message(argv[2], argv[2] + strlen(argv[2]));
		std::vector<uint8_t> signature = sign(message);
		if (signature.empty()) {
			return TCL_ERROR;
		}
		Tcl::instance().result(bytesToHex(signature).c_str());
		return TCL_OK;
#else
		return TCL_ERROR;
#endif
	}
	else if (argc == 4 && strcmp(argv[1], "sigVerify") == 0) {
#ifdef HAVE_LIBOQS
		std::vector<uint8_t> message(argv[2], argv[2] + strlen(argv[2]));
		std::vector<uint8_t> signature;
		if (!hexToBytes(argv[3], signature)) {
			return TCL_ERROR;
		}
		const bool ok = verify(message, signature);
		Tcl::instance().result(ok ? "1" : "0");
		return TCL_OK;
#else
		return TCL_ERROR;
#endif
	}
	else if (argc == 3 && strcmp(argv[1], "setKemAlgorithm") == 0) {
		// Set KEM algorithm dynamically
#ifdef HAVE_LIBOQS
		pqc_kem_alg_ = argv[2];
		if (kem_ != nullptr) {
			OQS_KEM_free(kem_);
		}
		kem_ = OQS_KEM_new(pqc_kem_alg_.c_str());
		if (kem_ != nullptr) {
			generateKEMKeys();
			std::cout << "UWPQC: Switched KEM algorithm to " << pqc_kem_alg_ << std::endl;
			return TCL_OK;
		} else {
			std::cerr << "UWPQC: Failed to set KEM algorithm: " << pqc_kem_alg_ << std::endl;
			return TCL_ERROR;
		}
#else
		std::cerr << "UWPQC: liboqs not available" << std::endl;
		return TCL_ERROR;
#endif
	}
	else if (argc == 3 && strcmp(argv[1], "setSigAlgorithm") == 0) {
#ifdef HAVE_LIBOQS
		std::string requested = argv[2];
		std::string resolved = resolveSignatureAlgorithm(requested);
		if (resolved.empty()) {
			std::cerr << "UWPQC: Failed to resolve SIG algorithm: " << requested << std::endl;
			return TCL_ERROR;
		}
		pqc_sig_alg_ = resolved;
		if (sig_ != nullptr) {
			OQS_SIG_free(sig_);
			sig_ = nullptr;
		}
		sig_ = OQS_SIG_new(pqc_sig_alg_.c_str());
		if (sig_ != nullptr) {
			generateSigKeys();
			std::cout << "UWPQC: Switched SIG algorithm to " << pqc_sig_alg_ << std::endl;
			return TCL_OK;
		} else {
			std::cerr << "UWPQC: Failed to set SIG algorithm: " << pqc_sig_alg_ << std::endl;
			return TCL_ERROR;
		}
#else
		std::cerr << "UWPQC: liboqs not available" << std::endl;
		return TCL_ERROR;
#endif
	}
	return packer::command(argc, argv);
}

packerUWPQC::~packerUWPQC()
{
#ifdef HAVE_LIBOQS
	if (kem_ != nullptr) {
		OQS_KEM_free(kem_);
	}
	if (sig_ != nullptr) {
		OQS_SIG_free(sig_);
	}
#endif
}

void
packerUWPQC::init()
{
	n_bits.clear();
	initPQCAlgorithms();
	
	// Define header field sizes
	n_bits.push_back(version_bits_);
	n_bits.push_back(flags_bits_);
	n_bits.push_back(ct_len_bits_);
	n_bits.push_back(sig_len_bits_);
	
#ifdef HAVE_LIBOQS
	// Generate keys for KEM and SIG if enabled
	if (use_kem_) {
		generateKEMKeys();
	}
	if (use_sig_) {
		generateSigKeys();
	}
#endif
}

void
packerUWPQC::initPQCAlgorithms()
{
#ifdef HAVE_LIBOQS
	pqc_kem_alg_ = getDefaultKEMAlgorithm();
	pqc_sig_alg_ = getDefaultSigAlgorithm();
	
	if (!pqc_kem_alg_.empty()) {
		kem_ = OQS_KEM_new(pqc_kem_alg_.c_str());
		if (kem_ != nullptr) {
			if (debug_) {
				std::cout << "UWPQC: Initialized KEM algorithm: " 
					  << pqc_kem_alg_ << std::endl;
			}
		} else {
			std::cerr << "UWPQC: Failed to initialize KEM: " 
				  << pqc_kem_alg_ << std::endl;
		}
	}
	
	if (!pqc_sig_alg_.empty()) {
		sig_ = OQS_SIG_new(pqc_sig_alg_.c_str());
		if (sig_ != nullptr) {
			if (debug_) {
				std::cout << "UWPQC: Initialized SIG algorithm: " 
					  << pqc_sig_alg_ << std::endl;
			}
		} else {
			std::cerr << "UWPQC: Failed to initialize SIG: " 
				  << pqc_sig_alg_ << std::endl;
		}
	}
#endif
}

std::string
packerUWPQC::getDefaultKEMAlgorithm()
{
#ifdef HAVE_LIBOQS
	if (OQS_KEM_alg_is_enabled("NTRU-HRSS-701")) {
		return "NTRU-HRSS-701";
	}
	// Prefer NTRU, then the standardized ML-KEM family, then legacy Kyber.
	if (OQS_KEM_alg_is_enabled("ML-KEM-768")) {
		return "ML-KEM-768";
	}
	if (OQS_KEM_alg_is_enabled("Kyber768")) {
		return "Kyber768";
	}
	// Fallbacks for older liboqs builds.
	if (OQS_KEM_alg_is_enabled("Kyber1024")) {
		return "Kyber1024";
	}
	if (OQS_KEM_alg_is_enabled("NTRU-HPS-2048-509")) {
		return "NTRU-HPS-2048-509";
	}
#endif
	return "";
}

std::string
packerUWPQC::resolveSignatureAlgorithm(const std::string& requested) const
{
#ifdef HAVE_LIBOQS
	if (requested.empty()) {
		return "";
	}

	std::string normalized = requested;
	std::transform(normalized.begin(), normalized.end(), normalized.begin(),
		[](unsigned char c) { return static_cast<char>(std::tolower(c)); });

	if (normalized == "falcon" || normalized == "falcon-1024" || normalized.find("falcon") != std::string::npos) {
		if (OQS_SIG_alg_is_enabled("Falcon-1024")) {
			return "Falcon-1024";
		}
		if (OQS_SIG_alg_is_enabled("Falcon-512")) {
			return "Falcon-512";
		}
	}

	if (normalized == "ml-dsa" || normalized == "ml-dsa-65" || normalized.find("ml-dsa") != std::string::npos) {
		if (OQS_SIG_alg_is_enabled("ML-DSA-65")) {
			return "ML-DSA-65";
		}
		if (OQS_SIG_alg_is_enabled("ML-DSA-44")) {
			return "ML-DSA-44";
		}
		if (OQS_SIG_alg_is_enabled("ML-DSA-87")) {
			return "ML-DSA-87";
		}
	}

	if (normalized == "slh-dsa" || normalized == "slh-dsa-128s" || normalized.find("slh") != std::string::npos) {
		if (OQS_SIG_alg_is_enabled("SLH_DSA_PURE_SHA2_128S")) {
			return "SLH_DSA_PURE_SHA2_128S";
		}
		if (OQS_SIG_alg_is_enabled("SLH_DSA_SHA2_128S")) {
			return "SLH_DSA_SHA2_128S";
		}
	}
#endif
	return requested;
}

std::string
packerUWPQC::getDefaultSigAlgorithm()
{
#ifdef HAVE_LIBOQS
	if (OQS_SIG_alg_is_enabled("Falcon-1024")) {
		return "Falcon-1024";
	}
	if (OQS_SIG_alg_is_enabled("ML-DSA-65")) {
		return "ML-DSA-65";
	}
	if (OQS_SIG_alg_is_enabled("SLH_DSA_PURE_SHA2_128S")) {
		return "SLH_DSA_PURE_SHA2_128S";
	}
	if (OQS_SIG_alg_is_enabled("Falcon-512")) {
		return "Falcon-512";
	}
	if (OQS_SIG_alg_is_enabled("Dilithium3")) {
		return "Dilithium3";
	}
#endif
	return "";
}

void
packerUWPQC::generateKEMKeys()
{
#ifdef HAVE_LIBOQS
	if (kem_ == nullptr) return;
	
	// Allocate buffers for public and secret keys
	uint8_t *public_key = new uint8_t[kem_->length_public_key];
	uint8_t *secret_key = new uint8_t[kem_->length_secret_key];
	
	// Generate keypair
	OQS_STATUS status = OQS_KEM_keypair(kem_, public_key, secret_key);
	
	if (status == OQS_SUCCESS) {
		// Store keys as vectors
		kem_public_key_.assign(public_key, public_key + kem_->length_public_key);
		kem_secret_key_.assign(secret_key, secret_key + kem_->length_secret_key);
		
		if (debug_) {
			std::cout << "UWPQC: Generated KEM keypair (" 
				  << kem_->length_public_key << " byte pubkey, "
				  << kem_->length_secret_key << " byte privkey)" << std::endl;
		}
	} else {
		std::cerr << "UWPQC: Failed to generate KEM keypair" << std::endl;
	}
	
	delete[] public_key;
	delete[] secret_key;
#endif
}

void
packerUWPQC::generateSigKeys()
{
#ifdef HAVE_LIBOQS
	if (sig_ == nullptr) return;
	
	// Allocate buffers for public and secret keys
	uint8_t *public_key = new uint8_t[sig_->length_public_key];
	uint8_t *secret_key = new uint8_t[sig_->length_secret_key];
	
	// Generate keypair
	OQS_STATUS status = OQS_SIG_keypair(sig_, public_key, secret_key);
	
	if (status == OQS_SUCCESS) {
		// Store keys as vectors
		sig_public_key_.assign(public_key, public_key + sig_->length_public_key);
		sig_secret_key_.assign(secret_key, secret_key + sig_->length_secret_key);
		
		if (debug_) {
			std::cout << "UWPQC: Generated SIG keypair (" 
				  << sig_->length_public_key << " byte pubkey, "
				  << sig_->length_secret_key << " byte privkey)" << std::endl;
		}
	} else {
		std::cerr << "UWPQC: Failed to generate SIG keypair" << std::endl;
	}
	
	delete[] public_key;
	delete[] secret_key;
#endif
}

std::vector<uint8_t>
packerUWPQC::encapsulate(const std::vector<uint8_t>& plaintext)
{
#ifdef HAVE_LIBOQS
	if (kem_ == nullptr || kem_public_key_.empty()) {
		return std::vector<uint8_t>();
	}
	
	// Allocate ciphertext buffer
	uint8_t *ciphertext = new uint8_t[kem_->length_ciphertext];
	uint8_t *shared_secret = new uint8_t[kem_->length_shared_secret];
	
	// Encapsulate with the public key
	OQS_STATUS status = OQS_KEM_encaps(kem_, ciphertext, shared_secret,
									   kem_public_key_.data());
	
	std::vector<uint8_t> result;
	if (status == OQS_SUCCESS) {
		result.assign(ciphertext, ciphertext + kem_->length_ciphertext);
		shared_secret_.assign(shared_secret, shared_secret + kem_->length_shared_secret);
		
		if (debug_) {
			std::cout << "UWPQC: Encapsulated data (" 
				  << result.size() << " bytes ciphertext)" << std::endl;
		}
	} else {
		std::cerr << "UWPQC: Failed to encapsulate" << std::endl;
	}
	
	delete[] ciphertext;
	delete[] shared_secret;
	return result;
#endif
	return std::vector<uint8_t>();
}

std::vector<uint8_t>
packerUWPQC::decapsulate(const std::vector<uint8_t>& ciphertext)
{
#ifdef HAVE_LIBOQS
	if (kem_ == nullptr || kem_secret_key_.empty()) {
		return std::vector<uint8_t>();
	}
	
	// Allocate shared secret buffer
	uint8_t *shared_secret = new uint8_t[kem_->length_shared_secret];
	
	// Decapsulate with the secret key
	OQS_STATUS status = OQS_KEM_decaps(kem_, shared_secret,
									   ciphertext.data(),
									   kem_secret_key_.data());
	
	std::vector<uint8_t> result;
	if (status == OQS_SUCCESS) {
		result.assign(shared_secret, shared_secret + kem_->length_shared_secret);
		
		if (debug_) {
			std::cout << "UWPQC: Decapsulated data (" 
				  << result.size() << " bytes shared secret)" << std::endl;
		}
	} else {
		std::cerr << "UWPQC: Failed to decapsulate" << std::endl;
	}
	
	delete[] shared_secret;
	return result;
#endif
	return std::vector<uint8_t>();
}

std::vector<uint8_t>
packerUWPQC::sign(const std::vector<uint8_t>& message)
{
#ifdef HAVE_LIBOQS
	if (sig_ == nullptr || sig_secret_key_.empty()) {
		return std::vector<uint8_t>();
	}
	
	// Allocate signature buffer
	uint8_t *signature = new uint8_t[sig_->length_signature];
	size_t sig_len = 0;
	
	// Sign the message
	OQS_STATUS status = OQS_SIG_sign(sig_, signature, &sig_len,
									 message.data(), message.size(),
									 sig_secret_key_.data());
	
	std::vector<uint8_t> result;
	if (status == OQS_SUCCESS) {
		result.assign(signature, signature + sig_len);
		
		if (debug_) {
			std::cout << "UWPQC: Signed message (" 
				  << result.size() << " bytes signature)" << std::endl;
		}
	} else {
		std::cerr << "UWPQC: Failed to sign message" << std::endl;
	}
	
	delete[] signature;
	return result;
#endif
	return std::vector<uint8_t>();
}

bool
packerUWPQC::verify(const std::vector<uint8_t>& message, 
					 const std::vector<uint8_t>& signature)
{
#ifdef HAVE_LIBOQS
	if (sig_ == nullptr || sig_public_key_.empty()) {
		return false;
	}
	
	// Verify the signature
	OQS_STATUS status = OQS_SIG_verify(sig_, message.data(), message.size(),
									   signature.data(), signature.size(),
									   sig_public_key_.data());
	
	if (status == OQS_SUCCESS) {
		if (debug_) {
			std::cout << "UWPQC: Signature verification successful" << std::endl;
		}
		return true;
	} else {
		if (debug_) {
			std::cout << "UWPQC: Signature verification failed" << std::endl;
		}
		return false;
	}
#endif
	return false;
}

size_t
packerUWPQC::packMyHdr(Packet *p, unsigned char *buf, size_t offset)
{
	hdr_uwpqc hdr;
	hdr.version_ = 1;
	hdr.flags_ = 0;
	hdr.ct_len_ = 0;
	hdr.sig_len_ = 0;

	hdr_cmn *ch = HDR_CMN(p);
	const size_t pkt_payload_len = (ch != nullptr && ch->size() > 0)
		? static_cast<size_t>(ch->size())
		: 0;
	const uint16_t seq_no = (ch != nullptr) ? static_cast<uint16_t>(ch->uid() & 0xFFFF) : 0;
	const size_t pqc_material_len = (pkt_payload_len > 0)
		? std::min(pkt_payload_len, static_cast<size_t>(256))
		: 16;

	std::vector<uint8_t> packet_material(pqc_material_len, 0);
	for (size_t i = 0; i < pqc_material_len; i++) {
		packet_material[i] = static_cast<uint8_t>((seq_no + i) & 0xFF);
	}
	
	if (use_kem_) {
		hdr.flags_ |= 0x01;
		std::vector<uint8_t> ciphertext = encapsulate(packet_material);
		if (!ciphertext.empty()) {
			hdr.ct_len_ = (ciphertext.size() > 512) ? 512 : ciphertext.size();
		}
	}
	
	if (use_sig_) {
		hdr.flags_ |= 0x02;
		std::vector<uint8_t> signature = sign(packet_material);
		if (!signature.empty()) {
			hdr.sig_len_ = (signature.size() > 512) ? 512 : signature.size();
		}
	}
	
	// Pack the header fields using packer's put() method
	int field_idx = 0;
	offset += put(buf, offset, &hdr.version_, n_bits[field_idx++]);
	offset += put(buf, offset, &hdr.flags_, n_bits[field_idx++]);
	offset += put(buf, offset, &hdr.ct_len_, n_bits[field_idx++]);
	offset += put(buf, offset, &hdr.sig_len_, n_bits[field_idx++]);
	
	if (debug_) {
		std::cout << "\033[0;46;30m TX PQC packer hdr \033[0m" << std::endl;
		std::cout << "  CBR SN: " << seq_no << " packet_size: " << pkt_payload_len << " material_len: " << pqc_material_len << std::endl;
		printMyHdrFields(p);
	}
	
	return offset;
}

size_t
packerUWPQC::unpackMyHdr(unsigned char *buf, size_t offset, Packet *p)
{
	hdr_uwpqc hdr;
	memset(&hdr, 0, sizeof(hdr));
	
	// Unpack the header fields using packer's get() method
	int field_idx = 0;
	offset += get(buf, offset, &hdr.version_, n_bits[field_idx++]);
	offset += get(buf, offset, &hdr.flags_, n_bits[field_idx++]);
	offset += get(buf, offset, &hdr.ct_len_, n_bits[field_idx++]);
	offset += get(buf, offset, &hdr.sig_len_, n_bits[field_idx++]);
	
	if (debug_) {
		std::cout << "\033[0;46;30m RX PQC packer hdr \033[0m" << std::endl;
		std::cout << "  Version: " << (int)hdr.version_ << std::endl;
		std::cout << "  Flags: 0x" << std::hex << (int)hdr.flags_ << std::dec << std::endl;
		std::cout << "  Ciphertext length: " << hdr.ct_len_ << " bytes" << std::endl;
		std::cout << "  Signature length: " << hdr.sig_len_ << " bytes" << std::endl;
	}
	
	return offset;
}

void
packerUWPQC::printMyHdrMap()
{
	std::cout << "\033[0;46;30m Packer Name \033[0m: UWPQC (Post-Quantum Cryptography)" << std::endl;
#ifdef HAVE_LIBOQS
	std::cout << "  liboqs version: " << OQS_VERSION_TEXT << std::endl;
	if (!pqc_kem_alg_.empty()) {
		std::cout << "  KEM Algorithm: " << pqc_kem_alg_ << std::endl;
		std::cout << "    version_: " << version_bits_ << " bits" << std::endl;
		std::cout << "    flags_: " << flags_bits_ << " bits" << std::endl;
		std::cout << "    ct_len_: " << ct_len_bits_ << " bits" << std::endl;
		std::cout << "    sig_len_: " << sig_len_bits_ << " bits" << std::endl;
	}
	if (!pqc_sig_alg_.empty()) {
		std::cout << "  SIG Algorithm: " << pqc_sig_alg_ << std::endl;
	}
#else
	std::cout << "  WARNING: liboqs not available - PQC features disabled" << std::endl;
#endif
}

void
packerUWPQC::printMyHdrFields(Packet *p)
{
	std::cout << "  UWPQC packer header: ";
	std::cout << "(use_kem=" << use_kem_ << " use_sig=" << use_sig_ << ")" << std::endl;
}

