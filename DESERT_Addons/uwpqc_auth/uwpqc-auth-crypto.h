#ifndef UWPQC_AUTH_CRYPTO_H
#define UWPQC_AUTH_CRYPTO_H

#include <oqs/oqs.h>

#include <cstdint>
#include <string>
#include <vector>

class UwPqcAuthCrypto
{
public:
	UwPqcAuthCrypto();
	~UwPqcAuthCrypto();

	bool available() const;
	bool createIdentity(std::vector<uint8_t> &public_key,
			std::vector<uint8_t> &secret_key) const;
	bool sign(const std::vector<uint8_t> &secret_key,
			const std::vector<uint8_t> &message,
			std::vector<uint8_t> &signature) const;
	bool verify(const std::vector<uint8_t> &public_key,
			const std::vector<uint8_t> &message,
			const std::vector<uint8_t> &signature) const;
	bool kemKeypair(std::vector<uint8_t> &public_key,
			std::vector<uint8_t> &secret_key) const;
	bool encapsulate(const std::vector<uint8_t> &public_key,
			std::vector<uint8_t> &ciphertext,
			std::vector<uint8_t> &shared_secret) const;
	bool decapsulate(const std::vector<uint8_t> &secret_key,
			const std::vector<uint8_t> &ciphertext,
			std::vector<uint8_t> &shared_secret) const;
	bool deriveConfirmationKey(const std::vector<uint8_t> &shared_secret,
			const std::vector<uint8_t> &transcript,
			std::vector<uint8_t> &confirmation_key) const;
	bool hmac(const std::vector<uint8_t> &key,
			const std::vector<uint8_t> &message,
			std::vector<uint8_t> &tag) const;
	bool random(uint8_t *buffer, size_t length) const;
	std::string base64Encode(const std::vector<uint8_t> &value) const;
	bool base64Decode(const std::string &encoded, std::vector<uint8_t> &value) const;
	void cleanse(std::vector<uint8_t> &value) const;

	const OQS_KEM *kem() const { return kem_; }
	const OQS_SIG *signature() const { return signature_; }

private:
	OQS_KEM *kem_;
	OQS_SIG *signature_;
};

#endif