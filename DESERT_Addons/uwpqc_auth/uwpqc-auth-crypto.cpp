#include "uwpqc-auth-crypto.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>

#include <algorithm>

UwPqcAuthCrypto::UwPqcAuthCrypto()
	: kem_(OQS_KEM_new(OQS_KEM_alg_ntru_hrss701))
	, signature_(OQS_SIG_new(OQS_SIG_alg_falcon_512))
{
}

UwPqcAuthCrypto::~UwPqcAuthCrypto()
{
	OQS_KEM_free(kem_);
	OQS_SIG_free(signature_);
}

bool
UwPqcAuthCrypto::available() const
{
	return kem_ != nullptr && signature_ != nullptr;
}

bool
UwPqcAuthCrypto::createIdentity(
		std::vector<uint8_t> &public_key, std::vector<uint8_t> &secret_key) const
{
	if (!available())
		return false;
	public_key.resize(signature_->length_public_key);
	secret_key.resize(signature_->length_secret_key);
	return OQS_SIG_keypair(signature_, public_key.data(), secret_key.data()) == OQS_SUCCESS;
}

bool
UwPqcAuthCrypto::sign(const std::vector<uint8_t> &secret_key,
		const std::vector<uint8_t> &message, std::vector<uint8_t> &signature) const
{
	if (!available() || secret_key.size() != signature_->length_secret_key)
		return false;
	signature.resize(signature_->length_signature);
	size_t length = 0;
	if (OQS_SIG_sign(signature_, signature.data(), &length, message.data(),
				message.size(), secret_key.data()) != OQS_SUCCESS)
		return false;
	signature.resize(length);
	return true;
}

bool
UwPqcAuthCrypto::verify(const std::vector<uint8_t> &public_key,
		const std::vector<uint8_t> &message,
		const std::vector<uint8_t> &signature) const
{
	return available() && public_key.size() == signature_->length_public_key
			&& OQS_SIG_verify(signature_, message.data(), message.size(),
					signature.data(), signature.size(), public_key.data()) == OQS_SUCCESS;
}

bool
UwPqcAuthCrypto::kemKeypair(
		std::vector<uint8_t> &public_key, std::vector<uint8_t> &secret_key) const
{
	if (!available())
		return false;
	public_key.resize(kem_->length_public_key);
	secret_key.resize(kem_->length_secret_key);
	return OQS_KEM_keypair(kem_, public_key.data(), secret_key.data()) == OQS_SUCCESS;
}

bool
UwPqcAuthCrypto::encapsulate(const std::vector<uint8_t> &public_key,
		std::vector<uint8_t> &ciphertext,
		std::vector<uint8_t> &shared_secret) const
{
	if (!available() || public_key.size() != kem_->length_public_key)
		return false;
	ciphertext.resize(kem_->length_ciphertext);
	shared_secret.resize(kem_->length_shared_secret);
	return OQS_KEM_encaps(kem_, ciphertext.data(), shared_secret.data(),
				public_key.data()) == OQS_SUCCESS;
}

bool
UwPqcAuthCrypto::decapsulate(const std::vector<uint8_t> &secret_key,
		const std::vector<uint8_t> &ciphertext,
		std::vector<uint8_t> &shared_secret) const
{
	if (!available() || secret_key.size() != kem_->length_secret_key
			|| ciphertext.size() != kem_->length_ciphertext)
		return false;
	shared_secret.resize(kem_->length_shared_secret);
	return OQS_KEM_decaps(kem_, shared_secret.data(), ciphertext.data(),
				secret_key.data()) == OQS_SUCCESS;
}

bool
UwPqcAuthCrypto::deriveConfirmationKey(const std::vector<uint8_t> &shared_secret,
		const std::vector<uint8_t> &transcript,
		std::vector<uint8_t> &confirmation_key) const
{
	EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
	if (context == nullptr)
		return false;
	confirmation_key.resize(32);
	size_t length = confirmation_key.size();
	const unsigned char info[] = "uwpqc-auth-confirmation";
	bool success = EVP_PKEY_derive_init(context) > 0
			&& EVP_PKEY_CTX_set_hkdf_md(context, EVP_sha256()) > 0
			&& EVP_PKEY_CTX_set1_hkdf_salt(context, transcript.data(), transcript.size()) > 0
			&& EVP_PKEY_CTX_set1_hkdf_key(context, shared_secret.data(), shared_secret.size()) > 0
			&& EVP_PKEY_CTX_add1_hkdf_info(context, info, sizeof(info) - 1) > 0
			&& EVP_PKEY_derive(context, confirmation_key.data(), &length) > 0;
	EVP_PKEY_CTX_free(context);
	if (!success || length != confirmation_key.size()) {
		cleanse(confirmation_key);
		return false;
	}
	return true;
}

bool
UwPqcAuthCrypto::hmac(const std::vector<uint8_t> &key,
		const std::vector<uint8_t> &message, std::vector<uint8_t> &tag) const
{
	unsigned int length = EVP_MAX_MD_SIZE;
	tag.resize(length);
	if (HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()), message.data(),
				message.size(), tag.data(), &length) == nullptr)
		return false;
	tag.resize(length);
	return true;
}

bool
UwPqcAuthCrypto::random(uint8_t *buffer, size_t length) const
{
	if (buffer == nullptr)
		return false;
	OQS_randombytes(buffer, length);
	return true;
}

std::string
UwPqcAuthCrypto::base64Encode(const std::vector<uint8_t> &value) const
{
	std::vector<unsigned char> encoded(4 * ((value.size() + 2) / 3) + 1);
	int length = EVP_EncodeBlock(encoded.data(), value.data(), value.size());
	return length < 0 ? "" : std::string(reinterpret_cast<char *>(encoded.data()), length);
}

bool
UwPqcAuthCrypto::base64Decode(const std::string &encoded, std::vector<uint8_t> &value) const
{
	if (encoded.empty() || encoded.size() % 4 != 0)
		return false;
	value.resize((encoded.size() / 4) * 3);
	int length = EVP_DecodeBlock(value.data(),
			reinterpret_cast<const unsigned char *>(encoded.data()), encoded.size());
	if (length < 0)
		return false;
	if (!encoded.empty() && encoded[encoded.size() - 1] == '=')
		--length;
	if (encoded.size() > 1 && encoded[encoded.size() - 2] == '=')
		--length;
	value.resize(length);
	return true;
}

void
UwPqcAuthCrypto::cleanse(std::vector<uint8_t> &value) const
{
	if (!value.empty())
		OQS_MEM_cleanse(value.data(), value.size());
	value.clear();
}