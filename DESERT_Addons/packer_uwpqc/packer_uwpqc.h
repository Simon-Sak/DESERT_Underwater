//
// Copyright (c) 2024 Regents of the SIGNET lab, University of Padova.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
// 3. Neither the name of the University of Padova (SIGNET lab) nor the
//    names of its contributors may be used to endorse or promote products
//    derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
// TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
// OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
// WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
// OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
// ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

/**
 * @file packer_uwpqc.h
 * @author DESERT Team
 * \version 1.0.0
 * \brief Header file for Post-Quantum Cryptography (PQC) packer module
 *        using liboqs for KEM (Key Encapsulation) and Signature operations
 */

#ifndef PACKER_UWPQC_H
#define PACKER_UWPQC_H

#include "packer.h"
#include <vector>
#include <string>
#include <cstdint>

#ifdef HAVE_LIBOQS
#include <oqs/oqs.h>
#endif

/**
 * Header structure for PQC packer
 */
struct hdr_uwpqc {
	uint8_t version_;   ///< Protocol version
	uint8_t flags_;     ///< Flags (bit 0: KEM enabled, bit 1: SIG enabled)
	uint16_t ct_len_;   ///< Ciphertext length
	uint16_t sig_len_;  ///< Signature length
};

/**
 * PQC Packer class - handles Post-Quantum Cryptography operations
 * Inherits from packer base class to provide KEM encapsulation/decapsulation
 * and digital signature generation/verification
 */
class packerUWPQC : public packer
{
public:
	/**
	 * Class constructor.
	 */
	packerUWPQC();

	/**
	 * Class destructor.
	 */
	~packerUWPQC();

	/**
	 * TCL command handler
	 */
	int command(int argc, const char *const *argv);

private:
	/**
	 * Initialize the packer
	 */
	void init();

	/**
	 * Initialize PQC algorithms
	 */
	void initPQCAlgorithms();

	/**
	 * Get default KEM algorithm
	 */
	std::string getDefaultKEMAlgorithm();

	/**
	 * Get default signature algorithm
	 */
	std::string getDefaultSigAlgorithm();

	/**
	 * Resolve signature algorithm name (handle aliases and case-insensitive lookup)
	 */
	std::string resolveSignatureAlgorithm(const std::string& requested) const;

	/**
	 * Generate KEM keypair
	 */
	void generateKEMKeys();

	/**
	 * Generate signature keypair
	 */
	void generateSigKeys();

	/**
	 * Encapsulate plaintext using KEM
	 */
	std::vector<uint8_t> encapsulate(const std::vector<uint8_t>& plaintext);

	/**
	 * Decapsulate ciphertext using KEM
	 */
	std::vector<uint8_t> decapsulate(const std::vector<uint8_t>& ciphertext);

	/**
	 * Sign a message
	 */
	std::vector<uint8_t> sign(const std::vector<uint8_t>& message);

	/**
	 * Verify a signature
	 */
	bool verify(const std::vector<uint8_t>& message,
				const std::vector<uint8_t>& signature);

	/**
	 * Method to transform the headers into a stream of bits
	 */
	size_t packMyHdr(Packet *, unsigned char *, size_t);

	/**
	 * Method to unpack headers from a bit stream
	 */
	size_t unpackMyHdr(unsigned char *, size_t, Packet *);

	/**
	 * Print header map for debug
	 */
	void printMyHdrMap();

	/**
	 * Print header fields for debug
	 */
	void printMyHdrFields(Packet *);

	// Configuration parameters
	size_t version_bits_;   ///< Number of bits for version field
	size_t flags_bits_;     ///< Number of bits for flags field
	size_t ct_len_bits_;    ///< Number of bits for ciphertext length field
	size_t sig_len_bits_;   ///< Number of bits for signature length field
	int use_kem_;           ///< Flag to enable KEM operations
	int use_sig_;           ///< Flag to enable signature operations

#ifdef HAVE_LIBOQS
	// liboqs KEM and signature algorithm pointers
	OQS_KEM *kem_;          ///< KEM algorithm context
	OQS_SIG *sig_;          ///< Signature algorithm context

	// Algorithm names
	std::string pqc_kem_alg_;   ///< Current KEM algorithm name
	std::string pqc_sig_alg_;   ///< Current signature algorithm name

	// Key material
	std::vector<uint8_t> kem_public_key_;   ///< KEM public key
	std::vector<uint8_t> kem_secret_key_;   ///< KEM secret key
	std::vector<uint8_t> sig_public_key_;   ///< Signature public key
	std::vector<uint8_t> sig_secret_key_;   ///< Signature secret key
	std::vector<uint8_t> shared_secret_;    ///< Shared secret from encapsulation
#endif
};

#endif
