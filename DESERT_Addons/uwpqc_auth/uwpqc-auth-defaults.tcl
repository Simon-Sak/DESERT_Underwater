PacketHeaderManager set tab_(PacketHeader/UWPQC_AUTH) 1

Module/UW/PQCAuth set debug_ 0
Module/UW/PQCAuth set destPort_ 0
Module/UW/PQCAuth set destAddr_ 0
Module/UW/PQCAuth set localAddr_ 0
Module/UW/PQCAuth set maxFragmentPayload_ 96
Module/UW/PQCAuth set retransmitTimeout_ 8.0
Module/UW/PQCAuth set maxRetries_ 3

# KEM and signature algorithms default to NTRU-HRSS-701 and Falcon-512 in the
# module's C++ constructor; use the per-instance "setKemAlgorithm" /
# "setSignatureAlgorithm" commands to switch to ML-KEM/HQC or ML-DSA/SLH-DSA.
