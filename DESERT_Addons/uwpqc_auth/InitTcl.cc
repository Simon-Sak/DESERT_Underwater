static char code[] = "PacketHeaderManager set tab_(PacketHeader/UWPQC_AUTH) 1\n\
\n\
Module/UW/PQCAuth set debug_ 0\n\
Module/UW/PQCAuth set destPort_ 0\n\
Module/UW/PQCAuth set destAddr_ 0\n\
Module/UW/PQCAuth set localAddr_ 0\n\
Module/UW/PQCAuth set kemAlgorithm_ \"NTRU-HRSS-701\"\n\
Module/UW/PQCAuth set signatureAlgorithm_ \"Falcon-512\"\n\
Module/UW/PQCAuth set maxFragmentPayload_ 96\n\
Module/UW/PQCAuth set retransmitTimeout_ 8.0\n\
Module/UW/PQCAuth set maxRetries_ 3\n\
Module/UW/PQCAuth set sessionTimeout_ 60.0";
#include "tclcl.h"
EmbeddedTcl UwpqcauthInitTclCode(code);
