#include "uwpqc-auth-packet.h"

#include <tclcl.h>

packet_t PT_UWPQC_AUTH;

extern EmbeddedTcl UwpqcauthInitTclCode;

extern "C" int
Uwpqcauth_Init()
{
	PT_UWPQC_AUTH = p_info::addPacket("PQC_AUTH");
	UwpqcauthInitTclCode.load();
	return 0;
}

extern "C" int
Uwpqc_auth_Init()
{
	return Uwpqcauth_Init();
}

extern "C" int
Cyguwpqcauth_Init()
{
	return Uwpqcauth_Init();
}