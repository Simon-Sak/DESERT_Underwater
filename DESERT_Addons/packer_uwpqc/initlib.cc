#include <tclcl.h>

extern EmbeddedTcl UwpqcTclCode;

extern "C" int
Uwpqc_Init()
{
	UwpqcTclCode.load();
	return 0;
}
