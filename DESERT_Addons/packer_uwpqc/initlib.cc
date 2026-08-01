#include <tclcl.h>

extern EmbeddedTcl PackerUwpqcTclCode;

extern "C" int
Packeruwpqc_Init()
{
	PackerUwpqcTclCode.load();
	return 0;
}
