#include "global.h"
#include "malk.h"
#include <stdio.h>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "Setupapi.lib")
#pragma comment(lib, "Newdev.lib")
#pragma comment(lib, "FltLib.lib")

int main(int argc, char** argv)
{
	if (argc < 2) {
		printf(
			"Usage: malk <Command>\n"
			"  -dse [addr]  : write user defined address to the CiValidateImageHeader callback (0 or omitted for writing the rand function address)\n"
			"  -cb          : demonstrate kernel process creation callback\n"
		);
		return 1;
	}

	if (strcmp(argv[1], "-dse") == 0) {
		// driver signature enforcement
		ULONG64 val = 0;
		if (argc > 2) {
			val = strtoull(argv[2], NULL, 0);
		}
		setDigitalSignatureEnforcementCallback(val);
	}
	else if (strcmp(argv[1], "-cb") == 0) {
		// create process callback
		demoKernelCreateProcessCallback();
	}

	return 0;
}