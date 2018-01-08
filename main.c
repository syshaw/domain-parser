#include "domain/domain.h"

int main (int argc, char **argv)
{
	int i = 0;
	int len = 0;
	char iparr[MAX_IP_LEN][16] = {0};

	if (argc < 2) {
		printf("usage: %s ip.address\n", argv[0]);
		exit(-1);
	}
	len = sizeof(iparr)/sizeof(iparr[0]);
	if(!get_domain_realip(argv[1], 2, iparr, len)) {
		for (; i < len && iparr[i][0]; i++) {
			printf("%s\n", iparr[i]);
		}
	} else {
		printf("parse domain failed\n");
	}
	return 0;
}
