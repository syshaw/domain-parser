#include <time.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/select.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define DNS_PKT_LEN 2048

struct header {
	uint16_t	tid;/*Trans ID 会话id*/
	uint16_t	flags;/*Flags 标识*/
	uint16_t	questions;/*Questions 问题数*/
	uint16_t	answers;/*Answer RRs 回答的资源记录*/
	uint16_t	auths;/*Auth RRs 授权什么的 不关心*/
	uint16_t	others;/*附加信息*/
	unsigned char data[1];/*data block 数据区 因为是变长的 保存首地址就行了*/
};

int request_packet_creater(char *pkt, int *size, char *domainname)
{
	struct header *hdr = NULL;
	int domainlen = 0;
	char *tmp = NULL, *pname = NULL;
	int chunklen = 0;

	/*构造dns头*/
	hdr = (struct header*)pkt;
	hdr->tid = 1;
	hdr->flags = htons(0x0100);
	hdr->questions = htons(0x0001);
	hdr->answers = 0;
	hdr->auths = 0;
	hdr->others = 0;

	/*query字段里添加domain信息*/
	domainlen = strlen(domainname);
	pname = domainname;

	tmp = (char *)&hdr->data;

	char *cur = NULL;
	do {
		if ((cur = strchr(pname, '.')) == NULL) chunklen = domainlen;
		else chunklen = cur - pname;
		*tmp++ = chunklen;
 		for (int i = 0; i < chunklen; i++) *tmp++ = pname[i];
		if (cur != NULL && *cur == '.') chunklen++;
		pname+=chunklen;
		domainlen-=chunklen;
	} while(cur != NULL);

	*tmp++ = 0;
	*tmp++ = 0;	
	*tmp++ = 1;
	*tmp++ = 0;
	*tmp++ = 1;

	*size = tmp - pkt;

	return 0;
}

int response_packet_parser(char *pkt, int pktlen, char arr[][16], int arrsize)
{
	int i = 0, j =0;
	struct header *hdr = NULL;
	unsigned char *data = NULL;
	int datalen = 0;

	if (!pkt && pktlen < 0 && !arr && arrsize < 0) {
		return -1;
	}

	hdr = (struct header*)pkt;
	data = hdr->data;

	/*跳过域名*/
	while(*data++);

	/*只查type=1 class=1时的*/
	if (htons(((uint16_t *)data)[0]) != 1 && htons(((uint16_t *)data)[1]) != 1) {
		return -2;
	}

	data+=4;
	/*有记录哦*/
	if (*data != 0xc0) {
		return -3;
	}
	/*可能answer中会有type=5(CNAME)项 得跳过*/
	if (htons(((uint16_t *)data)[1]) == 5) {
		data+=12;
		datalen = htons(*((uint16_t *)(data - 2)));
		data+=datalen;
	}
	for(i = 0; htons(((uint16_t *)data)[1]) == 1 && htons(((uint16_t *)data)[2]) == 1 && i < arrsize; i++) {
		/*跳过 domain(16bit) type(16bit)   class(16bit) ttl(32bit) = 10byte*/
		data+=10;
		datalen = htons(((uint16_t *)data)[0]);
		data+=2;
		for (j = 0; j < datalen; j++) {
			snprintf(arr[i] + strlen(arr[i]), sizeof(arr[i]) - strlen(arr[i]), "%d%s", *data++, ((j + 1) == datalen)?"":".");
		}
	}

	return 0;
}

int get_domain_realip(char *domain, int timeout, char arr[][16], int arrsize)
{
	int ret = -1;
	int sockfd = 0;
	int nsend = 0;
	int nrecv = 0;
	char pkt[DNS_PKT_LEN] = {0};
	fd_set set = {0};
	struct timeval tv = {0};
	struct sockaddr_in saddr = {0};

	if (!domain || timeout < 0 || !arr || arrsize < 0) {
		return -1;
	}

	request_packet_creater(pkt, &nsend, domain);

	/*建立UDP无连接请求*/
	if ((sockfd = socket(PF_INET, SOCK_DGRAM, 17)) < 0) {
		return -2;
	}
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(53);
	saddr.sin_addr.s_addr = inet_addr("127.0.1.1");

	if (sendto(sockfd, pkt, nsend, 0, 
	    (struct sockaddr *) &saddr, sizeof(saddr)) != -1) {
		struct sockaddr_in	sa;
		int len = sizeof(sa);

		tv.tv_sec = timeout;
		FD_ZERO(&set);
		FD_SET(sockfd, &set);

		if (select(sockfd + 1, &set, NULL, NULL, &tv) != 1) {
			close(sockfd); 
			return -3;
		}
		memset(pkt, 0, sizeof(pkt));
		nrecv = recvfrom(sockfd, pkt, sizeof(pkt), 0, (struct sockaddr *)&sa, &len);
		if (nrecv > 0 && nrecv > sizeof(struct header)) {
			ret = response_packet_parser(pkt, nrecv, arr, arrsize);
		}
	}
	close(sockfd); 

	return ret;
}

#define MAX_IP_LEN 10 /*max ip size*/

int main (int argc, char **argv)
{
	int i = 0;
	char iparr[MAX_IP_LEN][16] = {0};

	if (argc < 2) {
		printf("usage: %s ip.address\n", argv[0]);
		exit(-1);
	}

	if(!get_domain_realip(argv[1], 2, iparr, sizeof(iparr)/sizeof(iparr[0]))) {
		for (; iparr[i][0]; i++) {
			printf("%s\n", iparr[i]);
		}
	} else {
		printf("parse domain failed\n");
	}
	return 0;
}
