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

int request_packet(char *pkt, int *size, char *domainname)
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

#if 0
int pkt_parser(char *pkt)
{
	struct header *hdr = NULL;
	unsigned char *data = NULL;

	hdr = (struct header*)pkt;
	pdata = hdr->data;
}
#endif

int main (int argc, char **argv)
{
	int sockfd = 0;
	int nsend = 0;
	int nrecv = 0;
	char pkt[DNS_PKT_LEN] = {0};
	fd_set set = {0};
	struct timeval tv = {3,0};
	struct sockaddr_in saddr = {0};

	if (argc < 2) {
		printf("usage: %s ip.address\n", argv[0]);
		exit(-1);
	}

	/*建立UDP无连接请求*/
	if ((sockfd = socket(PF_INET, SOCK_DGRAM, 17)) < 0) {
		printf("socket init failed\n");
		exit(-1);
	}
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(53);
	saddr.sin_addr.s_addr = inet_addr("127.0.1.1");

	request_packet(pkt, &nsend, argv[1]);
	for (int i =0; i < nsend; i++) {
		printf("(%d)", pkt[i]);
	}

	if (sendto(sockfd, pkt, nsend, 0, 
	    (struct sockaddr *) &saddr, sizeof(saddr)) != -1) {
		/*接收*/
		printf("send ok\n");
		struct sockaddr_in	sa;
		int len = sizeof(sa);

		FD_ZERO(&set);
		FD_SET(sockfd, &set);
		if (select(sockfd + 1, &set, NULL, NULL, &tv) != 1) {
			printf("timeout\n");
			return -4;
		}
		memset(pkt, 0, sizeof(pkt));
		nrecv = recvfrom(sockfd, pkt, sizeof(pkt), 0, (struct sockaddr *)&sa, &len);
		if (nrecv > 0 && nrecv > sizeof(struct header)) {
			for (int i = 0; i < nrecv; i++)
			printf("(%d)", ((unsigned char*)pkt)[i]);
		printf("recv ok\n");
	}
		/*解析*/
	}
	close(sockfd); 
}
