#ifndef __DOMAIN__H
#define __DOMAIN__H

#include <sys/types.h>
#include <time.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define DNS_PKT_LEN 2048
#define MAX_IP_LEN 10 /*max ip size*/

struct header {
	uint16_t	tid;/*Trans ID 会话id*/
	uint16_t	flags;/*Flags 标识*/
	uint16_t	questions;/*Questions 问题数*/
	uint16_t	answers;/*Answer RRs 回答的资源记录*/
	uint16_t	auths;/*Auth RRs 授权什么的 不关心*/
	uint16_t	others;/*附加信息*/
	unsigned char data[1];/*data block 数据区 因为是变长的 保存首地址就行了*/
};
int request_packet_creater(char *pkt, int *size, char *domainname);
int response_packet_parser(char *pkt, int pktlen, char arr[][16], int arrsize);
int get_domain_realip(char *domain, int timeout, char arr[][16], int arrsize);

#endif