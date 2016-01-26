//--------------------------------------【程序说明】-------------------------------------------
//		程序描述：Winpcap的抓包与还原
//		开发测试所用操作系统： Windows 8.1 64bit
//		开发测试所用IDE版本：Visual Studio 2015
//		2015年11月28日 Created by @CodeLadyJJY
//------------------------------------------------------------------------------------------------


#include "pcap.h"
#include <winsock2.h>
#include <string.h>

#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "Ws2_32.lib")

#define LINE_LEN 16
#define MAX_ADDR_LEN 16

FILE *file = 0;

// 以太网协议格式的定义
typedef struct ether_header {
	u_char ether_dhost[6];		// 目标MAC地址
	u_char ether_shost[6];		// 源MAC地址
	u_short ether_type;			// 以太网类型
}ether_header;

// 用户保存4字节的IP地址
typedef struct ip_address {
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

// 用于保存IPV4的首部
typedef struct ip_header {
	u_char version_hlen;		// 首部长度 版本
	u_char tos;					// 服务质量
	u_short tlen;				// 总长度
	u_short identification;		// 身份识别
	u_short flags_offset;		// 标识 分组偏移
	u_char ttl;					// 生命周期
	u_char proto;				// 协议类型
	u_short checksum;			// 包头测验码
	u_int saddr;				// 源IP地址
	u_int daddr;				// 目的IP地址
}ip_header;

// 用于保存TCP首部
typedef struct tcp_header {
	u_short sport;
	u_short dport;
	u_int sequence;				// 序列码
	u_int ack;					// 回复码
	u_char hdrLen;				// 首部长度保留字
	u_char flags;				// 标志
	u_short windows;			// 窗口大小
	u_short checksum;			// 校验和
	u_short urgent_pointer;		// 紧急指针
}tcp_header;

// 用于保存UDP的首部
typedef struct udp_header {
	u_short sport;				// 源端口
	u_short dport;				// 目标端口
	u_short datalen;			// UDP数据长度
	u_short checksum;			// 校验和
}udp_header;

// 用于保存ICMP的首部
typedef struct icmp_header {
	u_char type;				// ICMP类型
	u_char code;				// 代码
	u_short checksum;			// 校验和
	u_short identification;		// 标识
	u_short sequence;			// 序列号
	u_long timestamp;			// 时间戳
}icmp_header;

// 用于保存ARP的首部
typedef struct arp_header {
	u_short hardware_type;					// 格式化的硬件地址
	u_short protocol_type;					// 协议地址格式
	u_char hardware_length;					// 硬件地址长度
	u_char protocol_length;					// 协议地址长度
	u_short operation_code;					// 操作码
	u_char source_ethernet_address[6];		// 发送者硬件地址
	u_char source_ip_address[4];			// 发送者协议地址
	u_char destination_ethernet_address[6];	// 目的方硬件地址
	u_char destination_ip_address[4];		// 目的方协议地址
}arp_header;

// TCP协议处理
//u_short sport;
//u_short dport;
//u_int sequence;			// 序列码
//u_int ack;				// 回复码
//u_char hdrLen;			// 首部长度保留字
//u_char flags;				// 标志
//u_short windows;			// 窗口大小
//u_short checksum;			// 校验和
//u_short urgent_pointer;	// 紧急指针
void tcp_protocol_packet_handle(u_char *arg, const struct pcap_pkthdr *pkt_header, const u_char *pkt_content)
{
	tcp_header *tcp_protocol;

	tcp_protocol = (tcp_header*)(pkt_content + 14 + 20);

	printf("===================TCP Protocol=================\n");

	printf("Source Port: %i\n", ntohs(tcp_protocol->sport));
	printf("Destination Port: %i\n", ntohs(tcp_protocol->dport));
	printf("Sequence number: %d\n", ntohl(tcp_protocol->sequence));
	printf("Acknowledgment number: %d\n", ntohl(tcp_protocol->ack));
	printf("Header Length: %d\n", (tcp_protocol->hdrLen >> 4) * 4);
	printf("Flags: 0x%.3x ", tcp_protocol->flags);
	if (tcp_protocol->flags & 0x08) printf("(PSH)");
	if (tcp_protocol->flags & 0x10) printf("(ACK)");
	if (tcp_protocol->flags & 0x02) printf("(SYN)");
	if (tcp_protocol->flags & 0x20) printf("(URG)");
	if (tcp_protocol->flags & 0x01) printf("(FIN)");
	if (tcp_protocol->flags & 0x04) printf("(RST)");
	printf("\n");
	printf("Windows Size: %i\n", ntohs(tcp_protocol->windows));
	printf("Checksum: 0x%.4x\n", ntohs(tcp_protocol->checksum));
	printf("Urgent Pointer: %i\n", ntohs(tcp_protocol->urgent_pointer));
}

// UDP协议处理
//u_short sport;			// 源端口
//u_short dport;			// 目标端口
//u_short datalen;			// UDP数据长度
//u_short checksum;			// 校验和
void udp_protocol_packet_handle(u_char *arg, const struct pcap_pkthdr *pkt_header, const u_char *pkt_content)
{
	udp_header *udp_protocol;

	udp_protocol = (udp_header*)(pkt_content + 14 + 20);

	printf("===================UDP Protocol=================\n");
	printf("Source Port: %i\n", ntohs(udp_protocol->sport));
	printf("Destination Port: %i\n", ntohs(udp_protocol->dport));
	printf("Datalen: %i\n", ntohs(udp_protocol->datalen));
	printf("Checksum: 0x%.4x\n", ntohs(udp_protocol->checksum));
}

// ICMP协议处理
//u_char type;				// ICMP类型
//u_char code;				// 代码
//u_short checksum;			// 校验和
//u_short identification;	// 标识
//u_short sequence;			// 序列号
//u_long timestamp;			// 时间戳
void icmp_protocol_packet_handle(u_char *arg, const struct pcap_pkthdr *pkt_header, const u_char *pkt_content)
{
	icmp_header *icmp_protocol;

	icmp_protocol = (icmp_header*)(pkt_content + 14 + 20);

	printf("==================ICMP Protocol=================\n");
	printf("Type: %d ", icmp_protocol->type);
	switch (icmp_protocol->type)
	{
	case 8:
		printf("(request)\n");
		break;
	case 0:
		printf("(reply)\n");
		break;
	default:
		printf("\n");
		break;
	}
	printf("Code: %d\n", icmp_protocol->code);
	printf("CheckSum: 0x%.4x\n", ntohs(icmp_protocol->checksum));
	printf("Identification: 0x%.4x\n", ntohs(icmp_protocol->identification));
	printf("Sequence: 0x%.4x\n", ntohs(icmp_protocol->sequence));
}

// ARP协议处理
//u_short hardware_type;					// 格式化的硬件地址
//u_short protocol_type;					// 协议地址格式
//u_char hardware_length;					// 硬件地址长度
//u_char protocol_length;					// 协议地址长度
//u_short operation_code;					// 操作码
//u_char source_ethernet_address[6];		// 发送者硬件地址
//u_char source_ip_address[4];				// 发送者协议地址
//u_char destination_ethernet_address[6];	// 目的方硬件地址
//u_char destination_ip_address[4];			// 目的方协议地址
void arp_protocol_packet_handle(u_char *arg, const struct pcap_pkthdr *pkt_header, const u_char *pkt_content)
{
	arp_header *arp_protocol;

	arp_protocol = (arp_header*)(pkt_content + 14);

	printf("==================ARP Protocol==================\n");
	printf("Hardware Type: ");
	switch (ntohs(arp_protocol->hardware_type))
	{
	case 1:
		printf("Ethernet");
		break;
	default:
		break;
	}
	printf(" (%d)\n", ntohs(arp_protocol->hardware_type));
	printf("Protocol Type: \n");
	switch (ntohs(arp_protocol->protocol_type))
	{
	case 0x0800:
		printf("%s", "IP");
		break;
	case 0x0806:
		printf("%s", "ARP");
		break;
	case 0x0835:
		printf("%s", "RARP");
		break;
	default:
		printf("%s", "Unknown Protocol");
		break;
	}
	printf(" (0x%04x)\n", ntohs(arp_protocol->protocol_type));
	printf("Hardware Length: %d\n", arp_protocol->hardware_length);
	printf("Protocol Length: %d\n", arp_protocol->protocol_length);
	printf("Operation Code: ");
	switch (ntohs(arp_protocol->operation_code))
	{
	case 1:
		printf("request");
		break;
	case 2:
		printf("reply");
		break;
	default:
		break;
	}
	printf(" (%i)\n", ntohs(arp_protocol->operation_code));
}

// IP协议处理
//u_char version_hlen;		// 首部长度 版本
//u_char tos;				// 服务质量
//u_short tlen;				// 总长度
//u_short identification;	// 身份识别
//u_short flags_offset;		// 标识 分组偏移
//u_char ttl;				// 生命周期
//u_char proto;				// 协议类型
//u_short checksum;			// 包头测验码
//u_int saddr;				// 源IP地址
//u_int daddr;				// 目的IP地址
void ip_protocol_packet_handle(u_char *arg, const struct pcap_pkthdr *pkt_header, const u_char *pkt_content)
{
	ip_header *ip_protocol;
	sockaddr_in source, dest;
	char sourceIP[MAX_ADDR_LEN], destIP[MAX_ADDR_LEN];

	ip_protocol = (ip_header*)(pkt_content + 14);
	source.sin_addr.s_addr = ip_protocol->saddr;
	dest.sin_addr.s_addr = ip_protocol->daddr;
	strncpy(sourceIP, inet_ntoa(source.sin_addr), MAX_ADDR_LEN);
	strncpy(destIP, inet_ntoa(dest.sin_addr), MAX_ADDR_LEN);

	printf("===================IP Protocol==================\n");
	printf("Version: %d\n", ip_protocol->version_hlen >> 4);
	printf("Header Length: %d bytes\n", (ip_protocol->version_hlen & 0x0f) * 4);
	printf("Tos: %d\n", ip_protocol->tos);
	printf("Total Length: %d\n", ntohs(ip_protocol->tlen));
	printf("Identification: 0x%.4x (%i)\n", ntohs(ip_protocol->identification), ntohs(ip_protocol->identification));
	printf("Flags: %d\n", ntohs(ip_protocol->flags_offset) >> 13);
	printf("---Reserved bit: %d\n", (ntohs(ip_protocol->flags_offset) & 0x8000) >> 15);
	printf("---Don't fragment: %d\n", (ntohs(ip_protocol->flags_offset) & 0x4000) >> 14);
	printf("---More fragment: %d\n", (ntohs(ip_protocol->flags_offset) & 0x2000) >> 13);
	printf("Fragment offset: %d\n", ntohs(ip_protocol->flags_offset) & 0x1fff);
	printf("Time to live: %d\n", ip_protocol->ttl);
	printf("Protocol Type: ");
	switch (ip_protocol->proto)
	{
	case 1:
		printf("ICMP");
		break;
	case 6:
		printf("TCP");
		break;
	case 17:
		printf("UDP");
		break;
	default:
		break;
	}
	printf(" (%d)\n", ip_protocol->proto);
	printf("Header checkSum: 0x%.4x\n", ntohs(ip_protocol->checksum));
	printf("Source: %s\n", sourceIP);
	printf("Destination: %s\n", destIP);

	if (ip_protocol->proto == htons(0x0600))
		tcp_protocol_packet_handle(arg, pkt_header, pkt_content);
	else if (ip_protocol->proto == htons(0x1100))
		udp_protocol_packet_handle(arg, pkt_header, pkt_content);
	else if (ip_protocol->proto == htons(0x0100))
		icmp_protocol_packet_handle(arg, pkt_header, pkt_content);
}

// Ethernet协议处理
void ethernet_protocol_packet_handle(u_char *arg, const struct pcap_pkthdr *pkt_header, const u_char *pkt_content)
{
	ether_header *ethernet_protocol;//以太网协议
	u_short ethernet_type;			//以太网类型
	u_char *mac_string;				//以太网地址

									//获取以太网数据内容
	ethernet_protocol = (ether_header*)pkt_content;
	ethernet_type = ntohs(ethernet_protocol->ether_type);

	printf("==============Ethernet Protocol=================\n");

	//以太网目标地址
	mac_string = ethernet_protocol->ether_dhost;

	printf("Destination Mac Address: %02x:%02x:%02x:%02x:%02x:%02x\n",
		*mac_string,
		*(mac_string + 1),
		*(mac_string + 2),
		*(mac_string + 3),
		*(mac_string + 4),
		*(mac_string + 5));

	//以太网源地址
	mac_string = ethernet_protocol->ether_shost;

	printf("Source Mac Address: %02x:%02x:%02x:%02x:%02x:%02x\n",
		*mac_string,
		*(mac_string + 1),
		*(mac_string + 2),
		*(mac_string + 3),
		*(mac_string + 4),
		*(mac_string + 5));

	printf("Ethernet type: ");
	switch (ethernet_type)
	{
	case 0x0800:
		printf("%s", "IP");
		break;
	case 0x0806:
		printf("%s", "ARP");
		break;
	case 0x0835:
		printf("%s", "RARP");
		break;
	default:
		printf("%s", "Unknown Protocol");
		break;
	}
	printf(" (0x%04x)\n", ethernet_type);

	switch (ethernet_type)
	{
	case 0x0800:
		ip_protocol_packet_handle(arg, pkt_header, pkt_content);
		break;
	case 0x0806:
		arp_protocol_packet_handle(arg, pkt_header, pkt_content);
		break;
	case 0x0835:
		printf("==============RARP Protocol=================\n");
		printf("RARP\n");
		break;
	default:
		printf("==============Unknown Protocol==============\n");
		printf("Unknown Protocol\n");
		break;
	}
}

int main()
{
	pcap_if_t *alldevs;	//适配器列表，它是一个链表的数据结构
	pcap_if_t *d;		//保存某个适配器
	pcap_t *fp;
	int res;
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	time_t local_tv_sec;
	struct tm *ltime;
	char timestr[16];

	int count = 1;
	int i = 0, inum;
	char errbuf[PCAP_ERRBUF_SIZE];

	printf("===============Adapter List===============\n");

	//获取本地设备列表
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	//输出列表
	for (d = alldevs; d != NULL; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	//获取选择编号
	while (1)
	{
		printf("\nEnter the interface number (1-%d): ", i);
		scanf("%d", &inum);

		if (inum > 0 && inum <= i)
			break;
	}

	//跳到用户选择的适配器
	for (d = alldevs, i = 0; i < inum - 1; ++i, d = d->next);

	//打开适配器
	if ((fp = pcap_open_live(d->name, 65536, 1, 1000, errbuf)) == NULL)
	{
		fprintf(stderr, "\nError openning adapter: %s\n", errbuf);
		pcap_freealldevs(alldevs);
		return -1;
	}

	//检查链路层的类型
	if (pcap_datalink(fp) != DLT_EN10MB)
	{
		fprintf(stderr, "This program only run on Ethernet networks\n");
		pcap_close(fp);
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("The program is working......\n");
	printf("The capture file is saving as 'data.txt'\n");
	printf("You can input 'ctrl + C' to stop the program\n");

	if ((file = freopen("data.txt", "w", stdout)) == 0)
		printf("Cannot open the file.\n");

	while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0)
	{
		//超时
		if (res == 0)
			continue;

		//将时间戳转化为可识别格式
		local_tv_sec = header->ts.tv_sec;
		ltime = localtime(&local_tv_sec);
		strftime(timestr, sizeof(timestr), "%H:%M:%S", ltime);

		//输出编号、时间戳和包长度
		printf("==============================================================================\n");
		printf("No.%d\ttime: %s\tlen: %ld\n", count++, timestr, header->len);
		printf("==============================================================================\n");

		char temp[LINE_LEN + 1];
		//输出包
		for (i = 0; i < header->caplen; ++i)
		{
			printf("%.2x ", pkt_data[i]);
			if (isgraph(pkt_data[i]) || pkt_data[i] == ' ')
				temp[i % LINE_LEN] = pkt_data[i];
			else
				temp[i % LINE_LEN] = '.';

			if (i % LINE_LEN == 15)
			{
				temp[16] = '\0';
				printf("        ");
				printf("%s", temp);
				printf("\n");
				memset(temp, 0, LINE_LEN);
			}
		}
		printf("\n");

		//分析数据包
		ethernet_protocol_packet_handle(NULL, header, pkt_data);
	}

	if (res == -1)
	{
		printf("Error reading the packets: %s\n", pcap_geterr(fp));
		pcap_close(fp);
		pcap_freealldevs(alldevs);
		fclose(stdin);
		if (file)
			fclose(file);
		return -1;
	}

	//释放
	pcap_close(fp);
	pcap_freealldevs(alldevs);
	fclose(stdin);
	if (file)
		fclose(file);

	return 0;
}