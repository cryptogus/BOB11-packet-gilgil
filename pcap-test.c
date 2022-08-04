#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <libnet.h>


void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};


bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet); //packet의 정보가 받아와짐
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		
		struct libnet_ethernet_hdr *p = (struct libnet_ethernet_hdr*)packet; //패킷 정보 받아오기위한 변수 선언
		struct libnet_ipv4_hdr * p2 = (struct libnet_ipv4_hdr*)(packet+ 14); //패킷의 시작주소로 부터 14바이트 떨어진 곳 즉 ethernet 의 정보 14바이트 제거
		struct libnet_tcp_hdr *p3 = (struct libnet_tcp_hdr*)(packet + 14 + (p2->ip_hl)*4); //ethernet 의 정보 14바이트 + ip length 제거, ip_len이 2바이트 변수이기에 1바이트로 캐스팅
		
		printf("source ethernet address : %02x:%02x:%02x:%02x:%02x:%02x\n",p->ether_shost[0],p->ether_shost[1],p->ether_shost[2],p->ether_shost[3],p->ether_shost[4],p->ether_shost[5]);
		printf("destination ethernet address : %02x:%02x:%02x:%02x:%02x:%02x\n",p->ether_dhost[0],p->ether_dhost[1],p->ether_dhost[2],p->ether_dhost[3],p->ether_dhost[4],p->ether_dhost[5]);
		if(ntohs(p->ether_type) == 0x0800){//0x0800 이면 ip, 0x0806 -> ARP, 0x8100 -> vlan
			printf("ip source address : %u.%u.%u.%u\n", p2->ip_src.s_addr &0xff, (p2->ip_src.s_addr >> 8 ) &0xff, (p2->ip_src.s_addr >> 16 ) &0xff, (p2->ip_src.s_addr>>24) &0xff); //s_addr 4바이트 변수 & little endian
			printf("ip destination adress : %u.%u.%u.%u\n", p2->ip_dst.s_addr & 0xff, (p2->ip_dst.s_addr >> 8) & 0xff, (p2->ip_dst.s_addr >> 16)&0xff, (p2->ip_dst.s_addr >> 24)&0xff);		
		}		
		else{
			printf("None ip\n");
		}

		if(p2->ip_p == 0x06){//TCP 인지 UDP 인지 ip_p는 1바이트 자료형
			printf("source port : %d\n",ntohs(p3->th_sport));// th_sport 2바이트 변수
			printf("destination port : %d\n", ntohs(p3->th_dport));//network to host -> little endian
		}else{
			printf("None TCP\n");
		}

		u_int8_t *payload = (u_int8_t*)(packet + 14 + (p2->ip_hl)*4 + (p3->th_off)*4); /*Data Offset(데이터 옵셋) : TCP 세그먼트가 시작되는 위치를 기준으로 데이터의 시작 위치를 나타내므로 TCP 헤더의 크기가 된다. 32비트 워드 단위로 표시된다 이 오프셋을 표기할 때는 32비트 워드 단위를 사용하며, 32 비트 체계에서의 1 Word = 4 bytes를 의미한다. 즉, 이 필드의 값에 4를 곱하면 세그먼트에서 헤더를 제외한 실제 데이터의 시작 위치를 알 수 있는 것이다.이 필드에 할당된 4 bits로 표현할 수 있는 값의 범위는 즉 0 ~ 15 Word이므로 기본적으로 0 ~ 60 bytes의 오프셋까지 표현할 수 있다. 하지만 옵션 필드를 제외한 나머지 필드는 필수로 존재해야 하기 때문에 최소 값은 20 bytes, 즉 5 Word로 고정되어 있다*/
		u_int32_t len = 0;																
		len = header->caplen - 14 - (p2->ip_hl)*4 - (p3->th_off)*4; //payload lenght
		//printf("\nTCP 헤더길이: %d\n",(p3->th_off)*4);
		printf("Payload(Data) :");
		if(len >10)
		{
			len = 10;
			for (int i=0; i < len; i++)
				printf("%#02x ",payload[i]);
		
		}else if(len == 0){
			printf("No Data\n");
		}else{
			for(int i = 0; i < len; i++)
				printf("%#02x ",payload[i]);
		}
		
		printf("\n%u bytes captured\n\n", header->caplen);
	}
	
	pcap_close(pcap);
}
// struct libnet_ethernet_hdr
// {
//     u_int8_t  ether_dhost[6];/* destination ethernet address */
//     u_int8_t  ether_shost[6];/* source ethernet address */
//     u_int16_t ether_type;                 /* protocol */
// };

// struct libnet_ipv4_hdr
// {
// #if (LIBNET_LIL_ENDIAN)
//     u_int8_t ip_hl:4,      /* header length */
//            ip_v:4;         /* version */
// #endif
// #if (LIBNET_BIG_ENDIAN)
//     u_int8_t ip_v:4,       /* version */
//            ip_hl:4;        /* header length */
// #endif
//     u_int8_t ip_tos;       /* type of service */
// #ifndef IPTOS_LOWDELAY
// #define IPTOS_LOWDELAY      0x10
// #endif
// #ifndef IPTOS_THROUGHPUT
// #define IPTOS_THROUGHPUT    0x08
// #endif
// #ifndef IPTOS_RELIABILITY
// #define IPTOS_RELIABILITY   0x04
// #endif
// #ifndef IPTOS_LOWCOST
// #define IPTOS_LOWCOST       0x02
// #endif
//     u_int16_t ip_len;         /* total length */
//     u_int16_t ip_id;          /* identification */
//     u_int16_t ip_off;
// #ifndef IP_RF
// #define IP_RF 0x8000        /* reserved fragment flag */
// #endif
// #ifndef IP_DF
// #define IP_DF 0x4000        /* dont fragment flag */
// #endif
// #ifndef IP_MF
// #define IP_MF 0x2000        /* more fragments flag */
// #endif 
// #ifndef IP_OFFMASK
// #define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
// #endif
//     u_int8_t ip_ttl;          /* time to live */
//     u_int8_t ip_p;            /* protocol */
//     u_int16_t ip_sum;         /* checksum */
//     struct in_addr ip_src, ip_dst; /* source and dest address */
// };
// struct libnet_tcp_hdr
// {
//     u_int16_t th_sport;       /* source port */
//     u_int16_t th_dport;       /* destination port */
//     u_int32_t th_seq;          /* sequence number */
//     u_int32_t th_ack;          /* acknowledgement number */
// #if (LIBNET_LIL_ENDIAN)
//     u_int8_t th_x2:4,         /* (unused) */
//            th_off:4;        /* data offset */
// #endif
// #if (LIBNET_BIG_ENDIAN)
//     u_int8_t th_off:4,        /* data offset */
//            th_x2:4;         /* (unused) */
// #endif
//     u_int8_t  th_flags;       /* control flags */
// #ifndef TH_FIN
// #define TH_FIN    0x01      /* finished send data */
// #endif
// #ifndef TH_SYN
// #define TH_SYN    0x02      /* synchronize sequence numbers */
// #endif
// #ifndef TH_RST
// #define TH_RST    0x04      /* reset the connection */
// #endif
// #ifndef TH_PUSH
// #define TH_PUSH   0x08      /* push data to the app layer */
// #endif
// #ifndef TH_ACK
// #define TH_ACK    0x10      /* acknowledge */
// #endif
// #ifndef TH_URG
// #define TH_URG    0x20      /* urgent! */
// #endif
// #ifndef TH_ECE
// #define TH_ECE    0x40
// #endif
// #ifndef TH_CWR   
// #define TH_CWR    0x80
// #endif
//     u_int16_t th_win;         /* window */
//     u_int16_t th_sum;         /* checksum */
//     u_int16_t th_urp;         /* urgent pointer */
// };
