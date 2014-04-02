/*
 * NamNX 
 * Internship - PLANETE - INRIA
 * 07.2012
 * @Purpose: This is the Wrapper prototype source that demostrates the ability of how to combine
 * a CCNx agent and an OF Switch, use in INFOCOM poster
 *
 * @Description:
 * CCNx serves as PIT and CS
 * The OF switch serves as FIB
 * CCNx and Wrapper running on an external machine, connect to port 1 of an OF switch
 *
 *
 * @Description:
 *
 * OF Switch must be configured:
 * inport = 2,3,... -> outport =1 (forward all to the machine of CCNx and Wrapper)
 *
 * inport = 1, DstIp = hash(/name)-> output=next hop toward the server.
 *
 *
 *
 *@Behavior
 * Wrapper: Listen Interest from CCNx, hashed the name to field and send to OpenFlow switch
 * 
 *
 *
 * @Use LibPcap CCNx lib and some code snippets from GG
 * 
 */

#include <ctype.h>
#include <unistd.h>
#include <getopt.h>
#include<stdio.h>
#include<pcap.h>
#include<assert.h>
#include<stdlib.h> // for exit()
#include<string.h> //for memset
#include<sys/socket.h>
#include<arpa/inet.h> // for inet_ntoa()
#include<net/ethernet.h>
#include<netinet/ip_icmp.h>	//Provides declarations for icmp header
#include<netinet/udp.h>	//Provides declarations for udp header
#include<netinet/tcp.h>	//Provides declarations for tcp header
#include<netinet/ip.h>	//Provides declarations for ip header

#include <netinet/in.h>
#include <sys/types.h>

#include <linux/if_packet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <signal.h>
#include <fcntl.h>
//CCNx lib
#include <ccn/header.h>
#include <ccn/ccn.h>
#include <ccn/uri.h>
//multi thread
#include <pthread.h>

static const char* LO_INTERFACE = "lo";

void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
char* print_ip(int);

char* getLocalIpAddr(char*);

int process_content_object(char*, int, int);
int fwCCN(int, const char*, int);
/*
int hash(const char*); //Hash function
*/
unsigned long hash(unsigned char*); //Hash function
unsigned short csum(unsigned short *buf, int nwords); //check sum

#define LISTEN_PORT_OF_INTEREST 1234//Wrapper listen port OF
#define LISTEN_PORT_CCN 8888//Wrapper listen port CCN
#define SRC_PORT_OUT 9001//port out
//#define CCN_AGENT_PORT 9003
#define CCN_TYPE_INTEREST 1
#define CCN_TYPE_DATA 2

//For Raw socket
#define MY_DEST_MAC0 0x00
#define MY_DEST_MAC1 0x00
#define MY_DEST_MAC2 0x00
#define MY_DEST_MAC3 0x00
#define MY_DEST_MAC4 0x00
#define MY_DEST_MAC5 0x02

#define DEFAULT_IF "eth0"
//#define SRC_IP "193.48.223.162"
#define SNAP_LEN 1500
/*
#define BUF_SIZ 1500
*/
#define BUF_SIZ 8192
//Max, min function
#define max( a, b ) ( ((a) > (b)) ? (a) : (b) )
#define min( a, b ) ( ((a) < (b)) ? (a) : (b) )

struct sockaddr_in source, dest;
int i, j;
int sockfd; //raw socket to send

char* listen_interface = DEFAULT_IF;
int ccn_agent_port = 9695;
int wrapper_ccn_port = 8888;
int of_port=3; //Total OpenFlow port
int dst_port_out = 1234;

char src_ip[20]="10.0.0.1";


char *str_name;
int res;

char* token;
struct ccn_charbuf* name;


//FILE *ptr_file;//for writing file
/*
 * Error informer
 */

void printError(char *s) {
    perror(s);
    exit(EXIT_FAILURE);
}


//count value to measure loss
static int count1 = 0, count2 = 0, count3=0;count4=0;
void summary() {
    printf("Number of packets in sk 1234: %d\n", count1);
    printf("Forward to CCN: %d\n", count4);
    printf("Number of packets in sk 8888: %d\n", count2);
    printf("Number of packets in send out from Wrapper: %d\n", count3);

    printf("Stopping Wrapper...\n");
//    fclose(ptr_file);


    exit(EXIT_SUCCESS);
}

/*Check it is interest or contentObject packet
 * Return
 * 1: Interest
 * 2: Content Object
 * 0: Not CCN
 */
int check_ccn_type(char *payload, int payload_size) {
    struct ccn_skeleton_decoder decoder = {0};
    struct ccn_skeleton_decoder *d = &decoder;
    ssize_t dres;
    enum ccn_dtag dtag;

    d->state |= CCN_DSTATE_PAUSE;
    dres = ccn_skeleton_decode(d, payload, payload_size);
    if (dres == -1) {
    	printError("Error skeleton decode");
    	return -1;
    }
    if (d->state < 0)
        abort(); /* cannot happen because of checks in caller */
    dtag = d->numval;
    switch (dtag) {
        case CCN_DTAG_Interest:
            //printf("got CCN Interest Msg \n");
            return CCN_TYPE_INTEREST;
        case CCN_DTAG_ContentObject:
            //printf("got CCN Data Msg \n");
            return CCN_TYPE_DATA;

        default:
            printf("Not CCN msg \n");
            return 0;
    }

}





int s1, s2, s3, s0; //socket from Wrapper to CCN

/* 17.07.2012
 * Init socket from Wrapper to CCNx
 * input source port and dest port
 *  
 */

int init_wrapper_ccn_socket(int sport, int dport) {
    int sd;
    struct sockaddr_in s_addr1, ccn_addr;
    //init value
    bzero(&ccn_addr, sizeof (ccn_addr));
    bzero(&s_addr1, sizeof (s_addr1));

    //CCNx runs at port CCN_AGENT_PORT
    ccn_addr.sin_family = AF_INET;
    ccn_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    ccn_addr.sin_port = htons(dport);

    if ((sd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        printError("socket init error");
    }
    s_addr1.sin_family = AF_INET;
    /*
        s_addr1.sin_addr.s_addr=inet_addr("194.254.174.183");
     */
    s_addr1.sin_addr.s_addr = inet_addr("127.0.0.1");
    s_addr1.sin_port = htons(sport);

    if (bind(sd, (struct sockaddr *) &s_addr1, sizeof (s_addr1)) < 0) {
        printError("bind error");
    }

//	unsigned char set = 1;
//	if (setsockopt(sd, IPPROTO_IP, IP_RECVTOS, &set, sizeof(set)) < 0) {
//		printError("cannot set recvtos\n");
//	}

    if (connect(sd, (struct sockaddr *) &ccn_addr, sizeof (ccn_addr)) < 0) {
        printError("connect error");
    }
    printf("Bind 127.0.0.1:%d to 127.0.0.1:%d, socket descriptor=%d \n", sport, dport, sd);

    /*
        exit(0);
     */

    return sd;
}


/* Open a Raw socket and construct to send 
 *  
 */
struct ifreq if_idx;
struct ifreq if_mac;
struct sockaddr_ll socket_address;
struct ether_header eh;

struct iphdr iph;
struct udphdr udph;


int init_raw_socket() {

    /* Open RAW socket to send on */
    if ((sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1) {
        printError("raw socket init error");
    }
    /* Ethernet header */

    char ifName[IFNAMSIZ];


    /* Get interface name */

    strcpy(ifName, listen_interface);
    memset(&if_idx, 0, sizeof (struct ifreq));
    strncpy(if_idx.ifr_name, ifName, IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
        perror("SIOCGIFINDEX");
    /* Get the MAC address of the interface to send on */
    memset(&if_mac, 0, sizeof (struct ifreq));
    strncpy(if_mac.ifr_name, ifName, IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0)
        perror("SIOCGIFHWADDR");
    /* Ethernet header */

    eh.ether_shost[0] = ((uint8_t *) & if_mac.ifr_hwaddr.sa_data)[0];
    eh.ether_shost[1] = ((uint8_t *) & if_mac.ifr_hwaddr.sa_data)[1];
    eh.ether_shost[2] = ((uint8_t *) & if_mac.ifr_hwaddr.sa_data)[2];
    eh.ether_shost[3] = ((uint8_t *) & if_mac.ifr_hwaddr.sa_data)[3];
    eh.ether_shost[4] = ((uint8_t *) & if_mac.ifr_hwaddr.sa_data)[4];
    eh.ether_shost[5] = ((uint8_t *) & if_mac.ifr_hwaddr.sa_data)[5];

    eh.ether_dhost[0] = MY_DEST_MAC0;
    eh.ether_dhost[1] = MY_DEST_MAC1;
    eh.ether_dhost[2] = MY_DEST_MAC2;
    eh.ether_dhost[3] = MY_DEST_MAC3;
    eh.ether_dhost[4] = MY_DEST_MAC4;
    eh.ether_dhost[5] = MY_DEST_MAC5;
    eh.ether_type = htons(ETH_P_IP);


    /* Index of the network device */
    socket_address.sll_ifindex = if_idx.ifr_ifindex;
    /* Address length*/
    socket_address.sll_halen = ETH_ALEN;
    /* Destination MAC */
    socket_address.sll_addr[0] = MY_DEST_MAC0;
    socket_address.sll_addr[1] = MY_DEST_MAC1;
    socket_address.sll_addr[2] = MY_DEST_MAC2;
    socket_address.sll_addr[3] = MY_DEST_MAC3;
    socket_address.sll_addr[4] = MY_DEST_MAC4;
    socket_address.sll_addr[5] = MY_DEST_MAC5;

    /* IP Header */
    iph.ihl = 5;
    iph.version = 4;
//    iph.tos = 16; // Low delay
    iph.tos = 0;
    iph.id = htons(54321);
    iph.ttl = 16; // hops
    iph.protocol = 17; // UDP
//    iph.daddr = inet_addr(dst_ip_out);
//    iph.daddr = inet_addr(dst_ip_out);
//    iph.saddr = inet_addr(src_ip);
    iph.saddr=inet_addr(getLocalIpAddr(listen_interface));


    //Construct the UDP header:
    /* UDP Header */
    udph.source = htons(SRC_PORT_OUT);
    udph.dest = htons(dst_port_out);
    udph.check = 0; // skip
    return EXIT_SUCCESS;

}
/*
 * Thread function
 */
void *threadFunc(void *arg)
{

	printf("Thread start, handle %s \n", (char*) arg);
	pcap_loop((pcap_t *) arg, -1, process_packet, NULL);

	return NULL;
}



/**
 * Using pcap and raw socket
 */
pcap_t *handle, *handleLo; //Handle of the device that shall be sniffed
int main(int argc, char* argv[]) {
	//Load arguments
	  int opt;
	  while((opt = getopt(argc, argv, "i:p:o:h:")) != -1) {
	    switch (opt){
	      case 'i':
	    	listen_interface = optarg;
	        break;
	      case 'p':
	    	ccn_agent_port=atoi(optarg);
	        break;
//	      case 'o':
//	    	of_port=atoi(optarg);
//	        break;
//	      case 'w':
//	    	wrapper_ccn_port=atoi(optarg);
//	        break;


	      case 'h':
		    	printf ("Wrapper Usage: ./Wrapper -p [portCCNx] -i [interface]");
		        return EXIT_SUCCESS;
	    }
	  }



    char errbuf[100];
//    int count = 1, n;

    signal(SIGINT, summary); //exit function
	printf("Wrapper to combine a CCNx agent and an OpenFlow Switch\n");


    strcpy(src_ip, getLocalIpAddr(listen_interface));
    printf("ip: %s\n",src_ip);



    printf("Listening interface: %s\n", listen_interface);
    printf("ccn_agent_port: %d\n", ccn_agent_port);
//    printf("dst_ip_out: %s\n", dst_ip_out);
//    printf("dst_port_out: %d\n", dst_port_out);
    printf("Init raw socket from Wrapper to OF\n");
    init_raw_socket();
    printf("Init sockets of Wrapper to CCNx\n");
    s1 = init_wrapper_ccn_socket(10001, ccn_agent_port);
    s2 = init_wrapper_ccn_socket(10002, ccn_agent_port);
    s3 = init_wrapper_ccn_socket(10003, ccn_agent_port);
    s0= init_wrapper_ccn_socket(8888, ccn_agent_port);





    //Open the device for sniffing
    printf("Opening device %s for sniffing ... ", listen_interface);
    handle = pcap_open_live(listen_interface, SNAP_LEN, 1, 0, errbuf);



    if (handle == NULL) {
    	printf("Couldn't open device %s : %s\n", listen_interface, errbuf);
        exit(EXIT_FAILURE);
    }



	 struct bpf_program fp;		/* The compiled filter expression */
//	 char filter_exp[] = "udp && dst host 10.0.0.1 && dst port 1234";	/* The filter expression */
	 char filter_exp[] = "(udp or icmp) && dst port 1234";	/* The filter expression */
//	 char filter_exp_lo[] = "udp and dst host 127.0.0.1 and (dst port 8888 or dst port 10001 or dst port 10002 or dst port 10003)";
	 char filter_exp_lo[] = "(udp or icmp) and (dst port 8888 or dst port 10001 or dst port 10002 or dst port 10003)";
	 bpf_u_int32 mask;		/* The netmask of our sniffing device */
	 bpf_u_int32 net;		/* The IP of our sniffing device */
	 printf("Set filter %s for eth0 + %s for lo \n", filter_exp, filter_exp_lo);
	if (pcap_lookupnet(listen_interface, &net, &mask, errbuf) == -1) {
		printf("Can't get netmask for device %s\n", listen_interface);
		net = 0;
		mask = 0;
	}

	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		printf( "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		printf("Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}



    handleLo = pcap_open_live(LO_INTERFACE, SNAP_LEN, 1, 0, errbuf);
    if (handleLo == NULL) {
        printf("Couldn't open device %s : %s\n", listen_interface, errbuf);
        exit(EXIT_FAILURE);
    }

	if (pcap_lookupnet(LO_INTERFACE, &net, &mask, errbuf) == -1) {
		printf("Can't get netmask for device %s\n", LO_INTERFACE);
		net = 0;
		mask = 0;
	}

	if (pcap_compile(handleLo, &fp, filter_exp_lo, 0, net) == -1) {
		printf("Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return (2);
	}
	if (pcap_setfilter(handleLo, &fp) == -1) {
		printf("Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return (2);
	}





    printf("Done\n");
    //NamNX 13.07.2012
    //bind tunnel from Wrapper to CCN
    printf("Init raw socket send packet out...\n");
    init_raw_socket();



	pthread_t pth, pthLo;	// thread identifier

	/* Create worker thread */
	printf("Init thread 1 to listen %s \n", listen_interface);
	pthread_create(&pth,NULL,threadFunc,handle);
	printf("Init thread 2 to listen %s \n", LO_INTERFACE);
	pthread_create(&pthLo,NULL,threadFunc,handleLo);

	//infinite loop
	while (1) {
	}
    //Put the device in sniff loop
//    pcap_loop(handle, -1, process_packet, NULL);

    return 0;
}



void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer) {
    int size = header->len;
    //Get the IP Header part of this packet , excluding the ethernet header
    struct iphdr *iph = (struct iphdr*) (buffer + sizeof (struct ethhdr));
    switch (iph->protocol)
    {

        case 6: //TCP Protocol
        	printf("TCP \n");
            break;

        case 17: //UDP Protocol
        {

            unsigned short iphdrlen;
//            struct iphdr *iph = (struct iphdr *) (buffer + sizeof (struct ethhdr));
            iphdrlen = iph->ihl * 4;
            struct udphdr *udph = (struct udphdr*) (buffer + iphdrlen + sizeof (struct ethhdr));
            /*
                        int header_size = sizeof (struct ethhdr) +iphdrlen + sizeof udph;
             */
            int header_size = sizeof (struct ethhdr) + iphdrlen + sizeof (struct udphdr);
            const u_char* payload = buffer + header_size;
            int payload_size = size - header_size;
            //get the dest port
            int dstport = ntohs(udph->dest);
            int tos = iph->tos;
            int res = 0; //response value

            switch (dstport) {

                case LISTEN_PORT_OF_INTEREST:

                    //get ToS field to decide where to send 
                    //if (tos != 0)
                    if (check_ccn_type(payload, payload_size) == CCN_TYPE_INTEREST) {//Interest
//                    	printf("Receive Interest on Wrapper port: %d\n",LISTEN_PORT_OF_INTEREST);
                    	count1++;

                        res = fwCCN(tos, payload, payload_size);
                        if (res == -1) {
                            printError("forward error");
                        }
                     } else if (check_ccn_type(payload, payload_size) == CCN_TYPE_DATA) {
//                    	 printf("Receive Data on Wrapper port: %d\n",LISTEN_PORT_OF_INTEREST);
                    	 name = ccn_charbuf_create();
                         res = ccn_uri_append(name, payload, payload_size, 0);
                         if (res == -1) {
                             printError("can not get data name");
                         }
                         str_name = ccn_charbuf_as_string(name);
//                         printf("data name : %s\n", str_name);

                    	    res = fwCCN(100, payload, payload_size);
                    	    if (res == -1) {
                    	    	printError("forward error");
                    	    }
                     }



                    break;
                case LISTEN_PORT_CCN:
                    //interest
                    /*
                        forward_to_of_switch(payload, payload_size);
                     */


                    if (check_ccn_type(payload, payload_size) == CCN_TYPE_INTEREST) {
                    	printf("Receive Interest on Wrapper port: %d\n",LISTEN_PORT_CCN);
                    	count2++;
                        process_interest(payload, payload_size);
                    }


                    break;
                    //if packet comes from these port, it is data packet, send to OF switch with correspond ToS    
                case 10001:
                    if (check_ccn_type(payload, payload_size) == CCN_TYPE_DATA) {//return content with ToS is set
//                    	printf("Receive Data on port 10001\n");
                        process_content_object(payload, payload_size, 4);
                    }

                    break;
                case 10002:
                    if (check_ccn_type(payload, payload_size) == CCN_TYPE_DATA) {//content
                        process_content_object(payload, payload_size, 8);
                    }
                    break;
                case 10003:
                    if (check_ccn_type(payload, payload_size) == CCN_TYPE_DATA) {//content
                        process_content_object(payload, payload_size, 12);
                    }
                    break;

                default:
                    break;

            }

        }
            break;
        default: //Some Other Protocol like ARP etc.
            break;
    }

}

/*FW packet to right face of CCNx
 * 1-> 127.0.0.1:10001
 * 2-> 127.0.0.1:20002
 * update 15.03: OpenFlow can not set ToS bit for 2 lower bits, so the value must be 4,8,12 ...
 *
 */

int fwCCN(int tos, const char* payload, int len) {
//    printf("Forward to port %d of CCNx deamon, payload %d bytes \n", tos, len);

    int i;
    count4++;
    switch (tos) {
        case 4:
            i = write(s1, payload, len);
            break;
        case 8:
            i = write(s2, payload, len);
            break;
        case 12:
            i = write(s3, payload, len);
            break;

        case 100://face wrapper to CCNx
//        	printf("Forward to port socket 0\n");

            i = write(s0, payload, len);
            break;

        default:
//            printf("ToS unknown, write to 1\n");
            i = write(s1, payload, len);
            break;
    }


    return i;



}

/* 17.07.2012
 * Process interest packet
 */

int process_interest(char* payload, int payload_size) {


	name = ccn_charbuf_create();
    res = ccn_uri_append(name, payload, payload_size, 0);


    if (res == -1) {
        printError("can not get interest name\n");
    }
    str_name = ccn_charbuf_as_string(name);

    printf("Interest name: %s\n", str_name);

    if (str_name != NULL) {


		strsep(&str_name, "/");//first element is before /, null
		token = strsep(&str_name, "/");//second element, the component 0;


    }
    //***********Uncomment to hash full name**********
//    return send_to_of_switch(payload, payload_size, hash(str_name), 0, 1);
    return send_to_of_switch(payload, payload_size, hash(token), 0, 1);

}

/* 18.07.2012
 * Process content object packet
 */

int process_content_object(char* payload, int payload_size, int tos) {


	name = ccn_charbuf_create();
    res = ccn_uri_append(name, payload, payload_size, 0);


    if (res == -1) {
        printError("can not get data name");
    }
    str_name = ccn_charbuf_as_string(name);
    printf("Data Name : %s\n", str_name);

    //TODO: Hash
	strsep(&str_name, "/");//first element is before /, null
	token = strsep(&str_name, "/");//second element, the component 0;

	//***********Uncomment to hash full name**********
//	send_to_of_switch(payload, payload_size, hash(str_name), tos, 2);
    send_to_of_switch(payload, payload_size, hash(token), tos, 2);

    return (EXIT_SUCCESS);

}

/* Send packet out to OF switch
 * Need to open a raw socket
 * 1 : send interest
 * 2 : send data
 */
/** */
int tx_len = 0;
char sendbuf[BUF_SIZ];
int send_to_of_switch(const char* payload, const int payload_size, int hash_name, int tos, int type) {
    /*
        int tx_len = tx_len_base + payload_size;
     */
	tx_len = 0;

    struct ether_header *eh1 = (struct ether_header *) sendbuf;
    memset(sendbuf, 0, BUF_SIZ);
    *eh1 = eh;
    /* Ethernet header */
    tx_len += sizeof (struct ether_header);
    /* IP Header */
    struct iphdr *iph1 = (struct iphdr *) (sendbuf + sizeof (struct ether_header));
    *iph1 = iph;
    if (type == CCN_TYPE_INTEREST) {
    	if (tos != 0)
    		iph1->tos = tos;
//    	printf("ToS:%d\n",tos);
    } else if (type == CCN_TYPE_DATA) {
    	if (tos != 0)
    	    	iph1->tos = tos;
//    			printf("ToS:%d\n",0);
    }



    tx_len += sizeof (struct iphdr);

    //Construct the UDP header:
    struct udphdr *udph1 = (struct udphdr *) (sendbuf + sizeof (struct iphdr) + sizeof (struct ether_header));
    /* UDP Header */
	udph1->source = ccn_agent_port;


    /*
        udph1->source = htons(3423);
        udph1->dest = htons(PORT_OUT);
        udph1->check = 0; // skip
     */
    *udph1 = udph;
    tx_len += sizeof (struct udphdr);
    //Fill in UDP payload:
    /* Packet data, copy from to payload of CCN packet */
    int i = 0;

    char *ptr = payload;
    for (i = 0; i < payload_size; i++, ptr++) {
        sendbuf[tx_len++] = *ptr;
    }

    if (type == CCN_TYPE_DATA) {//if return data, set IP of the machine invoke this request
//    	iph1->saddr = inet_addr(src_ip);
    	 printf("Return data\n");

//    	iph1->daddr = hash_name;
    	iph1->daddr = inet_addr("1.2.3.4");
    	udph1->dest = 1234;


    } else {//Interest forwarding
    	udph1->dest = 1234;
    	iph1->daddr = hash_name; //set hash value to source IP
    }

    //copy payload from CCN packet to payload
    /*
        memset(pl, 0 , BUF_SIZ - tx_len_base);//set pl to zero
        memcpy(pl, payload,  payload_size);
    
     */
    //Fill in remaining header info:
    /* Length of UDP payload and header */
    udph1->len = htons(tx_len - sizeof (struct ether_header) - sizeof (struct iphdr));
    /* Length of IP payload and header */
    iph1->tot_len = htons(tx_len - sizeof (struct ether_header));
    /* Calculate IP checksum on completed header */
    iph1->check = csum((unsigned short *) (sendbuf + sizeof (struct ether_header)), sizeof (struct iphdr) / 2);
    /*
        iph->check=0;
     */
    /* Send packet */
    if (sendto(sockfd, sendbuf, tx_len, 0, (struct sockaddr*) &socket_address, sizeof (struct sockaddr_ll)) < 0)
        printf("Send failed\n");
    /*
        close(sockfd);
     */
    count3++;
    printf("Send to raw socket, hash content name into %s\n",print_ip(hash_name));
    return (EXIT_SUCCESS);
}


//You can changed to other function you prefer (str -> int)
//http://www.cse.yorku.ca/~oz/hash.html
/**
 * Hash function djb2
 * @param str
 * @return 
 */
unsigned long hash(unsigned char *str)
    {
        unsigned long hash = 5381;
        int c;

        while (c = *str++)
            hash = ((hash << 5) + hash) + c; /* hash * 33 + c */

        return hash;
    }




// total udp header length: 8 bytes (=64 bits)
// Function for checksum calculation.
unsigned short csum(unsigned short *buf, int nwords) { //
    unsigned long sum;
    for (sum = 0; nwords > 0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short) (~sum);
}



/*Print Ip addr from int
 */
char* print_ip(int ip) {
	char str_ip[1000];
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;
    sprintf(str_ip,"%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);
    return str_ip;
}

//Get Local IP address of the interface
char* getLocalIpAddr(char *interface) {
	char str_ip[1000];
	int fd;
	struct ifreq ifr;

	fd = socket(AF_INET, SOCK_DGRAM, 0);

	/* I want to get an IPv4 IP address */
	ifr.ifr_addr.sa_family = AF_INET;

	/* I want IP address attached to "eth0" */
	strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);

	ioctl(fd, SIOCGIFADDR, &ifr);

	close(fd);

	/* display result */
//	printf("%s\n", inet_ntoa(((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr));
	sprintf(str_ip, "%s\n",
			inet_ntoa(((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr));
	return str_ip;

}




