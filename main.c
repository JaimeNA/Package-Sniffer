#include <stdio.h>
#include <pcap.h>
#include <time.h>

#define DEBUG 1                                           /* Basic debugging by bitwise flag check */
#define SIZE_ETHERNET 14                                  /* ethernet headers are always exactly 14 bytes */

bpf_u_int32 mask;		                                  /* The netmask of our sniffing device */
bpf_u_int32 net;		                                  /* The IP of our sniffing device */

void captureDev();
void getPacket(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);

int main()
{

    const char *packet;		                              /* The actual packet */
    char filter_exp[] = "port 5000";	                  /* The filter expression */
    struct bpf_program fp;		                          /* The compiled filter expression */
    bpf_u_int32 mask;		                              /* The netmask of our sniffing device */
    bpf_u_int32 net;		                              /* The IP of our sniffing device */

    /* Opens the device for sniffing */
    pcap_t *handle;

    captureDev();

	/* Close the session */
    printf("\nClosing session... \n");

	pcap_close(handle);

	return(0);
}

void captureDev()
{

    pcap_if_t *alldevs;                                   /* Device data */
    char errbuf[PCAP_ERRBUF_SIZE];                        /* Error message */

    /* Retrieve the interfaces list */
    if (pcap_findalldevs(&alldevs, errbuf) == -1) 
    {               
        printf("Error in pcap_findalldevs: %s\n", errbuf);

        return;
    }
    else
    {
        
        printf("Network device detected \n");

#if (DEBUG & 1)
    printf("dev: %s\n", alldevs->name);
#endif

    }

    /* Opens the device for sniffing */
    pcap_t *handle;

    handle = pcap_open_live(alldevs->name, BUFSIZ, 1, 1000, errbuf);/* Put the device into promiscuous mode (detectable)*/

    if (handle == NULL) 
    {
	    fprintf(stderr, "Couldn't open device %s: %s\n", alldevs->name, errbuf);

	    return;
    }

    /* Filter for the sniffing session - uncomment to enable */
    //if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) /* Compile the expression */
    //{
	//    fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));

	//    return -1;
    //}

    //if (pcap_setfilter(handle, &fp) == -1)                   /* Apply the filter */
    //{
	//    fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));

	//    return -1;
    //}

    /* Determine the type of link-layer headers the device provides */
    if (pcap_datalink(handle) != DLT_EN10MB) 
    {
	    fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", alldevs->name);

	    return;
    }

    /* Get IP and netmask of the sniffing device */
    if (pcap_lookupnet(alldevs->name, &net, &mask, errbuf) == -1)/* Returns device IPv4 network numbers and corresponding network mask */
    {
	    fprintf(stderr, "Can't get netmask for device %s\n", alldevs->name);

	    net = 0;
	    mask = 0;
    }

    /* Start snifffing*/
    pcap_loop(handle, -1, getPacket, NULL);                /* Detect everytime a packet is sniffed and will return when 10 packets are sniffed */

}

void getPacket(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet)
{

    static struct tm        t;                             /* Holds our calculated time */
    static char             tim[20], out[28];              /* Buffers for readable time */  
    
    /* translate packet arrival time from timeval to struct tm */
    localtime_r(&header->ts.tv_sec, &t);
    strftime(tim, sizeof(tim), "%Y.%m.%d@%H:%M:%S", &t);    /* Make readable */
    snprintf(out, sizeof(out), "%s.%06d", tim, (int) header->ts.tv_usec); /* Done */

    /* Print package data */
    printf("%s", out);
	printf("\tcaplen: %d\tlen: %d", header->caplen, header->len);

    printf("\n");
}
