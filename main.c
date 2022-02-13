#include <stdio.h>
#include <pcap.h>

void getPacket(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet)
{

	printf("%d  %d \n", header->ts.tv_sec, header->len);/* Print package data */

}

int main(int argc, char *argv[])
{

    pcap_if_t *alldevs;
    char *dev, errbuf[PCAP_ERRBUF_SIZE+1];                /* Device name and error message */
    const char *packet;		                              /* The actual packet */
    char filter_exp[] = "port 5000";	                  /* The filter expression */
    struct bpf_program fp;		                          /* The compiled filter expression */
    bpf_u_int32 mask;		                              /* The netmask of our sniffing device */
    bpf_u_int32 net;		                              /* The IP of our sniffing device */

    /* Retrieve the interfaces list */
    if (pcap_findalldevs(&alldevs, errbuf) == -1) 
    {               
        printf("Error in pcap_findalldevs: %s\n");

        return -1;
    }
    else
    {
        dev = alldevs->name;                              /* Get device name provided by findalldevs */

        printf("pcap_findalldevs(): %s\n", dev);
    }

    /* Opens the device for sniffing */
    pcap_t *handle;

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);/* Put the device into promiscuous mode (detectable)*/

    if (handle == NULL) 
    {
	    fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);

	    return -1;
    }

    /* Determine the type of link-layer headers the device provides */
    if (pcap_datalink(handle) != DLT_EN10MB) 
    {
	    fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", dev);

	    return -1;
    }

    /* Get IP and netmask of the sniffing device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)   /* Returns device IPv4 network numbers and corresponding network mask */
    {
	    fprintf(stderr, "Can't get netmask for device %s\n", dev);

	    net = 0;
	    mask = 0;
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

    /* Start snifffing*/
    printf("Time       | PKG Lenght | \n");

    pcap_loop(handle, 100, getPacket, NULL);                /* Detect everytime a packet is sniffed and will return when 10 packets are sniffed */

	/* Close the session */
    printf("\nClosing session... \n");

	pcap_close(handle);

	return(0);
}
