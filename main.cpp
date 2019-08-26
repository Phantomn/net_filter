#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include "struct.h"
#include <libnetfilter_queue/libnetfilter_queue.h>
static char* url;
void dump(unsigned char* buf, int size) {
    int i;
    for (i = 0; i < size; i++) {
        if (i % 16 == 0)
            printf("\n");
        printf("%02x ", buf[i]);
    }
}
struct ip ip;
struct tcp tcp;
void ip_print(const u_char* ptr){
    u_char val_v_len = *ptr;
    ip.version = (val_v_len & 0xF0)>>4;
    ip.hdrLen = (val_v_len & 0x0F)*4;
    uint8_t val_dscp = *(ptr=ptr+1);
    uint8_t DSCP[2];
    DSCP[0] = (val_dscp & 0xFC);
    DSCP[1] = (val_dscp & 0x3);
    ip.totLen = *(ptr=ptr+1) << 8 | *(ptr=ptr+1);
    ip.ID = *(ptr=ptr+1) << 8 | *(ptr=ptr+1);
    ip.flags = *(ptr=ptr+1) << 8 | *(ptr=ptr+1);
    ip.ttl = *(ptr=ptr+1);
    ip.protocol = *(ptr=ptr+1);
    ip.chksum = *(ptr=ptr+1) << 8 | *(ptr=ptr+1);
    memcpy(ip.srcIp, ptr=ptr+1, 4);
    memcpy(ip.destIp, ptr=ptr+4, 4);


    if(ip.version == 4)
        printf("\nVersion : IPv4\n");
    if(ip.protocol == 0x06){
        printf("Protocol : TCP\n");
        printf("Header Length : %d\n",ip.hdrLen);
        printf("Total Length : %d\n",ip.totLen);
    }
}
void tcp_print(const u_char* ptr){
    tcp.srcPort = *(ptr) << 8 | *(ptr=ptr+1);
    tcp.destPort = *(ptr=ptr+1) << 8 | *(ptr=ptr+1);
    if(tcp.destPort == 80){
        printf("Source Port : %d\n", tcp.srcPort);
        printf("Destination Port : %d\n", tcp.destPort);
        tcp.hdrLen = (*(ptr=ptr+9) >> 4)*4;
        printf("Header Length : %d\n",tcp.hdrLen);
    }
}
/* returns packet id */
static u_int32_t print_pkt (struct nfq_q_handle* qh, struct nfq_data *tb)
{
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    u_int32_t mark,ifi;
    int ret;
    int res;
    unsigned char *data;


    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        id = ntohl(ph->packet_id);
        printf("hw_protocol=0x%04x hook=%u id=%u ",
               ntohs(ph->hw_protocol), ph->hook, id);
    }

    hwph = nfq_get_packet_hw(tb);
    if (hwph) {
        int i, hlen = ntohs(hwph->hw_addrlen);

        printf("hw_src_addr=");
        for (i = 0; i < hlen-1; i++)
            printf("%02x:", hwph->hw_addr[i]);
        printf("%02x ", hwph->hw_addr[hlen-1]);
    }

    mark = nfq_get_nfmark(tb);
    if (mark)
        printf("mark=%u ", mark);

    ifi = nfq_get_indev(tb);
    if (ifi)
        printf("indev=%u ", ifi);

    ifi = nfq_get_outdev(tb);
    if (ifi)
        printf("outdev=%u ", ifi);
    ifi = nfq_get_physindev(tb);
    if (ifi)
        printf("physindev=%u ", ifi);

    ifi = nfq_get_physoutdev(tb);
    if (ifi)
        printf("physoutdev=%u ", ifi);

    ret = nfq_get_payload(tb, &data);
    //dump(data, 0x50);
    if (ret >= 0)
        printf("payload_len=%d ", ret);
    if(ret > 0){
        ip_print(data);
        tcp_print(&data[ip.hdrLen]);
        if(ip.version == 0x4){
            if(tcp.destPort == 80){
                if(ret > (ip.hdrLen + tcp.hdrLen)){
                    int offset = ip.hdrLen + tcp.hdrLen;
                    unsigned char * payload = &data[offset+22];
                    printf("=======HTTP Payload=======\n%s\n%s\n",payload,url);
                    if(!strncmp(reinterpret_cast<const char*>(payload), reinterpret_cast<const char*>(url),strlen(url))){
                        res = nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
                        fprintf(stdout, "This Domain is Blocked\n");
                    }
                }
            }
        }

    }

    fputc('\n', stdout);
    res = nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

    return res;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data)
{
    u_int32_t id = print_pkt(qh, nfa);
    printf("entering callback\n");
    return id;
}

int main(int argc, char **argv)
{
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));
    url = argv[1];

    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h,  0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            printf("pkt received\n");
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        /* if your application is too slow to digest the packets that
         * are sent from kernel-space, the socket buffer that we use
         * to enqueue packets may fill up returning ENOBUFS. Depending
         * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
         * the doxygen documentation of this library on how to improve
         * this situation.
         */
        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
}
