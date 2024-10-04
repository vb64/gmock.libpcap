/* Pcap library interface */
#include <stdio.h>  // must be before include <pcap.h>
#define HAVE_REMOTE
#include <pcap.h>

#ifndef __PCAP_INTERFACE__
#define __PCAP_INTERFACE__

class PcapLib {
public:
    virtual ~PcapLib() {}

    virtual int findalldevs(
      pcap_if_t **alldevs,
      char *errbuf
    ) = 0;

    virtual void freealldevs(
      pcap_if_t *alldevs
    ) = 0;

    virtual pcap_t *open_live(
      const char *device_name,
      int snaplen,
      int is_promiscuous,
      int timeout_ms,
      char *errbuf
    ) = 0;

    virtual pcap_t *create(
      const char *device_name,
      char *errbuf
    ) = 0;

    virtual int set_snaplen(
      pcap_t *handle,
      int snaplen
    ) = 0;

    virtual int set_promisc(
      pcap_t *handle,
      int promisc
    ) = 0;

    virtual int set_immediate_mode(
      pcap_t *handle,
      int immediate_mode
    ) = 0;

    virtual int set_buffer_size(
      pcap_t *handle,
      int buffer_size
    ) = 0;

    virtual int set_timeout(
      pcap_t *handle,
      int to_ms
    ) = 0;

    virtual int activate(
      pcap_t *handle
    ) = 0;

    virtual int datalink(
      pcap_t *handle
    ) = 0;

    virtual int compile(
      pcap_t *handle,
      struct bpf_program *filter_compiled,
      const char *filter_exp,
      int is_optimize,
      bpf_u_int32 netmask
    ) = 0;

    virtual char *geterr(
      pcap_t *handle
    ) = 0;

    virtual int setfilter(
      pcap_t *handle,
      struct bpf_program *filter_compiled
    ) = 0;

    // https://www.tcpdump.org/manpages/pcap_setdirection.3pcap.html
    virtual int setdirection(
      pcap_t *handle,
      pcap_direction_t direction
    ) = 0;

    virtual int setnonblock(
      pcap_t *handle,
      int nonblock,
      char *errbuf
    ) = 0;

    virtual int next_ex(
      pcap_t *handle,
      struct pcap_pkthdr **pkt_header,
      const u_char **pkt_data
    ) = 0;

    virtual int loop(
      pcap_t *handle,
      int max_packets_num,
      pcap_handler handler,
      u_char *custom_data
    ) = 0;

    virtual void freecode(
      struct bpf_program *filter_compiled
    ) = 0;

    virtual int sendpacket(
      pcap_t *handle,
      const u_char *buf,
      int size
    ) = 0;

    virtual void close(
      pcap_t *handle
    ) = 0;
};

#endif

extern PcapLib *pcap;
