/* pcap library wrapper for app */
#include <mockpcap/pcap_interface.h>

class Pcap : public PcapLib {
public:

    int findalldevs(
      pcap_if_t **alldevs,
      char *errbuf
    );

    void freealldevs(
      pcap_if_t *alldevs
    );

    pcap_t *open_live(
      const char *device_name,
      int snaplen,
      int is_promiscuous,
      int timeout_ms,
      char *errbuf
    );

    pcap_t *create(
      const char *device_name,
      char *errbuf
    );

    int set_snaplen(
      pcap_t *handle,
      int snaplen
    );

    int set_promisc(
      pcap_t *handle,
      int promisc
    );

    int set_immediate_mode(
      pcap_t *handle,
      int immediate_mode
    );

    int set_buffer_size(
      pcap_t *handle,
      int buffer_size
    );

    int set_timeout(
      pcap_t *handle,
      int to_ms
    );

    int activate(
      pcap_t *handle
    );

    int datalink(
      pcap_t *handle
    );

    int compile(
      pcap_t *handle,
      struct bpf_program *filter_compiled,
      const char *filter_exp,
      int is_optimize,
      bpf_u_int32 netmask
    );

    char *geterr(
      pcap_t *handle
    );

    int setfilter(
      pcap_t *handle,
      struct bpf_program *filter_compiled
    );

    int setdirection(
      pcap_t *handle,
      pcap_direction_t direction
    );

    int setnonblock(
      pcap_t *handle,
      int nonblock,
      char *errbuf
    );

    int next_ex(
      pcap_t *handle,
      struct pcap_pkthdr **pkt_header,
      const u_char **pkt_data
    );

    int loop(
      pcap_t *handle,
      int max_packets_num,
      pcap_handler handler,
      u_char *custom_data
    );

    void freecode(
      struct bpf_program *filter_compiled
    );

    int sendpacket(
      pcap_t *handle,
      const u_char *buf,
      int size
    );

    void close(
      pcap_t *handle
    );
};
