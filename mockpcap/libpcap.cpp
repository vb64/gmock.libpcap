/* pcap library wrapper implementation */
#include <mockpcap/libpcap.h>

int Pcap::findalldevs(
  pcap_if_t **alldevs,
  char *errbuf
) {
    return pcap_findalldevs(alldevs, errbuf);
}

/* Free the device list */
void Pcap::freealldevs(
  pcap_if_t *alldevs
) {
    pcap_freealldevs(alldevs);
}

pcap_t *Pcap::open_live(
  const char *device_name,
  int snaplen,
  int is_promiscuous,
  int timeout_ms,
  char *errbuf
) {
    return pcap_open_live(device_name, snaplen, is_promiscuous, timeout_ms, errbuf);
}

pcap_t *Pcap::create(
  const char *device_name,
  char *errbuf
) {
    return pcap_create(device_name, errbuf);
}

int Pcap::set_snaplen(
  pcap_t *handle,
  int snaplen
) {
    return pcap_set_snaplen(handle, snaplen);
}

int Pcap::set_promisc(
  pcap_t *handle,
  int promisc
) {
    return pcap_set_promisc(handle, promisc);
}

int Pcap::set_immediate_mode(
  pcap_t *handle,
  int immediate_mode
) {
#ifdef WIN32
    return pcap_setmintocopy(handle, (immediate_mode > 0) ? 10 : 16000);
#else
    return pcap_set_immediate_mode(handle, immediate_mode);
#endif
}

int Pcap::set_buffer_size(
  pcap_t *handle,
  int buffer_size
) {
    return pcap_set_buffer_size(handle, buffer_size);
}

int Pcap::set_timeout(
  pcap_t *handle,
  int to_ms
) {
    return pcap_set_timeout(handle, to_ms);
}

int Pcap::activate(
  pcap_t *handle
) {
    return pcap_activate(handle);
}

int Pcap::datalink(
  pcap_t *handle
) {
    return pcap_datalink(handle);
}

int Pcap::compile(
  pcap_t *handle,
  struct bpf_program *filter_compiled,
  const char *filter_exp,
  int is_optimize,
  bpf_u_int32 netmask
) {
    return pcap_compile(handle, filter_compiled, filter_exp, is_optimize, netmask);
}

char *Pcap::geterr(
  pcap_t *handle
) {
    return pcap_geterr(handle);
}

int Pcap::setfilter(
  pcap_t *handle,
  struct bpf_program *filter_compiled
) {
    return pcap_setfilter(handle, filter_compiled);
}

int Pcap::setdirection(
  pcap_t *handle,
  pcap_direction_t direction
) {
    return pcap_setdirection(handle, direction);
}

int Pcap::setnonblock(
  pcap_t *handle,
  int nonblock,
  char *errbuf
) {
    return pcap_setnonblock(handle, nonblock, errbuf);
}

int Pcap::next_ex(
  pcap_t *handle,
  struct pcap_pkthdr **pkt_header,
  const u_char **pkt_data
) {
    return pcap_next_ex(handle, pkt_header, pkt_data);
}

int Pcap::loop(
  pcap_t *handle,
  int max_packets_num,
  pcap_handler handler,
  u_char *custom_data
) {
    return pcap_loop(handle, max_packets_num, handler, custom_data);
}

void Pcap::freecode(
  struct bpf_program *filter_compiled
) {
    return pcap_freecode(filter_compiled);
}

int Pcap::sendpacket(
  pcap_t *handle,
  const u_char *buf,
  int size
) {
    return pcap_sendpacket(handle, buf, size);
}

void Pcap::close(
  pcap_t *handle
) {
    return close(handle);
}

Pcap pcap_wrapper;
PcapLib *pcap = &pcap_wrapper;
