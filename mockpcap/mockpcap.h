/* Mocked pcap library wrapper */
#ifndef __MOCK_PCAP__
#define __MOCK_PCAP__

#include <gmock/gmock.h>
#include <mockpcap/pcap_interface.h>

class MockPcap : public PcapLib {

public:
    MOCK_METHOD(int, findalldevs, (pcap_if_t **alldevs, char *errbuf), (override));
    MOCK_METHOD(void, freealldevs, (pcap_if_t *alldevs), (override));
    MOCK_METHOD(pcap_t *, open_live, (const char *device_name, int snaplen, int is_promiscuous, int timeout_ms, char *errbuf), (override));

    MOCK_METHOD(pcap_t *, create, (const char *device_name, char *errbuf), (override));
    MOCK_METHOD(int, set_snaplen, (pcap_t *handle,int snaplen), (override));
    MOCK_METHOD(int, set_promisc, (pcap_t *handle, int promisc), (override));
    MOCK_METHOD(int, set_immediate_mode, (pcap_t *handle, int immediate_mode), (override));
    MOCK_METHOD(int, set_buffer_size, (pcap_t *handle, int buffer_size), (override));
    MOCK_METHOD(int, set_timeout, (pcap_t *handle, int to_ms), (override));
    MOCK_METHOD(int, activate, (pcap_t *handle), (override));
    MOCK_METHOD(int, setnonblock, (pcap_t *handle, int nonblock, char *errbuf), (override));
    MOCK_METHOD(int, next_ex, (pcap_t *handle, struct pcap_pkthdr **pkt_header, const u_char **pkt_data), (override));
    MOCK_METHOD(int, setdirection, (pcap_t *handle, pcap_direction_t direction), (override));

    MOCK_METHOD(int, datalink, (pcap_t *handle), (override));
    MOCK_METHOD(int, compile, (pcap_t *handle, struct bpf_program *filter_compiled, const char *filter_exp, int is_optimize, bpf_u_int32 netmask), (override));
    MOCK_METHOD(char *, geterr, (pcap_t *handle), (override));
    MOCK_METHOD(int, setfilter, (pcap_t *handle, struct bpf_program *filter_compiled), (override));
    MOCK_METHOD(int, loop, (pcap_t *handle, int max_packets_num, pcap_handler handler, u_char *custom_data), (override));
    MOCK_METHOD(void, freecode, (struct bpf_program *filter_compiled), (override));
    MOCK_METHOD(int, sendpacket, (pcap_t *handle, const u_char *buf, int size), (override));
    MOCK_METHOD(void, close, (pcap_t *handle), (override));
};

#endif
