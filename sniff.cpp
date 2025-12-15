// sniff.cpp
// Debian 12, libpcap + libcurl + libndpi4.2
// Build:
//   g++ -std=c++17 sniff.cpp -I/usr/include/ndpi -lpcap -lcurl -lndpi -o sniffer
//
// Run:
//   ./sniffer eth0

#include <pcap.h>
#include <curl/curl.h>

#include <ndpi/ndpi_api.h>

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include <csignal>
#include <cstdint>
#include <cstring>
#include <cstdlib>

#include <map>
#include <mutex>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <string>


static const char *DEFAULT_IFACE = "eth0";
static const char *CONTROL_PLANE_URL = "http://127.0.0.1:8000/sniffer-events";


struct FlowKey {
    uint32_t src_ip;   // network order
    uint32_t dst_ip;   // network order
    uint16_t src_port; // host order
    uint16_t dst_port; // host order
    uint8_t  l4_proto; // IPPROTO_TCP/UDP/ICMP/etc.

    bool operator<(const FlowKey &o) const {
        if (src_ip   != o.src_ip)   return src_ip   < o.src_ip;
        if (dst_ip   != o.dst_ip)   return dst_ip   < o.dst_ip;
        if (src_port != o.src_port) return src_port < o.src_port;
        if (dst_port != o.dst_port) return dst_port < o.dst_port;
        return l4_proto < o.l4_proto;
    }
};

struct NdpiFlowState {
    ndpi_flow_struct *flow;
    ndpi_protocol     proto;
    bool              detected;

    NdpiFlowState() : flow(nullptr), detected(false) {
        std::memset(&proto, 0, sizeof(proto));
    }
};

static ndpi_detection_module_struct *g_ndpi_mod   = nullptr;
static uint32_t                      g_ndpi_flow_size = 0;
static std::map<FlowKey, NdpiFlowState> g_ndpi_flows;
static std::mutex                    g_ndpi_mutex;


static std::string mac_to_string(const uint8_t *mac) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0')
        << std::setw(2) << (int)mac[0] << ":"
        << std::setw(2) << (int)mac[1] << ":"
        << std::setw(2) << (int)mac[2] << ":"
        << std::setw(2) << (int)mac[3] << ":"
        << std::setw(2) << (int)mac[4] << ":"
        << std::setw(2) << (int)mac[5];
    return oss.str();
}

static std::string ip_to_string(uint32_t ip_net) {
    struct in_addr addr{};
    addr.s_addr = ip_net;
    char buf[INET_ADDRSTRLEN];
    if (!inet_ntop(AF_INET, &addr, buf, sizeof(buf))) {
        return "0.0.0.0";
    }
    return std::string(buf);
}

static bool is_private_ipv4(uint32_t ip_net) {
    uint32_t ip = ntohl(ip_net);
    uint8_t a = (ip >> 24) & 0xFF;
    uint8_t b = (ip >> 16) & 0xFF;

    if (a == 10) return true;
    if (a == 172 && (b >= 16 && b <= 31)) return true;
    if (a == 192 && b == 168) return true;
    return false;
}

static std::string infer_direction(uint32_t src_ip_net, uint32_t dst_ip_net) {
    bool src_local = is_private_ipv4(src_ip_net);
    bool dst_local = is_private_ipv4(dst_ip_net);

    if (src_local && !dst_local) return "outbound";
    if (!src_local && dst_local) return "inbound";
    // fallback so Pydantic doesn't cry
    return "outbound";
}

static std::string json_escape(const std::string &s) {
    std::string out;
    out.reserve(s.size() + 4);
    for (unsigned char c : s) {
        switch (c) {
        case '\\': out += "\\\\"; break;
        case '"':  out += "\\\""; break;
        case '\b': out += "\\b";  break;
        case '\f': out += "\\f";  break;
        case '\n': out += "\\n";  break;
        case '\r': out += "\\r";  break;
        case '\t': out += "\\t";  break;
        default:
            if (c < 0x20) {
                char buf[7];
                std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                out += buf;
            } else {
                out += c;
            }
        }
    }
    return out;
}

static std::string extract_tls_sni(const uint8_t *data, size_t len) {
    if (len < 5) return "";
    uint8_t content_type = data[0];
    if (content_type != 0x16) return ""; // handshake
    uint16_t rec_len = (data[3] << 8) | data[4];
    if (5 + rec_len > len) return "";

    if (len < 9) return "";
    const uint8_t *hs = data + 5;
    uint8_t hs_type = hs[0];
    if (hs_type != 0x01) return ""; // ClientHello

    uint32_t hs_len = (hs[1] << 16) | (hs[2] << 8) | hs[3];
    if (hs_len + 4 > rec_len) return "";

    size_t offset = 4;

    // client_version (2) + random (32)
    if (offset + 2 + 32 > rec_len) return "";
    offset += 2 + 32;

    if (offset + 1 > rec_len) return "";
    uint8_t sid_len = hs[offset];
    offset += 1 + sid_len;
    if (offset > rec_len) return "";

    if (offset + 2 > rec_len) return "";
    uint16_t cs_len = (hs[offset] << 8) | hs[offset + 1];
    offset += 2 + cs_len;
    if (offset > rec_len) return "";

    if (offset + 1 > rec_len) return "";
    uint8_t cm_len = hs[offset];
    offset += 1 + cm_len;
    if (offset > rec_len) return "";

    if (offset + 2 > rec_len) return "";
    uint16_t ext_len = (hs[offset] << 8) | hs[offset + 1];
    offset += 2;
    if (offset + ext_len > rec_len) return "";

    size_t ext_end = offset + ext_len;
    while (offset + 4 <= ext_end) {
        uint16_t ext_type = (hs[offset] << 8) | hs[offset + 1];
        uint16_t ext_size = (hs[offset + 2] << 8) | hs[offset + 3];
        offset += 4;
        if (offset + ext_size > ext_end) break;

        if (ext_type == 0x0000) { // server_name
            const uint8_t *p = hs + offset;
            if (ext_size < 2) break;
            uint16_t list_len = (p[0] << 8) | p[1];
            p += 2;
            if (list_len < 3 || list_len > ext_size - 2) break;

            uint8_t name_type = p[0];
            uint16_t name_len = (p[1] << 8) | p[2];
            if (name_type != 0 || 3 + name_len > list_len) break;
            p += 3;
            return std::string(reinterpret_cast<const char *>(p), name_len);
        }

        offset += ext_size;
    }
    return "";
}


static std::mutex g_curl_mutex;

static void send_event_to_control_plane(const std::string &json_body) {
    std::lock_guard<std::mutex> lock(g_curl_mutex);

    CURL *curl = curl_easy_init();
    if (!curl) {
        std::cerr << "[sniffer] curl_easy_init() failed\n";
        return;
    }

    struct curl_slist *headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, CONTROL_PLANE_URL);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_body.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, json_body.size());
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 2L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 1L);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        std::cerr << "[sniffer] curl error: " << curl_easy_strerror(res) << "\n";
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
}


static void ndpi_init_global() {
    g_ndpi_mod = ndpi_init_detection_module(ndpi_no_prefs);
    if (!g_ndpi_mod) {
        std::cerr << "[sniffer] ndpi_init_detection_module() failed\n";
        std::exit(1);
    }

    NDPI_PROTOCOL_BITMASK all;
    NDPI_BITMASK_SET_ALL(all);
    ndpi_set_protocol_detection_bitmask2(g_ndpi_mod, &all);
    ndpi_finalize_initialization(g_ndpi_mod);

    g_ndpi_flow_size = ndpi_detection_get_sizeof_ndpi_flow_struct();

    std::cerr << "[sniffer] nDPI initialized, flow size = "
              << g_ndpi_flow_size << " bytes\n";
}

static void ndpi_term_global() {
    std::lock_guard<std::mutex> lock(g_ndpi_mutex);

    for (auto &kv : g_ndpi_flows) {
        if (kv.second.flow) {
            std::free(kv.second.flow);
            kv.second.flow = nullptr;
        }
    }
    g_ndpi_flows.clear();

    if (g_ndpi_mod) {
        ndpi_exit_detection_module(g_ndpi_mod);
        g_ndpi_mod = nullptr;
    }
}

static NdpiFlowState &get_ndpi_flow(const FlowKey &key) {
    std::lock_guard<std::mutex> lock(g_ndpi_mutex);

    auto it = g_ndpi_flows.find(key);
    if (it != g_ndpi_flows.end()) {
        return it->second;
    }

    NdpiFlowState st;
    st.flow = (ndpi_flow_struct *)std::calloc(1, g_ndpi_flow_size);
    if (!st.flow) {
        std::cerr << "[sniffer] calloc() for nDPI flow failed\n";
        std::exit(1);
    }

    auto res = g_ndpi_flows.emplace(key, st);
    return res.first->second;
}


static volatile bool g_stop = false;

static void sigint_handler(int) {
    g_stop = true;
}

static void packet_handler(
    u_char *user,
    const struct pcap_pkthdr *header,
    const u_char *packet
) {
    (void)user;

    if (header->caplen < sizeof(struct ether_header)) return;

    const struct ether_header *eth =
        reinterpret_cast<const struct ether_header *>(packet);

    if (ntohs(eth->ether_type) != ETHERTYPE_IP) return;

    const uint8_t *ip_start = packet + sizeof(struct ether_header);
    size_t ip_available = header->caplen - sizeof(struct ether_header);
    if (ip_available < sizeof(struct ip)) return;

    const struct ip *iph = reinterpret_cast<const struct ip *>(ip_start);
    if (iph->ip_v != 4) return;

    uint16_t ip_hdr_len = iph->ip_hl * 4;
    if (ip_available < ip_hdr_len) return;

    uint16_t total_len = ntohs(iph->ip_len);
    if (total_len > ip_available) total_len = (uint16_t)ip_available;

    uint8_t proto = iph->ip_p;
    uint32_t src_ip = iph->ip_src.s_addr;
    uint32_t dst_ip = iph->ip_dst.s_addr;

    uint16_t src_port = 0;
    uint16_t dst_port = 0;

    const uint8_t *l4_start = ip_start + ip_hdr_len;
    size_t l4_len = (total_len > ip_hdr_len) ? (total_len - ip_hdr_len) : 0;

    if (proto == IPPROTO_TCP) {
        if (l4_len < sizeof(struct tcphdr)) return;
        const struct tcphdr *tcph =
            reinterpret_cast<const struct tcphdr *>(l4_start);
        src_port = ntohs(tcph->source);
        dst_port = ntohs(tcph->dest);
    } else if (proto == IPPROTO_UDP) {
        if (l4_len < sizeof(struct udphdr)) return;
        const struct udphdr *udph =
            reinterpret_cast<const struct udphdr *>(l4_start);
        src_port = ntohs(udph->source);
        dst_port = ntohs(udph->dest);
    }

    // Per-flow ndpi
    FlowKey key{src_ip, dst_ip, src_port, dst_port, proto};
    NdpiFlowState &st = get_ndpi_flow(key);

    // current time in ms
    uint64_t t_ms =
        (uint64_t)header->ts.tv_sec * 1000ULL +
        (uint64_t)header->ts.tv_usec / 1000ULL;

    st.proto = ndpi_detection_process_packet(
        g_ndpi_mod,
        st.flow,
        (uint8_t *)ip_start,
        total_len,
        (uint32_t)t_ms
    );

    bool just_detected = false;
    if (!st.detected && ndpi_is_protocol_detected(g_ndpi_mod, st.proto)) {
        st.detected = true;
        just_detected = true;
    }

    // Only send on first classification; if you want *more* events, remove this
    if (!just_detected) {
        return;
    }

    // TLS SNI for tcp/443 (best-effort)
    std::string tls_sni;
    if (proto == IPPROTO_TCP &&
        (src_port == 443 || dst_port == 443) &&
        l4_len > sizeof(struct tcphdr)) {

        const struct tcphdr *tcph =
            reinterpret_cast<const struct tcphdr *>(l4_start);
        uint16_t th_len = tcph->doff * 4;
        if (l4_len > th_len) {
            const uint8_t *tls = l4_start + th_len;
            size_t tls_len = l4_len - th_len;
            tls_sni = extract_tls_sni(tls, tls_len);
        }
    }

    std::string proto_str;
    switch (proto) {
    case IPPROTO_TCP:  proto_str = "tcp";  break;
    case IPPROTO_UDP:  proto_str = "udp";  break;
    case IPPROTO_ICMP: proto_str = "icmp"; break;
    default:           proto_str = "any";  break;
    }

    std::string direction = infer_direction(src_ip, dst_ip);
    std::string src_ip_str = ip_to_string(src_ip);
    std::string dst_ip_str = ip_to_string(dst_ip);
    std::string src_mac_str = mac_to_string(eth->ether_shost);
    std::string dst_mac_str = mac_to_string(eth->ether_dhost);

    const char *master_name =
        ndpi_get_proto_name(g_ndpi_mod, st.proto.master_protocol);
    const char *app_name =
        ndpi_get_proto_name(g_ndpi_mod, st.proto.app_protocol);
    const char *cat_name =
        ndpi_category_get_name(g_ndpi_mod, st.proto.category);

    std::ostringstream json;
    json << "{";
    json << "\"src_ip\":\"" << src_ip_str << "\",";
    json << "\"dst_ip\":\"" << dst_ip_str << "\",";
    json << "\"src_port\":" << src_port << ",";
    json << "\"dst_port\":" << dst_port << ",";
    json << "\"protocol\":\"" << proto_str << "\",";
    json << "\"direction\":\"" << direction << "\",";
    json << "\"src_mac\":\"" << src_mac_str << "\",";
    json << "\"dst_mac\":\"" << dst_mac_str << "\",";
    json << "\"iface\":null,";
    json << "\"vlan_id\":null,";
    json << "\"packet_len\":" << header->len << ",";
    json << "\"ip_ttl\":" << (unsigned int)iph->ip_ttl << ",";
    json << "\"ip_tos\":" << (unsigned int)iph->ip_tos << ",";
    json << "\"tcp_flags\":null,";
    json << "\"dns_qname\":null,";
    json << "\"dns_answer_ip\":null,";
    json << "\"tls_sni\":" << (tls_sni.empty()
                               ? "null"
                               : "\"" + json_escape(tls_sni) + "\"") << ",";
    json << "\"ndpi_app_proto\":"
         << (app_name && *app_name
             ? ("\"" + json_escape(app_name) + "\"")
             : "null") << ",";
    json << "\"ndpi_master_proto\":"
         << (master_name && *master_name
             ? ("\"" + json_escape(master_name) + "\"")
             : "null") << ",";
    json << "\"ndpi_category\":"
         << (cat_name && *cat_name
             ? ("\"" + json_escape(cat_name) + "\"")
             : "null") << ",";
    json << "\"timestamp_ms\":" << t_ms;
    json << "}";

    send_event_to_control_plane(json.str());
}


int main(int argc, char **argv) {
    const char *iface = DEFAULT_IFACE;
    if (argc > 1) iface = argv[1];

    std::cerr << "[sniffer] Using interface: " << iface << "\n";
    std::cerr << "[sniffer] Control plane URL: " << CONTROL_PLANE_URL << "\n";

    curl_global_init(CURL_GLOBAL_DEFAULT);
    ndpi_init_global();

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(iface, 65535, 1, 1000, errbuf);
    if (!handle) {
        std::cerr << "[sniffer] pcap_open_live failed: " << errbuf << "\n";
        ndpi_term_global();
        curl_global_cleanup();
        return 1;
    }

    std::signal(SIGINT, sigint_handler);
    std::cerr << "[sniffer] Capturing, Ctrl+C to stop\n";

    while (!g_stop) {
        int ret = pcap_dispatch(handle, 0, packet_handler, nullptr);
        if (ret == -1) {
            std::cerr << "[sniffer] pcap_dispatch error: "
                      << pcap_geterr(handle) << "\n";
            break;
        }
    }

    pcap_close(handle);
    ndpi_term_global();
    curl_global_cleanup();
    std::cerr << "[sniffer] Stopped\n";
    return 0;
}
