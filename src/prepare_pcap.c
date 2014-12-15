/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *  Author : Guillaume TEISSIER from FTR&D 02/02/2006
 */
#include <pcap.h>
#include <pcap/sll.h>
#include <stdlib.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <string.h>

#include "prepare_pcap.h"
#include "screen.hpp"

int check(const u_int16_t *buffer, int len)
{
    int i, sum = 0;

    for (i = 0; i < (len & ~1); i += 2)
        sum += *buffer++;

    if (len & 1)
        sum += htons((*(const u_int8_t *)buffer) << 8);

    return sum;
}

u_int16_t checksum_carry(int s)
{
    int s_c = (s >> 16) + (s & 0xffff);
    return ~(s_c + (s_c >> 16)) & 0xffff;
}

static uint16_t parse_en10mb(const uint8_t *packet, const uint8_t **payload)
{
    const struct ether_header *hdr = (struct ether_header *)packet;
    *payload = &packet[sizeof(*hdr)];
    return ntohs(hdr->ether_type);
}

static uint16_t parse_linux_sll(const uint8_t *packet, const uint8_t **payload)
{
    const struct sll_header *hdr = (struct sll_header *)packet;
    *payload = &packet[sizeof(*hdr)];
    return ntohs(hdr->sll_protocol);
}

static const struct udphdr *parse_ether_hdr(int datalink, const uint8_t *packet)
{
    uint16_t protocol = 0, next_header = 0;
    const uint8_t *payload = NULL;
    const struct udphdr *udp = NULL;

    switch (datalink) {
    case DLT_NULL:
        ERROR("Don't understand DLT_NULL\n");
        break;
    case DLT_EN10MB:
        protocol = parse_en10mb(packet, &payload);
        break;
    case DLT_RAW:
        ERROR("Don't understand DLT_RAW\n");
        break;
    case DLT_LINUX_SLL:
        protocol = parse_linux_sll(packet, &payload);
        break;
    default:
        ERROR("Don't understand datalink\n");
        break;
    }

    if (protocol == ETH_P_IP) {
        const struct ip *iphdr = (const struct ip *)payload;

        if (iphdr->ip_v != 4)
            ERROR("Expected ipv4 package, found version %d\n", iphdr->ip_v);

        if (iphdr->ip_p != IPPROTO_UDP) {
            WARNING("Ignoring non udp packet");
            return NULL;
        }

        payload += iphdr->ip_hl << 2;
    } else if (protocol == ETH_P_IPV6) {
        const struct ip6_hdr *iphdr = (const struct ip6_hdr *)payload;

        if (iphdr->ip6_ctlun.ip6_un2_vfc != 6)
            ERROR("Expected ipv6 package, found version %d\n", iphdr->ip6_ctlun.ip6_un2_vfc);

        if (iphdr->ip6_ctlun.ip6_un1.ip6_un1_nxt != IPPROTO_UDP) {
            WARNING("Ignoring non udp packet");
            return NULL;
        }

        payload += sizeof(*iphdr);
    } else {
        WARNING("Ignoring non ipv4/v6 packet");
        return NULL;
    }

    return (const struct udphdr *)payload;
}

int prepare_pkts(const char *file, pcap_pkts *pkts)
{
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t *pcap;
    struct pcap_pkthdr *pkthdr = NULL;
    const u_char *pktdata = NULL;

    size_t n_pkts = 0;
    size_t max_length = 0;
    u_int16_t base = 0xffff;

    pcap_pkt *pkt_index;
    pkts->pkts = NULL;

    pcap = pcap_open_offline(file, errbuf);
    if (!pcap)
        ERROR("Can't open PCAP file '%s'", file);

    int datalink = pcap_datalink(/*handle*/ pcap);
    if (datalink != DLT_EN10MB)
        ERROR("Don't understand datalink of pcap file");

    while (pcap_next_ex(pcap, &pkthdr, &pktdata) == 1)
    {
        const struct udphdr *udp = parse_ether_hdr(datalink, pktdata);
        if (!udp)
            continue;

        size_t pktlen = ntohs(udp->uh_ulen);
        if (pktlen > PCAP_MAXPACKET) {
            ERROR("Packet size is too big! Recompile with bigger PCAP_MAXPACKET in prepare_pcap.h");
        }

        pkts->pkts = realloc(pkts->pkts, sizeof(*pkts->pkts) * (n_pkts + 1));
        if (!pkts->pkts)
            ERROR("Can't re-allocate memory for pcap pkt");
        pkt_index = pkts->pkts + n_pkts;
        pkt_index->pktlen = pktlen;
        pkt_index->ts = pkthdr->ts;
        pkt_index->data = malloc(pktlen);
        if (!pkt_index->data)
            ERROR("Can't allocate memory for pcap pkt data");
        memcpy(pkt_index->data, udp, pktlen);

        // compute a partial udp checksum not including port that will
        // be changed when sending RTP
        pkt_index->partial_check = check((u_int16_t *) &udp->uh_ulen, pktlen - 4) + ntohs(IPPROTO_UDP + pktlen);

        if (max_length < pktlen)
            max_length = pktlen;

        u_int16_t dport = ntohs(udp->uh_dport);
        if (base > dport)
            base = dport;

        n_pkts++;
    }

    pkts->max = pkts->pkts + n_pkts;
    pkts->max_length = max_length;
    pkts->base = base;
    fprintf(stderr, "In pcap %s, npkts %zd\nmax pkt length %zd\nbase port %d\n", file, n_pkts, max_length, base);
    pcap_close(pcap);

    return 0;
}

void free_pkts(pcap_pkts *pkts) {
    pcap_pkt *pkt_index;
    while (pkt_index < pkts->max) {
        free(pkt_index->data);
    }
    free(pkts->pkts);
}
