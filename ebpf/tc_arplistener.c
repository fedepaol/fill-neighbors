// go:build ignore

#include "vmlinux.h"
#include "bpf_endian.h"
#include "bpf_core_read.h"
#include "bpf/bpf_helpers.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_MAP_ENTRIES 10000
#define BE_ETH_P_IP 8
#define BE_ETH_P_IPV6 56710
#define BE_ETH_P_ARP 0x0806

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

#define MAC_LEN 6
#define IP_LEN 4
#define ARP_REQUEST 1
#define ARP_REPLY 2
#define TC_ACT_OK 0
#define TC_ACT_SHOT -1

struct event
{
  u8 senderHWvalue[MAC_LEN];
  u8 senderProtoValue[IP_LEN];
  __u32 opCode;
};

struct
{
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
} events SEC(".maps");

const struct event *unused __attribute__((unused));

SEC("tc_incoming")
int arpReflect(struct __sk_buff *skb)
{
  void *data = (void *)(unsigned long long)skb->data;
  void *data_end = (void *)(unsigned long long)skb->data_end;

  struct ethhdr *eth = data;
  __u32 eth_proto;
  __u32 nh_off;
  nh_off = sizeof(struct ethhdr);

  if (data + nh_off + 1 > data_end)
  {
    return TC_ACT_SHOT;
  }
  eth_proto = bpf_ntohs(eth->h_proto);
  if (eth_proto != BE_ETH_P_ARP)
  {
    return TC_ACT_SHOT;
  }

  struct arphdr *arph;
  arph = data + sizeof(struct ethhdr);
  if ((void *)(arph + 1) > data_end)
  {
    bpf_printk("malformed 0");
    return TC_ACT_SHOT;
  }

  __u16 hlen = arph->ar_hln;
  __u16 plen = arph->ar_pln;
  __u32 opCode = bpf_ntohs(arph->ar_op);

  if (hlen > MAC_LEN)
  {
    hlen = MAC_LEN;
  }
  if (plen > IP_LEN)
  {
    plen = IP_LEN;
  }

  void *senderHwAddress = (void *)arph + sizeof(struct arphdr);
  if ((senderHwAddress + hlen) > data_end)
  {
    bpf_printk("malformed 0");
    return TC_ACT_SHOT;
  }
  void *senderProtoAddress = senderHwAddress + hlen;
  if ((senderProtoAddress + plen) > data_end)
  {
    bpf_printk("malformed 0");
    return TC_ACT_SHOT;
  }

  struct event *arp_event;

  arp_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
  if (!arp_event)
  {
    return 0;
  }

  bpf_core_read_str(arp_event->senderHWvalue, hlen + 1, senderHwAddress);
  bpf_core_read_str(arp_event->senderProtoValue, plen + 1, senderProtoAddress);
  arp_event->opCode = opCode;

  bpf_ringbuf_submit(arp_event, 0);
  return TC_ACT_OK;
}
