# ARP neighborhood entry filler

This simple daemon listens for arp requests on a set of interfaces, learns their Mac / IP association and fills the local ARP table.

The reason behind this is, with a pure L2 EVPN topology, the host where FRR runs never sees the ARP requests.
Because of that:

- the local neighbor table is never filled
- the zebra instance on the local endpoint won't learn the MAC / IP association
- FRR won't send the MAC / IP association as type 2 EVPN route
- ARP suppression on the remote endpoint won't work, and every ARP request is going to be forwarded through the fabric

Being the arp reply unicast, both leaf1 and leaf2 won't see it:

```raw
                  ┌────────────────────────────────┐
                  │                                │
                  │                                │
                  │                                │
┌───────────┐ ARP │           ┌───────────────┐    │
│           │     ├──────┐    │               │    │
│  host2    │◄────┤ eth1 ├────┤     br-10     │    │
│           │     ├──────┘    │               │    │
└───────────┘     │           └──────────▲────┘    │
                  │                      │         │
                  │                      │         │
                  │                      │         │
                  │             leaf2    │         │
                  └──────────────────────┼─────────┘
                                         │
                                         │   VXLan
                                         │
                  ┌──────────────────────┼─────────┐
                  │                      │         │
                  │                      │         │
                  │                      │         │
┌───────────┐ARP  │           ┌──────────┴────┐    │
│           │     ├──────┐    │               │    │
│  host1    ├────►│ eth1 ├────┤     br-10     │    │
│           │     ├──────┘    │               │    │
└───────────┘     │           └───────────────┘    │
                  │                                │
                  │                                │
                  │                                │
                  │             leaf1              │
                  └────────────────────────────────┘

```

To circumvent this, this daemon will observe ARP requests coming from the local interfaces, and will fill the local neighbor table based upon those requests.

In the scenario above, `leaf1` will learn about `host1`s MAC / IP association, and add it to the local neighbor table. By doing this, the MAC / IP association will
then be sent to `leaf2` as EVPN type 2 route.

```raw





                        ┌────────────────────────────────┐
                        │                                │
                        │                 ┌────────────┐ │
                        │                 │ neigh table│ │
                        │                 │            │ │
                        │                 │            │ │
                        │                 │            │ │
                        │                 │            │ │
                        │    ┌─────────┐  └────────────┘ │
                        │  ┌►│  ebpf   │         ▲       │
                        │  │ └─────┬───┘         │       │
                        │  │       │       ┌─────┴─────┐ │
                        │  │       └──────►│ userspace │ │
                        │  │               └───────────┘ │
      ┌───────────┐ARP  │  │                             │
      │           │     │  │        ┌───────────────┐    │
      │  host1    ├────►├──┴───┐    │               │    │
      │           │     │ eth1 ├────┤     br-10     │    │
      └───────────┘     ├──────┘    │               │    │
                        │           └───────────────┘    │
                        │                                │
                        │                                │
                        │             leaf1              │
                        └────────────────────────────────┘


```

## How to use it

The cli is pretty simple: a comma separated list of interfaces (no spaces!) the program must listen from, and the interface to be associated with the neighbor (the bridge, in case of L2 EVPN):

```bash
./fill-neighbor -attach-to eth2 -from-interface br10
```

## TODO

- Testing and proper CI. Can be done using two containers connected through a veth pair, asserting the content of the neighbor table.
- IPv6 support
- Think about having a local neighbor refresh policy: ideally, we should periodically ping / arping the interface to ensure the entry is maintained.
