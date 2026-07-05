"""Zigbee / 802.15.4 protocol: packet capture / inject / replay over the core verbs.

Analysis stays in stock tools (zbdsniff, tshark with the zigbee_pc_keys store). The core
verbs carry raw 802.15.4 PDUs unchanged; captures use DLT_IEEE802_15_4_WITHFCS (195) so
they dissect in wireshark/tshark. Frame layering is the target server's responsibility.
"""

PROTOCOL = "zigbee"
PCAP_DLT = 195          # LINKTYPE_IEEE802_15_4_WITHFCS
