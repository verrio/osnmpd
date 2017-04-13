/*
 * This file is part of the osnmpd distribution (https://github.com/verrio/osnmpd).
 * Copyright (C) 2016 Olivier Verriest
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef SRC_SNMP_MIB_IP_IF_CACHE_H_
#define SRC_SNMP_MIB_IP_IF_CACHE_H_

#include <linux/if.h>

#define MAX_IF_DESCR 80

enum IfType {
    IF_TYPE_OTHER = 1,
    IF_TYPE_REGULAR1822 = 2,
    IF_TYPE_HDH1822 = 3,
    IF_TYPE_DDN_X25 = 4,
    IF_TYPE_RFC877X25 = 5,
    IF_TYPE_ETHERNET_CSMA_CD = 6,
    IF_TYPE_SDLC = 17,
    IF_TYPE_PPP = 23,
    IF_TYPE_SOFTWARE_LOOP_BACK = 24,
    IF_TYPE_EON = 25,
    IF_TYPE_ETHERNET_3MBIT = 26,
    IF_TYPE_NSIP = 27,
    IF_TYPE_SLIP = 28,
    IF_TYPE_DS3 = 30,
    IF_TYPE_SIP = 31,
    IF_TYPE_RS232 = 33,
    IF_TYPE_PARA = 34,
    IF_TYPE_SONET = 39,
    IF_TYPE_ISO88022LLC = 41,
    IF_TYPE_SMDSDXI = 43,
    IF_TYPE_HSSI = 46,
    IF_TYPE_HIPPI = 47,
    IF_TYPE_MODEM = 48,
    IF_TYPE_SONET_PATH = 50,
    IF_TYPE_SONET_VT = 51,
    IF_TYPE_SMDSICIP = 52,
    IF_TYPE_PROP_VIRTUAL = 53,
    IF_TYPE_PROP_MULTIPLEXOR = 54,
    IF_TYPE_IEEE_802_12 = 55,
    IF_TYPE_FIBRE_CHANNEL = 56,
    IF_TYPE_AFLANE8023 = 59,
    IF_TYPE_AFLANE8025 = 60,
    IF_TYPE_CCTEMUL = 61,
    IF_TYPE_FAST_ETHER = 62,
    IF_TYPE_G703AT64K = 66,
    IF_TYPE_G703AT2MB = 67,
    IF_TYPE_QLLC = 68,
    IF_TYPE_FAST_ETHER_FX = 69,
    IF_TYPE_CHANNEL = 70,
    IF_TYPE_IEEE_802_11 = 71,
    IF_TYPE_IPSWITCH = 78,
    IF_TYPE_ATMLOGICAL = 80,
    IF_TYPE_DS0 = 81,
    IF_TYPE_DS0BUNDLE = 82,
    IF_TYPE_BSC = 83,
    IF_TYPE_ASYNC = 84,
    IF_TYPE_CNR = 85,
    IF_TYPE_ISO88025DTR = 86,
    IF_TYPE_EPLRS = 87,
    IF_TYPE_ARAP = 88,
    IF_TYPE_PROPCNLS = 89,
    IF_TYPE_HOSTPAD = 90,
    IF_TYPE_TERMPAD = 91,
    IF_TYPE_ADSL = 94,
    IF_TYPE_RADSL = 95,
    IF_TYPE_SDSL = 96,
    IF_TYPE_VDSL = 97,
    IF_TYPE_ISO88025CRFPINT = 98,
    IF_TYPE_PPP_MULTI_LINK_BUNDLE = 108,
    IF_TYPE_IP_OVER_CDLC = 109,
    IF_TYPE_IP_OVER_CLAW = 110,
    IF_TYPE_STACK_TO_STACK = 111,
    IF_TYPE_VIRTUAL_IP_ADDRESS = 112,
    IF_TYPE_MPC = 113,
    IF_TYPE_IP_OVER_ATM = 114,
    IF_TYPE_ISO_8802_5_FIBER = 115,
    IF_TYPE_TDLC = 116,
    IF_TYPE_GIGABIT_ETHERNET = 117,
    IF_TYPE_HDLC = 118,
    IF_TYPE_LAPF = 119,
    IF_TYPE_TRANSP_HDLC = 123,
    IF_TYPE_INTERLEAVE = 124,
    IF_TYPE_FAST = 125,
    IF_TYPE_IP = 126,
    IF_TYPE_DOCSCABLE_MACLAYER = 127,
    IF_TYPE_DOCSCABLE_DOWNSTREAM = 128,
    IF_TYPE_DOCSCABLE_UPSTREAM = 129,
    IF_TYPE_A12MPPSWITCH = 130,
    IF_TYPE_TUNNEL = 131,
    IF_TYPE_CES = 133,
    IF_TYPE_L2_VLAN = 135,
    IF_TYPE_L3_IPVLAN = 136,
    IF_TYPE_L3_IPXVLAN = 137,
    IF_TYPE_DIGITAL_POWERLINE = 138,
    IF_TYPE_MEDIA_MAIL_OVER_IP = 139,
    IF_TYPE_DTM = 140,
    IF_TYPE_DCN = 141,
    IF_TYPE_IP_FORWARD = 142,
    IF_TYPE_MSDSL = 143,
    IF_TYPE_IEEE1394 = 144,
    IF_TYPE_IF_GSN = 145,
    IF_TYPE_ATM_VIRTUAL = 149,
    IF_TYPE_MPLS_TUNNEL = 150,
    IF_TYPE_SRP = 151,
    IF_TYPE_IDSL = 154,
    IF_TYPE_COMPOSITE_LINK = 155,
    IF_TYPE_SS7_SIGLINK = 156,
    IF_TYPE_PROPWIRELESSP2P = 157,
    IF_TYPE_FRFORWARD = 158,
    IF_TYPE_RFC1483 = 159,
    IF_TYPE_USB = 160,
    IF_TYPE_IEEE8023ADLAG = 161,
    IF_TYPE_BGPPOLICYACCOUNTING = 162,
    IF_TYPE_FRF16MFRBUNDLE = 163,
    IF_TYPE_MPLS = 166,
    IF_TYPE_MFSIGLINK = 167,
    IF_TYPE_HDSL2 = 168,
    IF_TYPE_SHDSL = 169,
    IF_TYPE_DS1FDL = 170,
    IF_TYPE_POS = 171,
    IF_TYPE_PLC = 174,
    IF_TYPE_NFAS = 175,
    IF_TYPE_TR008 = 176,
    IF_TYPE_GR303RDT = 177,
    IF_TYPE_GR303IDT = 178,
    IF_TYPE_ISUP = 179,
    IF_TYPE_PROP_DOCSWIRELESS_MAC_LAYER = 180,
    IF_TYPE_PROP_DOCSWIRELESS_DOWNSTREAM = 181,
    IF_TYPE_PROP_DOCSWIRELESS_UPSTREAM = 182,
    IF_TYPE_PROPBWAP2MP = 184,
    IF_TYPE_SONETOVERHEADCHANNEL = 185,
    IF_TYPE_DIGITALWRAPPEROVERHEADCHANNEL = 186,
    IF_TYPE_RADIO_MAC = 188,
    IF_TYPE_IMT = 190,
    IF_TYPE_MVL = 191,
    IF_TYPE_REACHDSL = 192,
    IF_TYPE_FRDLCIENDPT = 193,
    IF_TYPE_OPTICAL_CHANNEL = 195,
    IF_TYPE_OPTICAL_TRANSPORT = 196,
    IF_TYPE_INFINIBAND = 199,
    IF_TYPE_Q2931 = 201,
    IF_TYPE_VIRTUAL_TG = 202,
    IF_TYPE_SIPTG = 203,
    IF_TYPE_SIPSIG = 204,
    IF_TYPE_DOCSCABLE_UPSTREAM_CHANNEL = 205,
    IF_TYPE_PON155 = 207,
    IF_TYPE_PON622 = 208,
    IF_TYPE_BRIDGE = 209,
    IF_TYPE_MPEG_TRANSPORT = 214,
    IF_TYPE_SIX_TO_FOUR = 215,
    IF_TYPE_GTP = 216,
    IF_TYPE_PDN_ETHER_LOOP_1 = 217,
    IF_TYPE_PDN_ETHER_LOOP_2 = 218,
    IF_TYPE_OPTICAL_CHANNEL_GROUP = 219,
    IF_TYPE_HOMEPNA = 220,
    IF_TYPE_GFP = 221,
    IF_TYPE_ACTEL_IS_META_LOOP = 223,
    IF_TYPE_FCIPLINK = 224,
    IF_TYPE_RPR = 225,
    IF_TYPE_QAM = 226,
    IF_TYPE_LMP = 227,
    IF_TYPE_DOCSCABLEMCMTSDOWNSTREAM = 229,
    IF_TYPE_ADSL2 = 230,
    IF_TYPE_MAC_SEC_CONTROLLED_IF = 231,
    IF_TYPE_MAC_SEC_UNCONTROLLED_IF = 232,
    IF_TYPE_AVICIOPTICALETHER = 233,
    IF_TYPE_MOCAVERSION1 = 236,
    IF_TYPE_ADSL2PLUS = 238,
    IF_TYPE_X86LAPS = 242,
    IF_TYPE_WWANPP = 243,
    IF_TYPE_WWANPP2 = 244,
    IF_TYPE_IFPWTYPE = 246,
    IF_TYPE_ILAN = 247,
    IF_TYPE_ALUELP = 249,
    IF_TYPE_GPON = 250,
    IF_TYPE_VDSL2 = 251,
    IF_TYPE_CAPWAPDOT11PROFILE = 252,
    IF_TYPE_CAPWAPDOT11BSS = 253,
    IF_TYPE_CAPWAPWTP_VIRTUAL_RADIO = 254,
    IF_TYPE_BITS = 255,
    IF_TYPE_DOCSCABLE_UPSTREAM_RFPORT = 256,
    IF_TYPE_CABLE_DOWNSTREAM_RFPORT = 257,
    IF_TYPE_VMWARE_VIRTUAL_NIC = 258,
    IF_TYPE_IEEE_802_1_54 = 259,
    IF_TYPE_OTNODU = 260,
    IF_TYPE_OTNOTU = 261,
    IF_TYPE_IFVFITYPE = 262,
    IF_TYPE_G9981 = 263,
    IF_TYPE_G9982 = 264,
    IF_TYPE_G9983 = 265,
    IF_TYPE_ALU_EPON = 266,
    IF_TYPE_ALU_EPON_ONU = 267,
    IF_TYPE_ALU_EPON_PHYSICAL_UNI = 268,
    IF_TYPE_ALU_EPON_LOGICAL_LINK = 269,
    IF_TYPE_ALU_GPON_ONU = 270,
    IF_TYPE_ALU_GPON_PHYSICAL_UNI = 271,
    IF_TYPE_VMWARE_NIC_TEAM = 272,
    IF_TYPE_DOCS_OFDM_DOWNSTREAM = 277,
    IF_TYPE_DOCS_OFDMA_UPSTREAM = 278,
    IF_TYPE_G_FAST = 279,
    IF_TYPE_SDCI = 280,
    IF_TYPE_XBOX_WIRELESS = 281,
    IF_TYPE_FAST_DSL = 282,
    IF_TYPE_DOCS_CABLE_SCTE_55D1_FWD_OOB = 283,
    IF_TYPE_DOCS_CABLE_SCTE_55D1_RET_OOB = 284,
    IF_TYPE_DOCS_CABLE_SCTE_55D2_DS_OOB = 285,
    IF_TYPE_DOCS_CABLE_SCTE_55D2_US_OOB = 286,
    IF_TYPE_DOCS_CABLE_NDF = 287,
    IF_TYPE_DOCS_CABLE_NDR = 288,
    IF_TYPE_PTM = 289,
    IF_TYPE_GHN = 290
};

enum IfOperState {
    IF_OPER_STATE_UP = 1,
    IF_OPER_STATE_DOWN = 2,
    IF_OPER_STATE_TESTING = 3,
    IF_OPER_STATE_UNKNOWN = 4,
    IF_OPER_STATE_DORMANT = 5,
    IF_OPER_STATE_NOTPRESENT = 6,
    IF_OPER_STATE_LOWERLAYERDOWN = 7
};

typedef struct {
    uint8_t admin_state;
    uint32_t retrans_time;
} Ip4IfaceEntry;

typedef struct {
    uint8_t admin_state;
    uint32_t retrans_time;
    uint32_t max_reasm_len;
    uint32_t reachable_time;
    uint32_t updated;
    uint8_t forwarding;
    uint64_t in_receives;
    uint64_t in_octets;
    uint64_t in_hdr_errors;
    uint64_t in_no_routes;
    uint64_t in_addr_errors;
    uint64_t in_unknown_protos;
    uint64_t in_truncated_pkts;
    uint64_t in_forw_datgrams;
    uint64_t reasm_reqds;
    uint64_t reasm_ok;
    uint64_t reasm_fails;
    uint64_t in_discards;
    uint64_t in_delivers;
    uint64_t out_requests;
    uint64_t out_forw_datagrams;
    uint64_t out_discards;
    uint64_t out_frag_oks;
    uint64_t out_frag_fails;
    uint64_t out_frag_creates;
    uint64_t out_transmits;
    uint64_t out_octets;
    uint64_t in_mcast_pkts;
    uint64_t in_mcast_octets;
    uint64_t out_mcast_pkts;
    uint64_t out_mcast_octets;
} Ip6IfaceEntry;

typedef struct {
    uint8_t promiscuous_state;
    uint8_t admin_state;
    uint8_t oper_state;
    uint32_t tx_qlen;
    uint32_t mtu;
    uint64_t speed;
    uint64_t out_errs;
    uint64_t out_discards;
    uint64_t out_ucast_pkts;
    uint64_t out_mcast_pkts;
    uint64_t out_bcast_pkts;
    uint64_t out_octets;
    uint64_t in_unknown_proto;
    uint64_t in_errs;
    uint64_t in_discards;
    uint64_t in_ucast_pkts;
    uint64_t in_mcast_pkts;
    uint64_t in_bcast_pkts;
    uint64_t in_octets;
} MacIfaceEntry;

typedef struct IfaceEntry {
    uint32_t id;
    enum IfType type;
    char iface_name[IFNAMSIZ];
    char iface_descr[MAX_IF_DESCR];
    Ip4IfaceEntry ip4_stats;
    Ip6IfaceEntry ip6_stats;
    MacIfaceEntry mac_stats;
    uint8_t address[64];
    size_t address_len;
    uint32_t iface_link;
    struct IfaceEntry *next;
} IfaceEntry;

/**
 * @internal
 * get_iface_list - returns the current network interface list
 *
 * @return iface list
 */
IfaceEntry *get_iface_list(void);

#endif /* SRC_SNMP_MIB_IP_IF_CACHE_H_ */
