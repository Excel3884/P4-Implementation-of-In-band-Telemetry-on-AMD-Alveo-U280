/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

// const bit<8>  UDP_PROTOCOL = 0x11;
const bit<16> ETHERTYPE_IPv4 = 0x800;
const bit<8>  TYPE_TCP  = 6;

// new constants
const bit<16> TYPE_FLAG = 1502;
const bit<8> OPTION_KIND_COUNT = 8w0x73;
const bit<8> OPTION_LENGTH_COUNT = 8w4;
const bit<8> OPTION_KIND_TEL = 8w0x72;
const bit<8> OPTION_LENGTH_TEL = 8w8;
const bit<4> TCP_DATA_OFFSET_FIRST = 3; // delta for first hop
const bit<4> TCP_DATA_OFFSET = 2; // delta for any other hop
const bit<16> LAST_SWID = 3;
const bit<16> ETHERTYPE_CTRL = 0x999; // ethertype for the control packet carrying the selected path

#define MAX_HOPS 3

register<bit<8>>(1) path_selection; // Stores the path (1 or 2)

/*************************************************************************
*********************** H E A D E R S ************************************
*************************************************************************/
typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ipv4Addr_t;
typedef bit<16> switchID_t;
typedef bit<1> reset_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ipv4Addr_t srcAddr;
    ipv4Addr_t dstAddr;
}

header tcp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<1>  intflag;
    bit<3>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

/* counter header & telemetry headers per switch (tcp options) */
header switch_count_t{
    bit<8> kind;
	bit<8> length;
	bit<16> count;
}

header switch_int_t {
	bit<8> kind;
	bit<8> length;
	bit<16> device_id;
	bit<16> location;
	bit<4> vendor;
	bit<4> firmware;
	bit<8> padding;
}

header control_pkt_t {
	bit<8> path;
}

struct parser_metadata_t {
    bit<16>  remaining;
}

struct metadata {
    @field_list(1) bit<8>  selected_path;
    bit<16> tcpLength;
    parser_metadata_t   parser_metadata;
    bit<16> device_id;
    bit<16> location;
    bit<4> vendor;
    bit<4> firmware;
}

struct headers {
    ethernet_t          ethernet;
    ipv4_t              ipv4;
    tcp_t               tcp;
    switch_count_t      sw_count;
    switch_int_t[MAX_HOPS]  sw_int;
    control_pkt_t control_pkt;
}

error { IPHeaderTooShort }

/*************************************************************************
************************ P A R S E R ************************************
*************************************************************************/
parser MyParser(packet_in packet,
               out headers hdr,
               inout metadata meta,
               inout standard_metadata_t standard_metadata) {

    state start {
         transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETHERTYPE_CTRL: parse_control_packet;
            ETHERTYPE_IPv4: parse_ipv4;
            default: accept;
        }
    }

    state parse_control_packet {
        packet.extract(hdr.control_pkt);
        transition accept;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
		// meta.tcpLength = hdr.ipv4.totalLen - (bit<16>)(hdr.ipv4.ihl << 2);
        meta.tcpLength = hdr.ipv4.totalLen - 20;
        transition select(hdr.ipv4.protocol){
            TYPE_TCP: parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition select(hdr.tcp.intflag){
            1: parse_sw_count;
            default: accept;
        }
    }

    state parse_sw_count{
        packet.extract(hdr.sw_count);
        meta.parser_metadata.remaining = hdr.sw_count.count;
        transition select(meta.parser_metadata.remaining){
            0:  accept;
            default: parse_sw_int;
        }
    }

    state parse_sw_int{
        packet.extract(hdr.sw_int.next);
        meta.parser_metadata.remaining = meta.parser_metadata.remaining - 1;
        transition select(meta.parser_metadata.remaining){
            0:  accept;
            default: parse_sw_int;
        }
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/
control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

/*************************************************************************
******************** I N G R E S S   P R O C E S S I N G *****************
*************************************************************************/
control MyIngress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm{
        key = {
            hdr.ipv4.dstAddr: lpm;
            meta.selected_path: exact;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        default_action = NoAction();
        size = 16;
    }

    action l2_forward(egressSpec_t port){
        standard_metadata.egress_spec = port;
    }


    table l2_forwarding{
        key = {
            hdr.ethernet.dstAddr : exact;
        }
        actions = {
            l2_forward;
            NoAction;
            drop;
        }
        default_action = NoAction();
        size = 16;
    }

    bit<16> device_id;
    bit<16> location;
    bit<4> vendor;
    bit<4> firmware;

    action get_specs(bit<16> def_device_id, bit<16> def_location, bit<4> def_vendor, bit<4> def_firmware) {
        meta.device_id = def_device_id;
        meta.location = def_location;
        meta.vendor = def_vendor;
        meta.firmware = def_firmware;
    }

    table specs_retrieval {
        actions = {
            get_specs;
            NoAction;
        }
        default_action = NoAction;
    }

    bit<3> client_port;
    action get_port(bit<3> def_client_port){
		client_port = def_client_port;
    }

    table traffic_origin {
        actions = {
            get_port;
            NoAction;
        }
        default_action = NoAction;
    }

    apply {
        path_selection.read(meta.selected_path,0);
        if (meta.selected_path == 0){
            meta.selected_path = 1;
            path_selection.write(0, meta.selected_path);
        }

        if (hdr.ethernet.etherType == ETHERTYPE_CTRL) { //if it's a control packet (signal to change path)
            meta.selected_path = hdr.control_pkt.path;
            path_selection.write(0, meta.selected_path);
            l2_forwarding.apply();

		} else if (hdr.ipv4.isValid()) {
            path_selection.read(meta.selected_path,0);
            ipv4_lpm.apply();
            specs_retrieval.apply();
			client_port = 0;
            traffic_origin.apply();

            if(hdr.tcp.isValid() && standard_metadata.egress_port != (bit<9>)client_port){
                if(!hdr.sw_count.isValid()){    // We are at switch 1
                    hdr.sw_count.setValid();
                    hdr.tcp.intflag = 1;
					/* hdr.ipv4.totalLen = hdr.ipv4.totalLen + (bit<16>)OPTION_LENGTH_COUNT + (bit<16>)OPTION_LENGTH_TEL; */
					/* hdr.tcp.dataOffset = hdr.tcp.dataOffset + TCP_DATA_OFFSET_FIRST; */
                    hdr.sw_count.count = 1;

                } else{
                    hdr.sw_count.count = hdr.sw_count.count + 1;
					/* hdr.ipv4.totalLen = hdr.ipv4.totalLen + (bit<16>)OPTION_LENGTH_TEL; */
					/* hdr.tcp.dataOffset = hdr.tcp.dataOffset + TCP_DATA_OFFSET; */
                }

                // Push INT data
                /* hdr.sw_int.push_front(1); */
                hdr.sw_int[0].setValid();

                // Assign values to new COUNT and INT header
                hdr.sw_count.kind = OPTION_KIND_COUNT;
                hdr.sw_count.length = OPTION_LENGTH_COUNT;
                hdr.sw_int[0].kind = OPTION_KIND_TEL;
                hdr.sw_int[0].length = OPTION_LENGTH_TEL;

                hdr.sw_int[0].device_id = meta.device_id;
                hdr.sw_int[0].location = meta.location;
                hdr.sw_int[0].vendor = meta.vendor;
                hdr.sw_int[0].firmware = meta.firmware;
            }
        }
    }
}

/*************************************************************************
******************** E G R E S S   P R O C E S S I N G *******************
*************************************************************************/
control MyEgress(inout headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    apply {


    }
}

/*************************************************************************
************** C H E C K S U M   C O M P U T A T I O N *******************
*************************************************************************/
control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);

        update_checksum_with_payload(
		hdr.tcp.isValid(),
		{
		hdr.ipv4.srcAddr,
		hdr.ipv4.dstAddr,
		8w0,
		hdr.ipv4.protocol,
		meta.tcpLength,
		hdr.tcp.srcPort,
		hdr.tcp.dstPort,
		hdr.tcp.seqNo,
		hdr.tcp.ackNo,
		hdr.tcp.dataOffset,
		hdr.tcp.intflag,
		hdr.tcp.res,
		hdr.tcp.cwr,
		hdr.tcp.ece,
		hdr.tcp.urg,
		hdr.tcp.ack,
		hdr.tcp.psh,
		hdr.tcp.rst,
		hdr.tcp.syn,
		hdr.tcp.fin,
		hdr.tcp.window,
		hdr.tcp.urgentPtr
		},
		hdr.tcp.checksum,
		HashAlgorithm.csum16);

        /* update_checksum_with_payload( */
		/* hdr.sw_int.isValid(), */
		/* { */
		/* hdr.ipv4.srcAddr, */
		/* hdr.ipv4.dstAddr, */
		/* 8w0, */
		/* hdr.ipv4.protocol, */
		/* /1* meta.tcpLength, *1/ */
        /* hdr.tcp.srcPort, */
		/* hdr.tcp.dstPort, */
		/* hdr.tcp.seqNo, */
		/* hdr.tcp.ackNo, */
		/* hdr.tcp.dataOffset, */
		/* hdr.tcp.intflag, */
		/* hdr.tcp.res, */
		/* hdr.tcp.cwr, */
		/* hdr.tcp.ece, */
		/* hdr.tcp.urg, */
		/* hdr.tcp.ack, */
		/* hdr.tcp.psh, */
		/* hdr.tcp.rst, */
		/* hdr.tcp.syn, */
		/* hdr.tcp.fin, */
		/* hdr.tcp.window, */
		/* hdr.tcp.urgentPtr, */
        /* hdr.sw_int.device_id, */
        /* hdr.sw_int.location, */
        /* hdr.sw_int.vendor, */
        /* hdr.sw_int.firmware, */
        /* hdr.sw_int.padding */
		/* }, */
		/* hdr.tcp.checksum, */
		/* HashAlgorithm.csum16); */

    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/
control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.sw_count);
        packet.emit(hdr.sw_int);
        packet.emit(hdr.control_pkt);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/
V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
