#include <core.p4>
#include <xsa.p4>

const bit<16> ETHERTYPE_IPv4 = 0x800;

/* new constants */
const bit<8>  TYPE_TCP  = 6;

typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;


// ****************************************************************************** //
// *************************** H E A D E R S  *********************************** //
// ****************************************************************************** //

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
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
    ipv4_addr_t srcAddr;
    ipv4_addr_t dstAddr;
}

header tcp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<1>  intflag;
	bit<1>	bkp_path;
    bit<2>  res;
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



/********************************************/

// ****************************************************************************** //
// ************************* S T R U C T U R E S  ******************************* //
// ****************************************************************************** //

// header structure
struct headers {
    ethernet_t ethernet;
    ipv4_t ipv4;
	tcp_t tcp;
}


struct smartnic_metadata {
    bit<64> timestamp_ns;
    bit<16> pid;
    bit<3>  ingress_port;
    bit<3>  egress_port;
    bit<1>  truncate_enable;
    bit<16> truncate_length;
    bit<1>  rss_enable;
    bit<12> rss_entropy;
    bit<4>  drop_reason;
    bit<32> scratch;
}

// ****************************************************************************** //
// *************************** P A R S E R  ************************************* //
// ****************************************************************************** //

parser ParserImpl( packet_in packet,
                   out headers hdr,
                   inout smartnic_metadata sn_meta,
                   inout standard_metadata_t std_meta) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETHERTYPE_IPv4 : parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            TYPE_TCP : parse_tcp;
            default : accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
		transition accept;
    }

}

// ****************************************************************************** //
// **************************  P R O C E S S I N G   **************************** //
// ****************************************************************************** //

control MatchActionImpl( inout headers hdr,
                        inout smartnic_metadata sn_meta,
                        inout standard_metadata_t std_meta) {
    action drop() {
        std_meta.drop = 1;
    }
							  /* L3 Forwarding */

    action ipv4_forward(mac_addr_t nextHop, bit<3> egress_port) {
        sn_meta.egress_port = egress_port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = nextHop;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_routing{
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        default_action = NoAction();
        size = 64;
    }
			  /* ********************************************* */




    apply {
        // check for errors in the packet
        if (std_meta.parser_error != error.NoError) {
            drop();
            return;
        }

		if (hdr.ipv4.isValid()) {
			ipv4_routing.apply();
		}

    }
}

// ****************************************************************************** //
// ***************************  D E P A R S E R  ******************************** //
// ****************************************************************************** //

control DeparserImpl( packet_out packet,
                        in headers hdr,
                        inout smartnic_metadata sn_meta,
                        inout standard_metadata_t std_meta) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
		packet.emit(hdr.tcp);
    }
}

// ****************************************************************************** //
// *******************************  M A I N  ************************************ //
// ****************************************************************************** //

XilinxPipeline(
    ParserImpl(),
	MatchActionImpl(),
	DeparserImpl()
) main;
