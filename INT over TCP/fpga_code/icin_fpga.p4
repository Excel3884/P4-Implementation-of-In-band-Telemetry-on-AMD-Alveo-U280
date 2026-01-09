#include <core.p4>
#include <xsa.p4>

const bit<16> ETHERTYPE_IPv4 = 0x800;

/* new constants */
const bit<8>  TYPE_TCP  = 6;
const bit<8> OPTION_KIND_COUNT = 8w0x73;
const bit<8> OPTION_LENGTH_COUNT = 8w4;
const bit<8> OPTION_KIND_TEL = 8w0x72;
const bit<8> OPTION_LENGTH_TEL = 8w8;
const bit<4> TCP_DATA_OFFSET_FIRST = 3; // delta for first hop
const bit<4> TCP_DATA_OFFSET = 2; // delta for any other hop
const bit<16> LAST_SWID = 3;
/* const bit<3> HOST_PORT = 0; // TO BE CHANGED TO CORRESPONDING INGRESS PORT FOR RIGHT DIRECTION */
const bit<16> ETHERTYPE_CTRL = 0x999; // ethertype for the control packet carrying the selected path


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

/* counter header & telemetry headers per switch (tcp options) */
header switch_count_t {
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
	bit<8> padding0;
	/* bit<16> counted_packets; */
}

header control_pkt_t {
	bit<8> path;
}

// exec_def_action is used as a key to execute an action for every telemetry packet
// default actions with parameters could not be added by the control plane
// so this exec_def_action is used as workaround to trigger the default action
// NOTE: the header is used only locally, it's set to valid/invalid internally only
/* header user_meta_t { */
/* 	bit<8> exec_def_action; //needs to be multiple of 8 probably */
/* } */


/********************************************/

// ****************************************************************************** //
// ************************* S T R U C T U R E S  ******************************* //
// ****************************************************************************** //

// header structure
struct headers {
    ethernet_t ethernet;
    ipv4_t ipv4;
	tcp_t tcp;
	switch_count_t sw_count; // number of following headers
	switch_int_t sw_int1; // 1st hop
	switch_int_t sw_int2; // 2nd hop
	switch_int_t sw_int3; // 3rd hop
	control_pkt_t control_pkt; // control packet containing selected path
	/* user_meta_t user_meta; // header used locally for user-defined metadata */
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
			ETHERTYPE_CTRL: parse_ctrl_pkt;
            default: accept;
        }
    }

	state parse_ctrl_pkt {
		packet.extract(hdr.control_pkt);
		transition accept;
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
        transition select(hdr.tcp.intflag) {
            1: parse_sw_count;
            default: accept;
        }
    }

	state parse_sw_count {
		packet.extract(hdr.sw_count);
		transition select(hdr.sw_count.count) {
			1: parse_sw_int1;
			default: accept;
		}
	}

	state parse_sw_int1 {
		packet.extract(hdr.sw_int1);
		transition select(hdr.sw_count.count) {
			2: parse_sw_int2;
			default: accept;
		}
	}

	state parse_sw_int2 {
		packet.extract(hdr.sw_int2);
		transition select(hdr.sw_count.count) {
			3: parse_sw_int3;
			default: accept;
		}
	}

	state parse_sw_int3 {
		packet.extract(hdr.sw_int3);
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

							  /* L2 Forwarding */

    action l2_forward(bit<3> egress_port){
        sn_meta.egress_port = egress_port;
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

			  /* ********************************************* */

							/* retrieve device specs */
	bit<16> device_id;
	bit<16> location;
	bit<4> vendor;
	bit<4> firmware;

    action get_specs(bit<16> def_device_id, bit<16> def_location, bit<4> def_vendor, bit<4> def_firmware) {
		device_id = def_device_id;
		location = def_location;
		vendor = def_vendor;
		firmware = def_firmware;
    }

    table specs_retrieval {
        key = {
            sn_meta.ingress_port : exact;
        }
        actions = {
            get_specs;
            NoAction;
        }
        default_action = NoAction();
		size = 16;
    }

			  /* ********************************************* */

			 /* counting total packets going through the switch */

	/* TODO: define register, actions, etc. */
	/* bit<16> counted_packets; */
	/* action retrieve_num_packets() { */

	/* } */


			  /* ********************************************* */

					 /* actions to embed data to packets */

	action add_sw_int1() {
		hdr.tcp.intflag = 1;
		/* hdr.ipv4.totalLen = hdr.ipv4.totalLen + (bit<16>)OPTION_LENGTH_COUNT + (bit<16>)OPTION_LENGTH_TEL; */
		/* hdr.tcp.dataOffset = hdr.tcp.dataOffset + TCP_DATA_OFFSET_FIRST; */

		hdr.sw_count.setValid();
		hdr.sw_count.kind = OPTION_KIND_COUNT;
		hdr.sw_count.length = OPTION_LENGTH_COUNT;
		hdr.sw_count.count = 1;

		hdr.sw_int1.setValid();
		hdr.sw_int1.kind = OPTION_KIND_TEL;
		hdr.sw_int1.length = OPTION_LENGTH_TEL;
		hdr.sw_int1.device_id = device_id;
		hdr.sw_int1.location = location;
		hdr.sw_int1.vendor = vendor;
		hdr.sw_int1.firmware = firmware;
		/* hdr.sw_int1.counted_packets = counted_packets; */
	}

	action add_sw_int2() {
		/* hdr.ipv4.totalLen = hdr.ipv4.totalLen + (bit<16>)OPTION_LENGTH_TEL; */
		/* hdr.tcp.dataOffset = hdr.tcp.dataOffset + TCP_DATA_OFFSET; */

		hdr.sw_int2.setValid();
		hdr.sw_int2.kind = OPTION_KIND_TEL;
		hdr.sw_int2.length = OPTION_LENGTH_TEL;
		hdr.sw_int2.device_id = device_id;
		hdr.sw_int2.location = location;
		hdr.sw_int2.vendor = vendor;
		hdr.sw_int2.firmware = firmware;
		/* hdr.sw_int2.counted_packets = counted_packets; */

	}

	action add_sw_int3() {
		/* hdr.ipv4.totalLen = hdr.ipv4.totalLen + (bit<16>)OPTION_LENGTH_TEL; */
		/* hdr.tcp.dataOffset = hdr.tcp.dataOffset + TCP_DATA_OFFSET; */

		hdr.sw_int3.setValid();
		hdr.sw_int3.kind = OPTION_KIND_TEL;
		hdr.sw_int3.length = OPTION_LENGTH_TEL;
		hdr.sw_int3.device_id = device_id;
		hdr.sw_int3.location = location;
		hdr.sw_int3.vendor = vendor;
		hdr.sw_int3.firmware = firmware;
		/* hdr.sw_int3.counted_packets = counted_packets; */

	}
			  /* ********************************************* */

		   /* retrieve the port where client's traffic is received (telemetry only for those packets) */

	bit<3> client_port;

    action get_port(bit<3> def_client_port) {
		client_port = def_client_port;
    }

    table traffic_origin {
        key = {
            sn_meta.ingress_port: exact;
        }
        actions = {
            get_port;
            NoAction;
        }
        default_action = NoAction();
		size = 16;
    }

			  /* ********************************************* */


    apply {
        // check for errors in the packet
        if (std_meta.parser_error != error.NoError) {
            drop();
            return;
        }

		if (hdr.ethernet.etherType == ETHERTYPE_CTRL) { //if it's a control packet (signal to change path)

			l2_forwarding.apply();

		} else if (hdr.ipv4.isValid()) { // if it's a "normal" packet
			ipv4_routing.apply(); // l3 forwaring

			// set the exec_def_action to 1 to be used as a key to the next tables (traffic origin + specs_retrieval)
			/* hdr.user_meta.setValid(); */
			/* hdr.user_meta.exec_def_action = 1; */

			// retrieve port, where traffic from client is received (telemetry only for those packets)
			traffic_origin.apply();

			// if packet is tcp and coming from client, then apply telemetry
			if (hdr.tcp.isValid() && sn_meta.egress_port != client_port) {

				specs_retrieval.apply(); // retrieve vendor, location, etc.
				if (!hdr.sw_count.isValid()) { // we are at switch 1

					/* retrieve_num_packets(); // get recorded number of packets */
					add_sw_int1(); // embed telemetry data into the packet

				} else { // we are at switch 2/3/4
					if (hdr.sw_count.count == 1) { // 2nd switch

						/* retrieve_num_packets(); // get recorded number of packets */
						add_sw_int2(); // embed telemetry data into the packet
						hdr.sw_count.count = hdr.sw_count.count + 1;

					} else if (hdr.sw_count.count == 2) { // 3rd switch

						/* retrieve_num_packets(); // get recorded number of packets */
						add_sw_int3(); // embed telemetry data into the packet
						hdr.sw_count.count = hdr.sw_count.count + 1;

					}

				}

			}
							 /*// traffic redirection */
			/*// check if packet is marked */
			/*if (hdr.tcp.isValid() && hdr.tcp.bkp_path == 1) { */
				/*if (device_id == 1 && sen_meta.egress_port == 0) { // at first switch and packets going to server */
					/*sn_meta.egress_port = 1; // to be changed to corresponding port for backup path */
				/*} else if (device_id == 3 && sn_meta.egress_port == 0) { //at sink node and packets going to client */
					/*sn_meta.egress_port = 1; // to be changed to corresponding port for backup path */
				/*} */
			/*} */

					/*************************************/
			/* hdr.user_meta.setInvalid(); */
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
		packet.emit(hdr.sw_count);
		packet.emit(hdr.sw_int1);
		packet.emit(hdr.sw_int2);
		packet.emit(hdr.sw_int3);
		packet.emit(hdr.control_pkt);
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
