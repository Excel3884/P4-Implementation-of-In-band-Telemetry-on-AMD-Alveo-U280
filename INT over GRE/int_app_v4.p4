/*remove routing implement just simple switch*/

#include <core.p4>
#include <xsa.p4>

const bit<16> ETHERTYPE_IPv4 = 0x800;
const bit<4> INT_MD = 0x3;
const bit<8>  PROTOCOL_GRE = 0x2F;
const bit<16> TBD_INT = 0x1717;
const bit<4> INT_VERSION = 0x2; // We use the int V2 spec
const bit<8> DS_MAX_HOPS = 0x2;

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
    bit<8>    protocol; //set to 0x2F for GRE encapsulated packets
    bit<16>   hdrChecksum;
    ipv4_addr_t srcAddr;
    ipv4_addr_t dstAddr;
}

header gre_t{
    bit<1>  C;  //tied to 0 as no checksum is used
    bit<1>  R;
    bit<1>  K;  //set to 0 for basic GRE
    bit<1>  S;
    bit<1>  s;
    bit<3>  recursion;
    bit<5>  flags;
    bit<3>  version;
    bit<16> protocol_type;  //TBD_INT in P4 specification
    //other fields are optional
}

header int_shim_t{
    bit<4> type; //INT-MD has type 1 in P4 specification
    bit<1> G; //GRE flag - 0 indicates original packet (before INT insertion) had GRE encaps.
    bit<3> Rsvd;
    bit<8> length; // length without the int data and header!
    bit<16> next_protocol; //ethernet type
}

header int_t{
    bit<4> ver;
    bit<1> D;
    bit<1> E;
    bit<1> M;
    bit<12> reserved;
    bit<5> hop_ml;
    bit<8> remaining_hop_cnt;
    bit<16> instruction_mask;
    bit<16> domain_id;
    bit<16> ds_instr;
    bit<16> ds_flags;
}

header switch_int0_t {
    bit<16> swid;
    bit<16> trust_level;
    bit<64> timestamp;
}

header switch_int1_t {
    bit<16> swid;
    bit<16> trust_level;
    bit<64> timestamp;
}

// ****************************************************************************** //
// ************************* S T R U C T U R E S  ******************************* //
// ****************************************************************************** //

// header structure
struct headers {
    ethernet_t ethernet;
    ipv4_t ipv4;
    gre_t gre;
    int_shim_t int_shim_header;
    int_t int_header;
    switch_int0_t int_data_sw0;
    switch_int1_t int_data_sw1;
}


struct smartnic_metadata {
    bit<64> timestamp_ns;    // 64b timestamp (in nanoseconds). Set at packet arrival time.
    bit<16> pid;             // 16b packet id used by platform (READ ONLY - DO NOT EDIT).
    bit<3>  ingress_port;    // 3b ingress port (0:CMAC0, 1:CMAC1, 2:HOST0, 3:HOST1).
    bit<3>  egress_port;     // 3b egress port  (0:CMAC0, 1:CMAC1, 2:HOST0, 3:HOST1).
    bit<1>  truncate_enable; // 1b set to 1 to enable truncation of egress packet to 'truncate_length'.
    bit<16> truncate_length; // 16b set to desired length of egress packet (used when 'truncate_enable' == 1).
    bit<1>  rss_enable;      // 1b set to 1 to override open-nic-shell rss hash result with 'rss_entropy' value.
    bit<12> rss_entropy;     // 12b set to rss_entropy hash value (used for open-nic-shell qdma qid selection).
    bit<4>  drop_reason;     // reserved (tied to 0).
    bit<32> scratch;         // reserved (tied to 0).
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
            default: accept; //NOT | ethernet |+| IP |+| ... | packets will be likely dropped
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            PROTOCOL_GRE : parse_gre_encapsulation;
            default : accept; // If not an encapsulated packet, apply classical routing
        }
    }

    state parse_gre_encapsulation{
        packet.extract(hdr.gre);
        transition select(hdr.gre.protocol_type){
            TBD_INT: parse_int_shim;
            default: accept; // If encapsulated packet NOT containing INT, apply classical routing
        }
    }

    state parse_int_shim{
        packet.extract(hdr.int_shim_header);
        transition parse_in_band;
    }

    state parse_in_band{
        packet.extract(hdr.int_header);
        transition parse_int_sw0;
    }
    state parse_int_sw0{
        packet.extract(hdr.int_data_sw0);
        transition parse_int_sw1;
    }

    state parse_int_sw1{
        packet.extract(hdr.int_data_sw1);
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

    action sw0_push_id(bit<16> switch_id){
        hdr.int_data_sw0.swid = switch_id;
    }

    action sw1_push_id(bit<16> switch_id){
        hdr.int_data_sw1.swid = switch_id;
    }

    action sw0_push_ingress_timestamp(){
        hdr.int_data_sw0.timestamp = std_meta.ingress_timestamp;
    }

    action sw1_push_ingress_timestamp(){
        hdr.int_data_sw1.timestamp = std_meta.ingress_timestamp;
    }

    action sw0_push_trust_level(){
        hdr.int_data_sw0.trust_level = 16w0xdead;
    }

    action sw1_push_trust_level(){
        hdr.int_data_sw1.trust_level = 16w0xface;
    }

    table int_operation{
        key = {
            hdr.int_header.ds_instr: exact;
        }
        actions = {
            sw0_push_id;
            sw1_push_id;
            sw0_push_ingress_timestamp;
            sw1_push_ingress_timestamp;
            sw0_push_trust_level;
            sw1_push_trust_level;
            drop;
        }
        default_action = drop;
        size = 32;
    }

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

    action l2_forward(bit<3> egress_port){
        sn_meta.egress_port = egress_port;
    }

    table l2_forwarding{
        key = {
            hdr.ethernet.dstAddr : exact;
        }
        actions = {
            l2_forward;
            //backward_learning;
            //flooding;
            NoAction;
            drop;
        }
        default_action = NoAction();
        size = 16;
    }

    apply {
        // 1. errors in the packet
        if (std_meta.parser_error != error.NoError) {
            drop();
            return;
        }
        // 2. valid ethernet and valid INT header -> apply INT and forward
        if (hdr.ethernet.isValid() && hdr.int_header.isValid()) {
            sn_meta.rss_entropy = 12w0;
            sn_meta.rss_enable = 1w0;

            if(hdr.int_shim_header.type == INT_MD && hdr.int_header.remaining_hop_cnt > 0){
                hdr.int_header.remaining_hop_cnt = hdr.int_header.remaining_hop_cnt - 1;
                int_operation.apply();
            }
            if (hdr.int_header.remaining_hop_cnt == 0) {
                hdr.int_header.M = 1;
            }
            l2_forwarding.apply();
        }
        // 3. valid ethernet without INT -> apply forward
        else if(hdr.ethernet.isValid() && hdr.ipv4.isValid()){
            l2_forwarding.apply();
        }
        else{
            drop();
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
        packet.emit(hdr.gre);
        packet.emit(hdr.int_shim_header);
        packet.emit(hdr.int_header);
        packet.emit(hdr.int_data_sw0);
        packet.emit(hdr.int_data_sw1);
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
