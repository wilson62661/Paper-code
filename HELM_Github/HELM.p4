// SPDX-License-Identifier: Apache-2.0
/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

/*************************************************************************
****************** C O N S T A N T S  AND  T Y P E S *********************
*************************************************************************/

#define ALARM_SESSION 250
#define CS_WIDTH 1280
#define BM_SIZE 1280
#define INDEX_WIDTH 16
#define timeout_threshold 512

// Defense Readiness State
#define DR_SAFE 0
#define DR_ACTIVE 1
#define DR_COOLDOWN 2

// Packet Classification
#define LEGITIMATE 0
#define MALICIOUS 1

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_DDOSM = 0x6605;
const bit<16> TYPE_RECIRC = 0x88B5;
const bit<8> TYPE_TCP = 6;
const bit<8> TYPE_UDP = 17;
const bit<32> MAX_REGISTER_ENTRIES = 65536;

typedef bit<9> egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ipv4Addr_t;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16> etherType;
}

header latency_t {
    bit<48> proc_us;   // 1 µs precision in BMv2
}

header ipv4_t {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3> flags;
    bit<13> fragOffset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdrChecksum;
    ipv4Addr_t srcAddr;
    ipv4Addr_t dstAddr;
}

/* TCP 標頭 */
header tcp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4> data_offset;
    bit<4> res;
    bit<1> cwr;
    bit<1> ece;
    bit<1> urg;
    bit<1> ack;
    bit<1> psh;
    bit<1> rst;
    bit<1> syn;
    bit<1> fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

/* UDP 標頭 */
header udp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> udp_total_len;
    bit<16> checksum;
}

struct metadata {
    @field_list(1) 
	int<32> ip_count;
    @field_list(1, 2)
        bit<32> src_entropy_term;
    @field_list(1, 2, 3)
        bit<32> dst_entropy_term;
    @field_list(1, 2, 3, 4)
        bit<32> pktlen_entropy_term;
    @field_list(1, 2, 3, 4, 5)
        bit<32> pkt_num;
    @field_list(1, 2, 3, 4, 5, 6)
        bit<32> src_entropy;
    @field_list(1, 2, 3, 4, 5, 6, 7)
        bit<32> src_ewma;
    @field_list(1, 2, 3, 4, 5, 6, 7, 8)
        bit<32> src_ewmmd;
    @field_list(1, 2, 3, 4, 5, 6, 7, 8, 9)
        bit<32> dst_entropy;
    @field_list(1, 2, 3, 4, 5, 6, 7, 8, 9, 10)
        bit<32> dst_ewma;
    @field_list(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11)
        bit<32> dst_ewmmd;
    @field_list(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12)
        bit<8> alarm;
    @field_list(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13)
        bit<8> dr_state;
    @field_list(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14) 
	int<32> pktlen_count;
    @field_list(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15)
        bit<32> pktlen_ewma;
    @field_list(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16)
        bit<32> pktlen_ewmmd;
    @field_list(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17)
        bit<32> pktlen_entropy;
    @field_list(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18)
	bit<64> process_time;
        
    // 特徵
    bit<32> hdr_dstip;
    bit<16> hdr_srcport;
    bit<16> hdr_dstport;
    bit<32> pkt_len;
    bit<1> syn_flag;
    bit<1> fin_flag;
    bit<1> ack_flag;
    bit<1> psh_flag;
    bit<1> rst_flag;
    bit<1> ece_flag;

    // 分類結果
    bit<8> class0;
    bit<8> class1;
    bit<8> final_class;

    // codewords
    bit<256> codeword0;
    bit<256> codeword1;

    bit<1> classification;
}

struct headers {
    ethernet_t ethernet;
    ipv4_t ipv4;
    latency_t lat;
    tcp_t tcp;
    udp_t udp;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
         out headers hdr,
         inout metadata meta,
         inout standard_metadata_t standard_metadata) {
    // 解析器起點
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
        TYPE_IPV4: parse_ipv4;
        default: accept;
        }
    }

    // IPv4 → TCP/UDP 分流
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
	meta.hdr_dstip = hdr.ipv4.dstAddr;
        transition select(hdr.ipv4.protocol) {
        TYPE_TCP: parse_tcp;
        TYPE_UDP: parse_udp;
        default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        meta.hdr_dstport = hdr.tcp.dst_port;
        meta.hdr_srcport = hdr.tcp.src_port;
        meta.ack_flag = hdr.tcp.ack;
        //meta.syn_flag = hdr.tcp.syn;
        //meta.fin_flag = hdr.tcp.fin;
	//meta.psh_flag = hdr.tcp.psh;
	//meta.rst_flag = hdr.tcp.rst;
	//meta.ece_flag = hdr.tcp.ece;
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        meta.hdr_dstport = hdr.udp.dst_port;
        meta.hdr_srcport = hdr.udp.src_port;
        meta.ack_flag = 0;
        //meta.syn_flag = 0;
        //meta.fin_flag = 0;
	//meta.psh_flag = 0;
	//meta.rst_flag = 0;
	//meta.ece_flag = 0;
        transition accept;
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {}
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    // 觀測視窗參數
    register<bit<5>>(1) log2_m;
    register<bit<32>>(1) training_len;

    // 觀察窗控制
    register<bit<32>>(1) ow_counter;
    register<bit<32>>(1) pkt_counter;

    // CS_Src_Curr (來源 IP) (當前 OW)
    // Counters
    register<int<32>>(CS_WIDTH) cs_src_curr_1;
    register<int<32>>(CS_WIDTH) cs_src_curr_2;
    register<int<32>>(CS_WIDTH) cs_src_curr_3;
    register<int<32>>(CS_WIDTH) cs_src_curr_4;
    // Annotations
    register<bit<8>>(CS_WIDTH) cs_src_curr_1_wid;
    register<bit<8>>(CS_WIDTH) cs_src_curr_2_wid;
    register<bit<8>>(CS_WIDTH) cs_src_curr_3_wid;
    register<bit<8>>(CS_WIDTH) cs_src_curr_4_wid;


    // CS_Dst_Curr (目的 IP) (當前 OW)
    // Counters
    register<int<32>>(CS_WIDTH) cs_dst_curr_1;
    register<int<32>>(CS_WIDTH) cs_dst_curr_2;
    register<int<32>>(CS_WIDTH) cs_dst_curr_3;
    register<int<32>>(CS_WIDTH) cs_dst_curr_4;
    // 註釋
    register<bit<8>>(CS_WIDTH) cs_dst_curr_1_wid;
    register<bit<8>>(CS_WIDTH) cs_dst_curr_2_wid;
    register<bit<8>>(CS_WIDTH) cs_dst_curr_3_wid;
    register<bit<8>>(CS_WIDTH) cs_dst_curr_4_wid;

    // CS_Dst_Last (目的 IP) (前一個 OW)
    register<int<32>>(CS_WIDTH) cs_dst_last_1;
    register<int<32>>(CS_WIDTH) cs_dst_last_2;
    register<int<32>>(CS_WIDTH) cs_dst_last_3;
    register<int<32>>(CS_WIDTH) cs_dst_last_4;

    // CS_PktLen_Curr (封包長度) (當前 OW)
    // Counters
    register<int<32>>(CS_WIDTH) cs_pktlen_curr_1;
    register<int<32>>(CS_WIDTH) cs_pktlen_curr_2;
    register<int<32>>(CS_WIDTH) cs_pktlen_curr_3;
    register<int<32>>(CS_WIDTH) cs_pktlen_curr_4;
    // Annotations
    register<bit<8>>(CS_WIDTH) cs_pktlen_curr_1_wid;
    register<bit<8>>(CS_WIDTH) cs_pktlen_curr_2_wid;
    register<bit<8>>(CS_WIDTH) cs_pktlen_curr_3_wid;
    register<bit<8>>(CS_WIDTH) cs_pktlen_curr_4_wid;

    // 每格 1 bit 用來記錄目的IP是否有出現過, 總共1280個格子
    register<bit<1>>(BM_SIZE) bmap_dst_curr;
    // 註釋
    register<bit<8>>(BM_SIZE) bmap_dst_curr_wid;

    // 熵規範 - 定點表示：28 個整數位元，4 個小數位元。
    //Debug
    register<bit<32>>(1) src_S;
    register<bit<32>>(1) dst_S;
    register<bit<32>>(1) pktlen_S;


    // 熵 EWMA 和 EWMMD - 定點表示法： 14 個整數位元，18 個小數位元。
    register<bit<32>>(1) src_ewma;
    register<bit<32>>(1) src_ewmmd;
    register<bit<32>>(1) dst_ewma;
    register<bit<32>>(1) dst_ewmmd;
    register<bit<32>>(1) pktlen_ewma;
    register<bit<32>>(1) pktlen_ewmmd;
/*    
    //Debug
    register<bit<32>>(1) src_entropy;
    register<bit<32>>(1) dst_entropy;
    register<bit<32>>(1) pktlen_entropy;
    register<bit<32>>(1) src_thresh_log;
    register<bit<32>>(1) dst_thresh_log;
    register<bit<32>>(1) pktlen_thresh_log;
*/
    register<bit<32>>(1) dst_uniq_count;
    register<bit<32>>(1) dst_uniq_compare;

    // 平滑 & 敏感係數
    register<bit<8>>(1) alpha; // 定點表示法： 0 個整數位元，8 個小數位元。
    register<bit<8>>(1) k;     // 定點表示法： 5 個整數位元，3 個小數位元。

    // 交換器狀態的暫存器
    register<bit<8>>(1) dr_state;

    // 動作部分
    /* 如果位於葉節點，則指定類別 */
    action SetClass0(bit<8> classe) {
        meta.class0 = classe;
    }

    action SetClass1(bit<8> classe) {
        meta.class1 = classe;
    }

    /* 特徵表動作 */
    action SetCode0(bit<1> code0, bit<1> code1) {
        meta.codeword0 [255:255] = code0;
        meta.codeword1 [255:255] = code1;
    }

    action SetCode1(bit<8> code0, bit<2> code1) {
        meta.codeword0 [254:247] = code0;
        meta.codeword1 [254:253] = code1;
    }

    action SetCode2(bit<1> code0, bit<2> code1) {
        meta.codeword0[246:246] = code0;
        meta.codeword1[252:251] = code1;
    }

    action SetCode3(bit<6> code0) {
        meta.codeword0[245:240] = code0;
    }

    action SetCode4(bit<7> code0, bit<6> code1) {
        meta.codeword0[239:233] = code0;
        meta.codeword1[250:245] = code1;
    }

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(egressSpec_t port) {
        standard_metadata.egress_spec = port;
    }

    /* 投票時設定最終類別 */
    action set_final_class(bit<8> class_result) {
        if (class_result == 0)
	    meta.classification = LEGITIMATE;
	else
	    meta.classification = MALICIOUS;
    }

    action get_src_entropy_term(bit<32> src_entropy_term) {
        meta.src_entropy_term = src_entropy_term;
    }

    action get_dst_entropy_term(bit<32> dst_entropy_term) {
        meta.dst_entropy_term = dst_entropy_term;
    }

    action get_pktlen_entropy_term(bit<32> pktlen_entropy_term) {
        meta.pktlen_entropy_term = pktlen_entropy_term;
    }

    action cs_hash(in bit<32> ipv4_addr, out bit<32> h1, out bit<32> h2, out bit<32> h3, out bit<32> h4) {
        hash(h1, HashAlgorithm.crc32, 32w0, {ipv4_addr}, 32w1280);
        hash(h2, HashAlgorithm.crc16, 32w0, {ipv4_addr}, 32w1280);
        hash(h3, HashAlgorithm.identity, 32w0, {ipv4_addr}, 32w1280);
        hash(h4, HashAlgorithm.xor16, 32w0, {ipv4_addr}, 32w1280);
    }

    action cs_ghash(in bit<32> ipv4_addr, out int<32> g1, out int<32> g2, out int<32> g3, out int<32> g4) {
        hash(g1, HashAlgorithm.crc32, 32w0, {ipv4_addr}, 32w2);
        hash(g2, HashAlgorithm.crc16, 32w0, {ipv4_addr}, 32w2);
        hash(g3, HashAlgorithm.identity, 32w0, {ipv4_addr}, 32w2);
        hash(g4, HashAlgorithm.xor16, 32w0, {ipv4_addr}, 32w2);

        // As ghash outputs 0 or 1, we must map 0 to -1.
        g1 = 2 * g1 - 1;
        g2 = 2 * g2 - 1;
        g3 = 2 * g3 - 1;
        g4 = 2 * g4 - 1;
    }

    action median(in int<32> x1, in int<32> x2, in int<32> x3, in int<32> x4, out int<32> y) {
        // This is why we should minimize the sketch depth: the median operator is hardcoded.
        if ((x1 <= x2 && x1 <= x3 && x1 <= x4 && x2 >= x3 && x2 >= x4) ||
            (x2 <= x1 && x2 <= x3 && x2 <= x4 && x1 >= x3 && x1 >= x4))
            y = (x3 + x4) >> 1;
        else if ((x1 <= x2 && x1 <= x3 && x1 <= x4 && x3 >= x2 && x3 >= x4) ||
                 (x3 <= x1 && x3 <= x2 && x3 <= x4 && x1 >= x2 && x1 >= x4))
            y = (x2 + x4) >> 1;
        else if ((x1 <= x2 && x1 <= x3 && x1 <= x4 && x4 >= x2 && x4 >= x3) ||
                 (x4 <= x1 && x4 <= x2 && x4 <= x3 && x1 >= x2 && x1 >= x3))
            y = (x2 + x3) >> 1;
        else if ((x2 <= x1 && x2 <= x3 && x2 <= x4 && x3 >= x1 && x3 >= x4) ||
                 (x3 <= x1 && x3 <= x2 && x3 <= x4 && x2 >= x1 && x2 >= x4))
            y = (x1 + x4) >> 1;
        else if ((x2 <= x1 && x2 <= x3 && x2 <= x4 && x4 >= x1 && x4 >= x3) ||
                 (x4 <= x1 && x4 <= x2 && x4 <= x3 && x2 >= x1 && x2 >= x3))
            y = (x1 + x3) >> 1;
        else
            y = (x1 + x2) >> 1;
    }
    action bmap_hash(in bit<32> ipv4_addr, out bit<32> bmap_index) {
        hash(bmap_index, HashAlgorithm.crc32, 32w0, {ipv4_addr}, 32w1280);
    }
    // 表部分
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr : lpm;
    }
    actions = {
        ipv4_forward;
    	drop;
    }
    size = 128;
    default_action = drop();
    }

    table ipv4_dpi_lpm {
        key = {
            hdr.ipv4.dstAddr : lpm;
	}
	actions = {
    	    ipv4_forward;
    	    drop;
	}
	size = 128;
	default_action = drop();
    }

	// The two tables below are supposed to be implemented as a single one,
	// but our target (i.e., the simple_switch) does not support two table lookups within the the same control flow.
    table src_entropy_term {
    	key = {
            meta.ip_count : lpm;
    	}
	actions = {
    	    get_src_entropy_term;
	}
	default_action = get_src_entropy_term(0);
	}

    table dst_entropy_term {
    	key = {
            meta.ip_count : lpm;
	}
	actions = {
    	    get_dst_entropy_term;
	}
	default_action = get_dst_entropy_term(0);
    }

    table pktlen_entropy_term {
    	key = {
            meta.pktlen_count : lpm;
	}
	actions = {
    	    get_pktlen_entropy_term;
	}
	default_action = get_pktlen_entropy_term(0);
    }

    table table_feature0 {
    	key = {
            meta.syn_flag : range @name("feature0");
	}
	actions = {
    	    SetCode0;
	    NoAction;
	}
	size = 64;
	default_action = NoAction;
    }

    table table_feature1 {
    	key = {
            meta.pkt_len : range @name("feature1");
	}
	actions = {
    	    SetCode1;
	    NoAction;
    	}	
	size = 64;
	default_action = NoAction;
    }

    table table_feature2 {
    	key = {
            meta.ack_flag : range @name("feature2");
	}
	actions = {
    	    SetCode2;
    	    NoAction;
	}
	size = 64;
	default_action = NoAction;
    }

    table table_feature3 {
    	key = {
            meta.hdr_srcport : range @name("feature3");
	}
	actions = {
    	    SetCode3;
    	    NoAction;
	}
	size = 256;
	default_action = NoAction;
    }

    table table_feature4 {
    	key = {
            meta.hdr_dstip : range @name("feature4");
	}
	actions = {
    	    SetCode4;
    	    NoAction;
	}
	size = 256;
	default_action = NoAction;
    }
/*
    table table_feature5 {
    	key = {
            meta.hdr_srcport : range @name("feature5");
	}
	actions = {
    	    SetCode5;
    	    NoAction;
	}
	size = 256;
	default_action = NoAction;
    }
    
    table table_feature6 {
    	key = {
            meta.rst_flag : range @name("feature6");
	}
	actions = {
    	    SetCode6;
    	    NoAction;
	}
	size = 64;
	default_action = NoAction;
    }
*/
    /* 代碼表 */
    table code_table0 {
    	key = {
            meta.codeword0 : ternary;
	}
	actions = {
    	    SetClass0;
            NoAction;
	}
	size = 256;
	default_action = NoAction;
    }

  table code_table1 {
      key = {
        meta.codeword1 : ternary;
      }
      actions = {
          SetClass1;
          NoAction;
      }
      size = 256;
      default_action = NoAction;
  }

  table voting_table {
      key = {
        meta.class0 : exact;
        meta.class1 : exact;
      }
      actions = { 
        set_final_class;
        NoAction;
      }
      size = 64;
      default_action = NoAction;
  }

  apply {

    if (hdr.ipv4.isValid()) {
        meta.pkt_len = standard_metadata.packet_length;

        // 從暫存器取得觀察視窗編號。
        bit<32> current_wid;
        ow_counter.read(current_wid, 0);

        // 從暫存器取得交換器狀態
        bit<8> dr_state_aux;
        // 從 register dr_state 第 0 格 讀值 → 放進 dr_state_aux。
        dr_state.read(dr_state_aux, 0);

        // Wlast 目的IP出現頻率
        int<32> f_dst_last;

        // --------------------------------------------------------------------------------------------------------

        //--------------------------------------------------------------------------------------------------------
        // 開始封包長度的頻率與熵範數估計。

        // 取得所有資料column的 row ID
        bit<32> pktlen_hash_1;
        bit<32> pktlen_hash_2;
        bit<32> pktlen_hash_3;
        bit<32> pktlen_hash_4;

        cs_hash(standard_metadata.packet_length, pktlen_hash_1, pktlen_hash_2, pktlen_hash_3, pktlen_hash_4);

        // 決定是否增加或減少計數器
        int<32> pktlen_ghash_1;
        int<32> pktlen_ghash_2;
        int<32> pktlen_ghash_3;
        int<32> pktlen_ghash_4;
        cs_ghash(standard_metadata.packet_length, pktlen_ghash_1, pktlen_ghash_2, pktlen_ghash_3, pktlen_ghash_4);

        // 估計封包長度的頻率

        // 計數器和注解的變數。
        // 用於頻率近似和熵估算:
        int<32> pktlen_curr_1;
        bit<8> pktlen_curr_1_wid;
        int<32> pktlen_curr_2;
        bit<8> pktlen_curr_2_wid;
        int<32> pktlen_curr_3;
        bit<8> pktlen_curr_3_wid;
        int<32> pktlen_curr_4;
        bit<8> pktlen_curr_4_wid;

        // 讀取計數器和注釋。
        cs_pktlen_curr_1.read(pktlen_curr_1, pktlen_hash_1);         // 讀取目前的計數器。
        cs_pktlen_curr_1_wid.read(pktlen_curr_1_wid, pktlen_hash_1); // 讀取目前的註解。
        cs_pktlen_curr_2.read(pktlen_curr_2, pktlen_hash_2);         // 讀取目前的計數器。
        cs_pktlen_curr_2_wid.read(pktlen_curr_2_wid, pktlen_hash_2); // 讀取目前的註解。
        cs_pktlen_curr_3.read(pktlen_curr_3, pktlen_hash_3);         // 讀取目前的計數器。
        cs_pktlen_curr_3_wid.read(pktlen_curr_3_wid, pktlen_hash_3); // 讀取目前的註解。
        cs_pktlen_curr_4.read(pktlen_curr_4, pktlen_hash_4);         // 讀取目前的計數器。
        cs_pktlen_curr_4_wid.read(pktlen_curr_4_wid, pktlen_hash_4); // 讀取目前的註解。

        // 因為資料平面不具有一口氣重置的方法
        if (pktlen_curr_1_wid != current_wid [7:0]) {
            pktlen_curr_1 = 0;
            cs_pktlen_curr_1_wid.write(pktlen_hash_1, current_wid [7:0]);
        }

        if (pktlen_curr_2_wid != current_wid [7:0]) {
            pktlen_curr_2 = 0;
            cs_pktlen_curr_2_wid.write(pktlen_hash_2, current_wid [7:0]);
        }

        if (pktlen_curr_3_wid != current_wid [7:0]) {
            pktlen_curr_3 = 0;
            cs_pktlen_curr_3_wid.write(pktlen_hash_3, current_wid [7:0]);
        }

        if (pktlen_curr_4_wid != current_wid [7:0]) {
            pktlen_curr_4 = 0;
            cs_pktlen_curr_4_wid.write(pktlen_hash_4, current_wid [7:0]);
        }

        // 更新計數器。
        pktlen_curr_1 = pktlen_curr_1 + pktlen_ghash_1; // Update the counter.
        pktlen_curr_2 = pktlen_curr_2 + pktlen_ghash_2; // Update the counter.
        pktlen_curr_3 = pktlen_curr_3 + pktlen_ghash_3; // Update the counter.
        pktlen_curr_4 = pktlen_curr_4 + pktlen_ghash_4; // Update the counter.

        // 將計數器寫回草圖。
        cs_pktlen_curr_1.write(pktlen_hash_1, pktlen_curr_1); // Write the counter.
        cs_pktlen_curr_2.write(pktlen_hash_2, pktlen_curr_2); // Write the counter.
        cs_pktlen_curr_3.write(pktlen_hash_3, pktlen_curr_3); // Write the counter.
        cs_pktlen_curr_4.write(pktlen_hash_4, pktlen_curr_4); // Write the counter.

        // ghash 與計數器的符號相同；這會計算絕對值。
        pktlen_curr_1 = pktlen_curr_1 * pktlen_ghash_1;
        pktlen_curr_2 = pktlen_curr_2 * pktlen_ghash_2;
        pktlen_curr_3 = pktlen_curr_3 * pktlen_ghash_3;
        pktlen_curr_4 = pktlen_curr_4 * pktlen_ghash_4;

        // 此時，我們已更新 pktlen_curr_1、pktlen_curr_2、pktlen_curr_3 和 pktlen_curr_4 中的計數器。

        // 計數 Sketch 封包長度 頻率估計：將其儲存在 meta.pktlen_count。
        median(pktlen_curr_1, pktlen_curr_2, pktlen_curr_3, pktlen_curr_4, meta.pktlen_count);

        // LPM 查表。 副作用：更新 meta.entropy_term。
        if (meta.pktlen_count > 0) // 這可以避免在參數為零時執行查詢。
            pktlen_entropy_term.apply();
        else
            meta.pktlen_entropy_term = 0;
        // At this point, meta.entropy_term has the 'increment'.

        // PktLen Entropy Norm Update
        bit<32> pktlen_S_aux;
        
        pktlen_S.read(pktlen_S_aux, 0);
        
        pktlen_S_aux = pktlen_S_aux + meta.pktlen_entropy_term;
        
        pktlen_S.write(0, pktlen_S_aux);

        // 封包長度頻率 & 熵範數估算結束

        // --------------------------------------------------------------------------------------------------------

        // --------------------------------------------------------------------------------------------------------
        // 開始來源IP頻率與熵範數估計。

        // 取得所有資料column的 row ID
        bit<32> src_hash_1;
        bit<32> src_hash_2;
        bit<32> src_hash_3;
        bit<32> src_hash_4;
        cs_hash(hdr.ipv4.srcAddr, src_hash_1, src_hash_2, src_hash_3, src_hash_4);

        // 決定是否增加或減少計數器
        int<32> src_ghash_1;
        int<32> src_ghash_2;
        int<32> src_ghash_3;
        int<32> src_ghash_4;
        cs_ghash(hdr.ipv4.srcAddr, src_ghash_1, src_ghash_2, src_ghash_3, src_ghash_4);

        // 估計來源IP的頻率

        // 計數器和注解的變數。
        // 用於頻率近似和熵估算:
        int<32> src_curr_1;
        bit<8> src_curr_1_wid;
        int<32> src_curr_2;
        bit<8> src_curr_2_wid;
        int<32> src_curr_3;
        bit<8> src_curr_3_wid;
        int<32> src_curr_4;
        bit<8> src_curr_4_wid;

        // 讀取計數器和注釋。
        cs_src_curr_1.read(src_curr_1, src_hash_1);         // 讀取目前的計數器。
        cs_src_curr_1_wid.read(src_curr_1_wid, src_hash_1); // 讀取cs_src_curr_1_wid，索引是src_hash_1，賦值給src_curr_1_wid
        cs_src_curr_2.read(src_curr_2, src_hash_2);         // 讀取目前的計數器。
        cs_src_curr_2_wid.read(src_curr_2_wid, src_hash_2); // 讀取目前的註解。
        cs_src_curr_3.read(src_curr_3, src_hash_3);         // 讀取目前的計數器。
        cs_src_curr_3_wid.read(src_curr_3_wid, src_hash_3); // 讀取目前的註解。
        cs_src_curr_4.read(src_curr_4, src_hash_4);         // 讀取目前的計數器。
        cs_src_curr_4_wid.read(src_curr_4_wid, src_hash_4); // 讀取目前的註解。

        // 因為資料平面不具有一口氣重置的方法
        if (src_curr_1_wid != current_wid [7:0]) {
            src_curr_1 = 0;
            cs_src_curr_1_wid.write(src_hash_1, current_wid [7:0]);
        }

        if (src_curr_2_wid != current_wid [7:0]) {
            src_curr_2 = 0;
            cs_src_curr_2_wid.write(src_hash_2, current_wid [7:0]);
        }

        if (src_curr_3_wid != current_wid [7:0]) {
            src_curr_3 = 0;
            cs_src_curr_3_wid.write(src_hash_3, current_wid [7:0]);
        }

        if (src_curr_4_wid != current_wid [7:0]) {
            src_curr_4 = 0;
            cs_src_curr_4_wid.write(src_hash_4, current_wid [7:0]);
        }

        // 更新計數器。
        src_curr_1 = src_curr_1 + src_ghash_1; // Update the counter.
        src_curr_2 = src_curr_2 + src_ghash_2; // Update the counter.
        src_curr_3 = src_curr_3 + src_ghash_3; // Update the counter.
        src_curr_4 = src_curr_4 + src_ghash_4; // Update the counter.

        // 將計數器寫回草圖。
        cs_src_curr_1.write(src_hash_1, src_curr_1); // Write the counter.
        cs_src_curr_2.write(src_hash_2, src_curr_2); // Write the counter.
        cs_src_curr_3.write(src_hash_3, src_curr_3); // Write the counter.
        cs_src_curr_4.write(src_hash_4, src_curr_4); // Write the counter.

        // ghash 與計數器的符號相同；這會計算絕對值。
        src_curr_1 = src_curr_1 * src_ghash_1;
        src_curr_2 = src_curr_2 * src_ghash_2;
        src_curr_3 = src_curr_3 * src_ghash_3;
        src_curr_4 = src_curr_4 * src_ghash_4;

        // 此時，我們已更新 src_curr_1、src_curr_2、src_curr_3 和 src_curr_4 中的計數器。

        // Count Sketch Source IP Frequency Estimate: store it in meta.ip_count.
        median(src_curr_1, src_curr_2, src_curr_3, src_curr_4, meta.ip_count);

        // LPM table lookup. Side effect: meta.entropy_term is updated.
        if (meta.ip_count > 0) // 這可以避免在參數為零時執行查詢。
            src_entropy_term.apply();
        else
            meta.src_entropy_term = 0;
        // At this point, meta.entropy_term has the 'increment'.

        // Source Entropy Norm Update
        bit<32> src_S_aux;
        src_S.read(src_S_aux, 0);
        src_S_aux = src_S_aux + meta.src_entropy_term;
        src_S.write(0, src_S_aux);

        // 來源IP頻率與熵範數估算結束
        // --------------------------------------------------------------------------------------------------------

        // --------------------------------------------------------------------------------------------------------

        // 開始目的IP頻率與熵範數估計。

        // Obtain column IDs for all rows
        bit<32> dst_hash_1;
        bit<32> dst_hash_2;
        bit<32> dst_hash_3;
        bit<32> dst_hash_4;
        cs_hash(hdr.ipv4.dstAddr, dst_hash_1, dst_hash_2, dst_hash_3, dst_hash_4);

        // 決定是否增加或減少計數器
        int<32> dst_ghash_1;
        int<32> dst_ghash_2;
        int<32> dst_ghash_3;
        int<32> dst_ghash_4;
        cs_ghash(hdr.ipv4.dstAddr, dst_ghash_1, dst_ghash_2, dst_ghash_3, dst_ghash_4);

        // 估計目的IP的頻率

        // 計數器和注解的變數。
        // 用於頻率近似和熵估算：
        int<32> dst_curr_1;
        bit<8> dst_curr_1_wid;
        int<32> dst_curr_2;
        bit<8> dst_curr_2_wid;
        int<32> dst_curr_3;
        bit<8> dst_curr_3_wid;
        int<32> dst_curr_4;
        bit<8> dst_curr_4_wid;
        // 用於頻率變化分析：
        int<32> dst_last_1;
        int<32> dst_last_2;
        int<32> dst_last_3;
        int<32> dst_last_4;

        // Read counters and annotations.
        cs_dst_curr_1.read(dst_curr_1, dst_hash_1);         // 讀取目前的計數器。
        cs_dst_curr_1_wid.read(dst_curr_1_wid, dst_hash_1); // 讀取目前的註解。
        cs_dst_curr_2.read(dst_curr_2, dst_hash_2);         // 讀取目前的計數器。
        cs_dst_curr_2_wid.read(dst_curr_2_wid, dst_hash_2); // 讀取目前的註解。
        cs_dst_curr_3.read(dst_curr_3, dst_hash_3);         // 讀取目前的計數器。
        cs_dst_curr_3_wid.read(dst_curr_3_wid, dst_hash_3); // 讀取目前的註解。
        cs_dst_curr_4.read(dst_curr_4, dst_hash_4);         // 讀取目前的計數器。
        cs_dst_curr_4_wid.read(dst_curr_4_wid, dst_hash_4); // 讀取目前的註解。
        cs_dst_last_1.read(dst_last_1, dst_hash_1);         // 讀取 Wlast 計數器。
        cs_dst_last_2.read(dst_last_2, dst_hash_2);         // 讀取 Wlast 計數器。
        cs_dst_last_3.read(dst_last_3, dst_hash_3);         // 讀取 Wlast 計數器。
        cs_dst_last_4.read(dst_last_4, dst_hash_4);         // 讀取 Wlast 計數器。

        // 因為資料平面不具有一口氣重置的方法
        if (dst_curr_1_wid != current_wid [7:0]) {
            dst_last_1 = dst_curr_1;                     // Copy Wcurr counter to Wlast.
            cs_dst_last_1.write(dst_hash_1, dst_last_1); // Write back.
            dst_curr_1 = 0;
            cs_dst_curr_1_wid.write(dst_hash_1, current_wid [7:0]);
        }

        if (dst_curr_2_wid != current_wid [7:0]) {
            dst_last_2 = dst_curr_2;                     // Copy Wcurr counter to Wlast.
            cs_dst_last_2.write(dst_hash_2, dst_last_2); // Write back.
            dst_curr_2 = 0;
            cs_dst_curr_2_wid.write(dst_hash_2, current_wid [7:0]);
        }

        if (dst_curr_3_wid != current_wid [7:0]) {
            dst_last_3 = dst_curr_3;                     // Copy Wcurr counter to Wlast.
            cs_dst_last_3.write(dst_hash_3, dst_last_3); // Write back.
            dst_curr_3 = 0;
            cs_dst_curr_3_wid.write(dst_hash_3, current_wid [7:0]);
        }

        if (dst_curr_4_wid != current_wid [7:0]) {
            dst_last_4 = dst_curr_4;                     // Copy Wcurr counter to Wlast.
            cs_dst_last_4.write(dst_hash_4, dst_last_4); // Write back.
            dst_curr_4 = 0;
            cs_dst_curr_4_wid.write(dst_hash_4, current_wid [7:0]);
        }

        // 更新計數器。
        dst_curr_1 = dst_curr_1 + dst_ghash_1; // Update the counter.
        dst_curr_2 = dst_curr_2 + dst_ghash_2; // Update the counter.
        dst_curr_3 = dst_curr_3 + dst_ghash_3; // Update the counter.
        dst_curr_4 = dst_curr_4 + dst_ghash_4; // Update the counter.

        // 將計數器寫回Sketch。
        cs_dst_curr_1.write(dst_hash_1, dst_curr_1); // Write the counter.
        cs_dst_curr_2.write(dst_hash_2, dst_curr_2); // Write the counter.
        cs_dst_curr_3.write(dst_hash_3, dst_curr_3); // Write the counter.
        cs_dst_curr_4.write(dst_hash_4, dst_curr_4); // Write the counter.

        // ghash and the counter have the same sign; this computes the absolute value.
        dst_curr_1 = dst_curr_1 * dst_ghash_1;
        dst_curr_2 = dst_curr_2 * dst_ghash_2;
        dst_curr_3 = dst_curr_3 * dst_ghash_3;
        dst_curr_4 = dst_curr_4 * dst_ghash_4;

        // 此時，我們已更新 dst_curr_1、dst_curr_2、dst_curr_3 和 dst_curr_4 中的計數器。

        // Count Sketch Destination IP Frequency Estimate
        median(dst_curr_1, dst_curr_2, dst_curr_3, dst_curr_4, meta.ip_count);

        // LPM table lookup. Side effect: meta.entropy_term is updated.
        dst_entropy_term.apply();
        // At this point, meta.entropy_term has the 'increment'.

        // Destination Entropy Norm Update
        bit<32> dst_S_aux;
        
        dst_S.read(dst_S_aux, 0);
        
        dst_S_aux = dst_S_aux + meta.dst_entropy_term;
        
        dst_S.write(0, dst_S_aux);

        // 此時，我們已經有來源和目的IP & 封包長度的熵範數 (src_S、dst_S、pktlen_S)。

        // 目的IP頻率與熵範數估算結束
        // --------------------------------------------------------------------------------------------------------
        
        // --------------------------------------------------------------------------------------------------------
        // 計算Bitmap, 估計不同目的IP的數量
        bit<32> dst_hash_0;
        bmap_hash(hdr.ipv4.dstAddr, dst_hash_0);

        bit<1> dst_curr_0;
        bit<8> dst_curr_0_wid;
        bit<32> dst_uniq_count_aux;
        dst_uniq_count.read(dst_uniq_count_aux, 0);

        bmap_dst_curr.read(dst_curr_0, dst_hash_0);           // 讀取目前的計數器
        bmap_dst_curr_wid.read(dst_curr_0_wid, dst_hash_0);   // 讀取目前的註解

        // 資料平面不能一口氣重置
        if (dst_curr_0_wid != current_wid [7:0]) {
            dst_curr_0 = 0; 
            bmap_dst_curr_wid.write(dst_hash_0, current_wid [7:0]);
        }
        // IP在此OW中第一次出現
        if (dst_curr_0 == 0) {
            bmap_dst_curr.write(dst_hash_0, 1); // 把此IP設為已出現
            dst_uniq_count_aux = dst_uniq_count_aux + 1;
            dst_uniq_count.write(0, dst_uniq_count_aux);
        }
	//--------------------------------------------------------------------------------------------------------
        // 開始異常偵測。
        // Step 1: 檢查觀察視窗是否已結束。
        // Step 2: If the OW has ended, estimate the entropies.
        // Step 3: If we detect an entropy anomaly, signal this condition. Otherwise, just update the moving averages.

        // Step 1: 檢查觀察視窗是否已結束。

        bit<32> m; // 觀察視窗的尺寸
        bit<5> log2_m_aux;
        
        log2_m.read(log2_m_aux, 0);
        
        m = 32w1 << log2_m_aux;            // m = 2^log2(m)
        
        pkt_counter.read(meta.pkt_num, 0); // Packet Counter
        
        meta.pkt_num = meta.pkt_num + 1;

        if (meta.pkt_num != m) { // Observation Window has not ended yet; just update the counter.
            pkt_counter.write(0, meta.pkt_num);
        }
        else { // End of Observation Window. Begin OW Summarization.
            current_wid = current_wid + 1;
            
            ow_counter.write(0, current_wid); // Save the number of the new OW in its register.

            // Step 2: 估計熵值。

            // 我們需要計算 Ĥ = log2(m) - Ŝ/m .
            // 由於我們的流水線沒有實作除法，因此對於正的 m，我們可以使用 1/m = 2^(-log2(m)) 的特性。
            // 由於 m 是 2 的整數次幂次方，而且我們已經知道 log2(m)，因此除法變成 log2(m) 位元的右移。
            // 因此 Ĥ = log2(m) - Ŝ/m  =  log2(m) - Ŝ * 2^(-log2(m)).

            meta.pktlen_entropy = ((bit<32>)log2_m_aux << 4) - (pktlen_S_aux >> log2_m_aux);
            
            meta.src_entropy = ((bit<32>)log2_m_aux << 4) - (src_S_aux >> log2_m_aux);
            
            meta.dst_entropy = ((bit<32>)log2_m_aux << 4) - (dst_S_aux >> log2_m_aux);
/*            
            //除蟲
            src_entropy.write(0, meta.src_entropy);
            
	    dst_entropy.write(0, meta.dst_entropy);
	    
	    pktlen_entropy.write(0, meta.pktlen_entropy);
*/
            // 讀取EWMA & EWMMD。
            src_ewma.read(meta.src_ewma, 0);
            
            src_ewmmd.read(meta.src_ewmmd, 0);
            
            dst_ewma.read(meta.dst_ewma, 0);
            
            dst_ewmmd.read(meta.dst_ewmmd, 0);
            
	    pktlen_ewma.read(meta.pktlen_ewma, 0);
	    
            pktlen_ewmmd.read(meta.pktlen_ewmmd, 0);

            // 在第一個視窗中...
            if (current_wid == 1) {                                           
                meta.src_ewma = meta.src_entropy << 14; // 使用第一次估計的熵初始化平均值。 平均值有 18 個小數位元。
                
                meta.src_ewmmd = 0;
                
               	meta.dst_ewma = meta.dst_entropy << 14;
               	
               	meta.dst_ewmmd = 0;
               	
		meta.pktlen_ewma = meta.pktlen_entropy << 14; // 使用第一次估計的熵初始化平均值。 平均值有 18 個小數位元。
		
                meta.pktlen_ewmmd = 0;
            }
            else {                   
                meta.alarm = 0; // 預設情況下，沒有警報。

                // 步驟 3：如果我們偵測到異常，就將此狀況訊號化。 否則，只需更新閾值。

                bit<32> training_len_aux;
                
                training_len.read(training_len_aux, 0);
                
                if (current_wid > training_len_aux) { // 如果我們已經完成訓練，我們會檢查是否有異常。
                    bit<8> k_aux;
                    
                    k.read(k_aux, 0);

                    bit<32> pktlen_thresh;
                    
                    pktlen_thresh = meta.pktlen_ewma - ((bit<32>)k_aux * meta.pktlen_ewmmd >> 3);

                    bit<32> src_thresh;
                    
                    src_thresh = meta.src_ewma + ((bit<32>)k_aux * meta.src_ewmmd >> 3); // k has 3 fractional bits.

                    bit<32> dst_thresh;
                    
                    dst_thresh = meta.dst_ewma - ((bit<32>)k_aux * meta.dst_ewmmd >> 3);
/*
                    //除蟲
                    src_thresh_log.write(0, src_thresh);

                    dst_thresh_log.write(0, dst_thresh);

                    pktlen_thresh_log.write(0, pktlen_thresh);
*/

		    //異常偵測區塊
                    if (((meta.pktlen_entropy << 14) < pktlen_thresh && (meta.dst_entropy << 14) < dst_thresh) || ((meta.pktlen_entropy << 14) < pktlen_thresh && (meta.src_entropy << 14) > src_thresh)){
                          meta.alarm = 1;
                          dr_state_aux = DR_ACTIVE;        // Enables mitigation.
                          dr_state.write(0, dr_state_aux); // Write back.
                          meta.dr_state = dr_state_aux;    // Write into the head.
                    }
                }

                if (meta.alarm == 0) { // No attack detected; let's update EWMA and EWMMD.
                    bit<8> alpha_aux;
                    alpha.read(alpha_aux, 0);

                    // Fixed-point alignments:
                    // Alpha： 8 個小數位元；Entropy： 4 小數位元。 EWMA 和 EWMMD：18 小數位元。
                    // Alpha*Entropy: 8 + 4 = 12 位元；左移 6 位元得到 18 位元。
                    // Alpha*EWMx：8 + 18 = 26 位元；右移 8 位元，得到 18 位元。

                    meta.pktlen_ewma = (((bit<32>)alpha_aux * meta.pktlen_entropy) << 6) + (((0x00000100 - (bit<32>)alpha_aux) * meta.pktlen_ewma) >> 8);
                    meta.src_ewma = (((bit<32>)alpha_aux * meta.src_entropy) << 6) + (((0x00000100 - (bit<32>)alpha_aux) * meta.src_ewma) >> 8);
                    meta.dst_ewma = (((bit<32>)alpha_aux * meta.dst_entropy) << 6) + (((0x00000100 - (bit<32>)alpha_aux) * meta.dst_ewma) >> 8);

                    // 要取絕對值
                    if ((meta.pktlen_entropy << 14) >= meta.pktlen_ewma)
                        meta.pktlen_ewmmd = (((bit<32>)alpha_aux * ((meta.pktlen_entropy << 14) - meta.pktlen_ewma)) >> 8) + (((0x00000100 - (bit<32>)alpha_aux) * meta.pktlen_ewmmd) >> 8);
                    else
                        meta.pktlen_ewmmd = (((bit<32>)alpha_aux * (meta.pktlen_ewma - (meta.pktlen_entropy << 14))) >> 8) + (((0x00000100 - (bit<32>)alpha_aux) * meta.pktlen_ewmmd) >> 8);

                    if ((meta.src_entropy << 14) >= meta.src_ewma)
                        meta.src_ewmmd = (((bit<32>)alpha_aux * ((meta.src_entropy << 14) - meta.src_ewma)) >> 8) + (((0x00000100 - (bit<32>)alpha_aux) * meta.src_ewmmd) >> 8);
                    else
                        meta.src_ewmmd = (((bit<32>)alpha_aux * (meta.src_ewma - (meta.src_entropy << 14))) >> 8) + (((0x00000100 - (bit<32>)alpha_aux) * meta.src_ewmmd) >> 8);

                    if ((meta.dst_entropy << 14) >= meta.dst_ewma)
                        meta.dst_ewmmd = (((bit<32>)alpha_aux * ((meta.dst_entropy << 14) - meta.dst_ewma)) >> 8) + (((0x00000100 - (bit<32>)alpha_aux) * meta.dst_ewmmd) >> 8);
                    else
                        meta.dst_ewmmd = (((bit<32>)alpha_aux * (meta.dst_ewma - (meta.dst_entropy << 14))) >> 8) + (((0x00000100 - (bit<32>)alpha_aux) * meta.dst_ewmmd) >> 8);

                }

                // End of Step 3 (Anomaly Detection).
            }

            // End of Step 2 (Entropy Estimation).

            // Preparation for the next OW:

            // 寫回 EWMA 和 EWMMD 的值。
            pktlen_ewma.write(0, meta.pktlen_ewma);
            pktlen_ewmmd.write(0, meta.pktlen_ewmmd);
            src_ewma.write(0, meta.src_ewma);
            src_ewmmd.write(0, meta.src_ewmmd);
            dst_ewma.write(0, meta.dst_ewma);
            dst_ewmmd.write(0, meta.dst_ewmmd);

	    //count值要reset，而dst_uniq_compare留到後面進行比較
            dst_uniq_compare.write(0, dst_uniq_count_aux);
            dst_uniq_count.write(0, 0);

            // 重設封包計數器 & 熵值。
            pkt_counter.write(0, 0);
            pktlen_S.write(0, 0);
            src_S.write(0, 0);
            dst_S.write(0, 0);
	     

            // 檢查我們是否應該重設 Defense Readiness。
            if (dr_state_aux == DR_ACTIVE && meta.alarm == 0)
            {
                dr_state_aux = DR_COOLDOWN;
                dr_state.write(0, dr_state_aux); // Write back.
            }
	    else if (dr_state_aux == DR_COOLDOWN && meta.alarm == 0) {
		dr_state_aux = DR_SAFE;
		dr_state.write(0, dr_state_aux);
	    }
	    else if (dr_state_aux == DR_COOLDOWN && meta.alarm == 1) {
		dr_state_aux = DR_ACTIVE;
                dr_state.write(0, dr_state_aux);
	    }

            // 每個觀察視窗結束時，產生訊號封包。
            clone_preserving_field_list(CloneType.I2E, ALARM_SESSION, 1);

        } // End OW summarization.

        // End of Step 1 (OW Summarization)
        // --------------------------------------------------------------------------------------------------------

        // --------------------------------------------------------------------------------------------------------
        // Beginning of Defense-Readiness Processing.

        meta.classification = LEGITIMATE; // 預設情況下，將所有封包分類為合法。
	
        // 檢查是否為防禦狀態，若是防禦狀態則取得不同目的IP出現的數量
        if (dr_state_aux == DR_ACTIVE || dr_state_aux == DR_COOLDOWN) {
            // 在 Wlast 取得目的IP的估計計數器。
            dst_last_1 = dst_last_1 * dst_ghash_1;
            dst_last_2 = dst_last_2 * dst_ghash_2;
            dst_last_3 = dst_last_3 * dst_ghash_3;
            dst_last_4 = dst_last_4 * dst_ghash_4;
            median(dst_last_1, dst_last_2, dst_last_3, dst_last_4, f_dst_last);
		
	    bit<32> dst_uniq_compare_aux;
	    dst_uniq_compare.read(dst_uniq_compare_aux, 0);

            //if ((bit<32>)f_dst_last * dst_uniq_compare_aux >= m) {
                 // apply feature tables to assign codes
                 table_feature0.apply();
                 table_feature1.apply();
                 table_feature2.apply();
                 table_feature3.apply();
                 table_feature4.apply();

                 // apply code tables to assign labels
                 code_table0.apply();
                 code_table1.apply();

                 // decide final class
                 voting_table.apply();
            //}
        }

        // Divert is set to one for packets that must undergo further inspection.
        if (meta.classification == LEGITIMATE) {
            ipv4_lpm.apply(); // 使用一般的轉送表。
        }
        else{
            ipv4_dpi_lpm.apply(); // 使用替代轉送表。
        }

        // End of Policy Enforcement.
        // --------------------------------------------------------------------------------------------------------
	
    } // End of IPv4 header processing.
  } // End of ingress pipeline control block.
} // End of ingress pipeline definition.
/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    apply {
        if(standard_metadata.ingress_global_timestamp != 0){
	    if(standard_metadata.egress_global_timestamp != 0){
		bit<48>t0 = standard_metadata.egress_global_timestamp - standard_metadata.ingress_global_timestamp;
		hdr.lat.setValid();
		hdr.lat.proc_us = t0;
	    }
	}
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta)
{
    apply
    {
        update_checksum(
            hdr.ipv4.isValid(),
            {hdr.ipv4.version,
             hdr.ipv4.ihl,
             hdr.ipv4.diffserv,
             hdr.ipv4.totalLen,
             hdr.ipv4.identification,
             hdr.ipv4.flags,
             hdr.ipv4.fragOffset,
             hdr.ipv4.ttl,
             hdr.ipv4.protocol,
             hdr.ipv4.srcAddr,
             hdr.ipv4.dstAddr},
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr)
{
    apply
    {
        packet.emit(hdr);
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
    MyDeparser()) main;
