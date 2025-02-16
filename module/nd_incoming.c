
// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		DATACENTER ADMISSION CONTROL PROTOCOL(ND) 
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Arnt Gulbrandsen, <agulbra@nvg.unit.no>
 *		Alan Cox, <alan@lxorguk.ukuu.org.uk>
 *		Hirokazu Takahashi, <taka@valinux.co.jp>
 */

#define pr_fmt(fmt) "ND: " fmt

#include <linux/uaccess.h>
#include <asm/ioctls.h>
#include <linux/memblock.h>
#include <linux/highmem.h>
#include <linux/swap.h>
#include <linux/types.h>
#include <linux/fcntl.h>
#include <linux/module.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/igmp.h>
#include <linux/inetdevice.h>
#include <linux/in.h>
#include <linux/errno.h>
#include <linux/timer.h>
#include <linux/mm.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/slab.h>
#include <net/tcp_states.h>
#include <linux/skbuff.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <net/net_namespace.h>
#include <net/icmp.h>
#include <net/inet_hashtables.h>
#include <net/ip_tunnels.h>
#include <net/route.h>
#include <net/tcp.h>
#include <net/checksum.h>
#include <net/xfrm.h>
#include <trace/events/udp.h>
#include <linux/static_key.h>
#include <trace/events/skb.h>
#include <net/busy_poll.h>
#include "nd_impl.h"
#include <net/sock_reuseport.h>
#include <net/addrconf.h>
#include <net/udp_tunnel.h>

// #include "linux_nd.h"
 #include "net_nd.h"
// #include "net_ndlite.h"
#include "uapi_linux_nd.h"
#include "nd_impl.h"
#include "nd_host.h"
// #include "nd_hashtables.h"

// static inline struct sock *__nd4_lib_lookup_skb(struct sk_buff *skb,
// 						 __be16 sport, __be16 dport,
// 						 struct udp_table *ndtable)
// {
// 	const struct iphdr *iph = ip_hdr(skb);

// 	return __nd4_lib_lookup(dev_net(skb->dev), iph->saddr, sport,
// 				 iph->daddr, dport, inet_iif(skb),
// 				 inet_sdif(skb), ndtable, skb);
// }


static void nd_rfree(struct sk_buff *skb)//用于回收skb
{
	struct sock *sk = skb->sk;
	// struct kcm_sock *kcm = kcm_sk(sk);
	// struct kcm_mux *mux = kcm->mux;
	unsigned int len = skb->truesize;

	/* recycle to the page pool */
	nd_page_pool_recycle_pages(skb);
	// sk_mem_uncharge(sk, len);
	atomic_sub(len, &sk->sk_rmem_alloc);

	/* For reading rx_wait and rx_psock without holding lock */
	// smp_mb__after_atomic();
//
	// if (!kcm->rx_wait && !kcm->rx_psock &&
	//     sk_rmem_alloc_get(sk) < sk->sk_rcvlowat) {
	// 	spin_lock_bh(&mux->rx_lock);
	// 	kcm_rcv_ready(kcm);
	// 	spin_unlock_bh(&mux->rx_lock);
	// }
}


static inline bool nd_sack_extend(struct nd_sack_block *sp, u32 seq,
				  u32 end_seq)
{
	if (!after(seq, sp->end_seq) && !after(sp->start_seq, end_seq)) {
		if (before(seq, sp->start_seq))
			sp->start_seq = seq;
		if (after(end_seq, sp->end_seq))
			sp->end_seq = end_seq;
		return true;
	}
	return false;
}

/* Remove acknowledged frames from the retransmission queue. If our packet
 * is before the ack sequence we can discard it as it's confirmed to have
 * arrived at the other end.
 */
int nd_clean_rtx_queue(struct sock *sk)
{
	// const struct inet_connection_sock *icsk = inet_csk(sk);
	struct nd_sock *dsk = nd_sk(sk);
	// u64 first_ackt, last_ackt;
	// u32 prior_sacked = tp->sacked_out;
	// u32 reord = tp->snd_nxt;  lowest acked un-retx un-sacked seq 
	struct sk_buff *skb, *next;
	bool fully_acked = true;
	// long sack_rtt_us = -1L;
	// long seq_rtt_us = -1L;
	// long ca_rtt_us = -1L;
	// u32 pkts_acked = 0;
	// u32 last_in_flight = 0;
	// bool rtt_update;
	int flag = 0;

	// first_ackt = 0;

	for (skb = skb_rb_first(&sk->tcp_rtx_queue); skb; skb = next) {
		struct nd_skb_cb *scb = ND_SKB_CB(skb);
		// const u32 start_seq = scb->seq;
		// u8 sacked = scb->sacked;
		// u32 acked_pcount;

		// tcp_ack_tstamp(sk, skb, prior_snd_una);

		/* Determine how many packets and what bytes were acked, tso and else */
		if (after(scb->end_seq, dsk->sender.snd_una)) {
			// if (tcp_skb_pcount(skb) == 1 ||
			//     !after(tp->snd_una, scb->seq))
			// 	break;

			// acked_pcount = tcp_tso_acked(sk, skb);
			// if (!acked_pcount)
			// 	break;
			fully_acked = false;
		} else {
			// acked_pcount = tcp_skb_pcount(skb);
		}

		// if (unlikely(sacked & TCPCB_RETRANS)) {
		// 	if (sacked & TCPCB_SACKED_RETRANS)
		// 		tp->retrans_out -= acked_pcount;
		// 	flag |= FLAG_RETRANS_DATA_ACKED;
		// } else if (!(sacked & TCPCB_SACKED_ACKED)) {
		// 	last_ackt = tcp_skb_timestamp_us(skb);
		// 	WARN_ON_ONCE(last_ackt == 0);
		// 	if (!first_ackt)
		// 		first_ackt = last_ackt;
//
		// 	last_in_flight = TCP_SKB_CB(skb)->tx.in_flight;
		// 	if (before(start_seq, reord))
		// 		reord = start_seq;
		// 	if (!after(scb->end_seq, tp->high_seq))
		// 		flag |= FLAG_ORIG_SACK_ACKED;
		// }
//
		// if (sacked & TCPCB_SACKED_ACKED) {
		// 	tp->sacked_out -= acked_pcount;
		// } else if (tcp_is_sack(tp)) {
		// 	tp->delivered += acked_pcount;
		// 	if (!tcp_skb_spurious_retrans(tp, skb))
		// 		tcp_rack_advance(tp, sacked, scb->end_seq,
		// 				 tcp_skb_timestamp_us(skb));
		// }
		// if (sacked & TCPCB_LOST)
		// 	tp->lost_out -= acked_pcount;
//
		// tp->packets_out -= acked_pcount;
		// pkts_acked += acked_pcount;
		// tcp_rate_skb_delivered(sk, skb, sack->rate);
//
		/* Initial outgoing SYN's get put onto the write_queue
		 * just like anything else we transmit.  It is not
		 * true data, and if we misinform our callers that
		 * this ACK acks real data, we will erroneously exit
		 * connection startup slow start one packet too
		 * quickly.  This is severely frowned upon behavior.
		 */
		// if (likely(!(scb->tcp_flags & TCPHDR_SYN))) {
		// 	flag |= FLAG_DATA_ACKED;
		// } else {
		// 	flag |= FLAG_SYN_ACKED;
		// 	tp->retrans_stamp = 0;
		// }

		if (!fully_acked)
			break;

		next = skb_rb_next(skb);
		// if (unlikely(skb == tp->retransmit_skb_hint))
		// 	tp->retransmit_skb_hint = NULL;
		// if (unlikely(skb == tp->lost_skb_hint))
		// 	tp->lost_skb_hint = NULL;
		// tcp_highest_sack_replace(sk, skb, next);
		nd_rtx_queue_unlink_and_free(skb, sk);
		// sk_stream_write_space(sk);
	}
	// if (!skb)
	// 	tcp_chrono_stop(sk, TCP_CHRONO_BUSY);
	//
	// if (likely(between(tp->snd_up, prior_snd_una, tp->snd_una)))
	// 	tp->snd_up = tp->snd_una;
//
	// if (skb && (TCP_SKB_CB(skb)->sacked & TCPCB_SACKED_ACKED))
	// 	flag |= FLAG_SACK_RENEGING;
//
	// if (likely(first_ackt) && !(flag & FLAG_RETRANS_DATA_ACKED)) {
	// 	seq_rtt_us = tcp_stamp_us_delta(tp->tcp_mstamp, first_ackt);
	// 	ca_rtt_us = tcp_stamp_us_delta(tp->tcp_mstamp, last_ackt);
//
	// 	if (pkts_acked == 1 && last_in_flight < tp->mss_cache &&
	// 	    last_in_flight && !prior_sacked && fully_acked &&
	// 	    sack->rate->prior_delivered + 1 == tp->delivered &&
	// 	    !(flag & (FLAG_CA_ALERT | FLAG_SYN_ACKED))) {
	// 		/* Conservatively mark a delayed ACK. It's typically
	// 		 * from a lone runt packet over the round trip to
	// 		 * a receiver w/o out-of-order or CE events.
	// 		 */
	// 		flag |= FLAG_ACK_MAYBE_DELAYED;
	// 	}
	// }
	// if (sack->first_sackt) {
	// 	sack_rtt_us = tcp_stamp_us_delta(tp->tcp_mstamp, sack->first_sackt);
	// 	ca_rtt_us = tcp_stamp_us_delta(tp->tcp_mstamp, sack->last_sackt);
	// }
	// rtt_update = tcp_ack_update_rtt(sk, flag, seq_rtt_us, sack_rtt_us,
	// 				ca_rtt_us, sack->rate);
//
	// if (flag & FLAG_ACKED) {
	// 	flag |= FLAG_SET_XMIT_TIMER;  /* set TLP or RTO timer */
	// 	if (unlikely(icsk->icsk_mtup.probe_size &&
	// 		     !after(tp->mtu_probe.probe_seq_end, tp->snd_una))) {
	// 		tcp_mtup_probe_success(sk);
	// 	}
//
	// 	if (tcp_is_reno(tp)) {
	// 		tcp_remove_reno_sacks(sk, pkts_acked);
//
	// 		/* If any of the cumulatively ACKed segments was
	// 		 * retransmitted, non-SACK case cannot confirm that
	// 		 * progress was due to original transmission due to
	// 		 * lack of TCPCB_SACKED_ACKED bits even if some of
	// 		 * the packets may have been never retransmitted.
	// 		 */
	// 		if (flag & FLAG_RETRANS_DATA_ACKED)
	// 			flag &= ~FLAG_ORIG_SACK_ACKED;
	// 	} else {
	// 		int delta;
//
	// 		/* Non-retransmitted hole got filled? That's reordering */
	// 		if (before(reord, prior_fack))
	// 			tcp_check_sack_reordering(sk, reord, 0);
//
	// 		delta = prior_sacked - tp->sacked_out;
	// 		tp->lost_cnt_hint -= min(tp->lost_cnt_hint, delta);
	// 	}
	// } else if (skb && rtt_update && sack_rtt_us >= 0 &&
	// 	   sack_rtt_us > tcp_stamp_us_delta(tp->tcp_mstamp,
	// 					    tcp_skb_timestamp_us(skb))) {
	// 	/* Do not re-arm RTO if the sack RTT is measured from data sent
	// 	 * after when the head was last (re)transmitted. Otherwise the
	// 	 * timeout may continue to extend in loss recovery.
	// 	 */
	// 	flag |= FLAG_SET_XMIT_TIMER;  /* set TLP or RTO timer */
	// }
//
	// if (icsk->icsk_ca_ops->pkts_acked) {
	// 	struct ack_sample sample = { .pkts_acked = pkts_acked,
	// 				     .rtt_us = sack->rate->rtt_us,
	// 				     .in_flight = last_in_flight };
//
	// 	icsk->icsk_ca_ops->pkts_acked(sk, &sample);
	// }
	return flag;
}

/* If we update dsk->receiver.rcv_nxt, also update dsk->receiver.bytes_received 
 * and send ack pkt if the flow is finished */
 
static void nd_rcv_nxt_update(struct nd_sock *nsk, u32 seq)
{
	// struct sock *sk = (struct sock*) nsk;
	// struct inet_sock *inet = inet_sk(sk);
	u32 delta = seq - (u32)atomic_read(&nsk->receiver.rcv_nxt);
	// u32 new_grant_nxt;
	// int grant_bytes = calc_grant_bytes(sk);

	nsk->receiver.bytes_received += delta;
	atomic_set(&nsk->receiver.rcv_nxt, seq);
	// printk("update the rcvnext :%u\n", nsk->receiver.rcv_nxt);
	// new_grant_nxt = nd_window_size(nsk) + nsk->receiver.rcv_nxt;
	// if(new_grant_nxt - nsk->receiver.grant_nxt <= nsk->default_win) {
	// 	/* send ack pkt for new window */
	// 	 nsk->receiver.grant_nxt = new_grant_nxt;
	// 	nd_conn_queue_request(construct_ack_req(sk), false, true);
	// 	// pr_info("grant next update:%u\n", nsk->receiver.grant_nxt);
	// } else {
	// 	pr_info("new_grant_nxt: %u\n", new_grant_nxt);
	// 	pr_info("old grant nxt:%u\n", nsk->receiver.grant_nxt);
	// 	pr_info("nd_window_size(nsk):%u\n", nd_window_size(nsk));
	// }
	// if(dsk->receiver.rcv_nxt >= dsk->receiver.last_ack + dsk->receiver.max_grant_batch) {
	// 	// nd_xmit_control(construct_ack_pkt(sk, dsk->receiver.rcv_nxt), sk, inet->inet_dport); 
	// 	dsk->receiver.last_ack = dsk->receiver.rcv_nxt;
	// }
}

static inline void nd_send_grant(struct nd_sock *nsk, bool sync) {
	struct sock *sk = (struct sock*)nsk;
	gfp_t flag = sync? GFP_KERNEL: GFP_ATOMIC;
	u32 new_grant_nxt;
	new_grant_nxt = nd_window_size(nsk) + (u32)atomic_read(&nsk->receiver.rcv_nxt);
	
	// printk("new grant nxt:%u\n", new_);
	if(new_grant_nxt - nsk->receiver.grant_nxt <= nsk->default_win && new_grant_nxt != nsk->receiver.grant_nxt
		&& new_grant_nxt - nsk->receiver.grant_nxt >= nsk->default_win / 16) {
		/* send ack pkt for new window */
		 nsk->receiver.grant_nxt = new_grant_nxt;
		nd_conn_queue_request(construct_ack_req(sk, flag), nsk, sync, true, true);
		if(nd_params.nd_debug)
			pr_info("grant next update:%u\n", nsk->receiver.grant_nxt);
	} else {
		// if(nd_params.nd_debug) {
		// 	pr_info("new_grant_nxt: %u\n", new_grant_nxt);
		// 	pr_info("old grant nxt:%u\n", nsk->receiver.grant_nxt);
		// 	pr_info("nd_window_size(nsk):%u\n", nd_window_size(nsk));
		// }
	}
}
static void nd_drop(struct sock *sk, struct sk_buff *skb)
{
        sk_drops_add(sk, skb);
        // __kfree_skb(skb);
}

static void nd_v4_fill_cb(struct sk_buff *skb, const struct ndhdr *dh)//将dh信息填充到skb的cb中，主要是seq和end_seq
{
    /* This is tricky : We move IPCB at its correct location into TCP_SKB_CB()
     * barrier() makes sure compiler wont play fool^Waliasing games.
     */
    // memmove(&ND_SKB_CB(skb)->header.h4, IPCB(skb),
    //         sizeof(struct inet_skb_parm));
    barrier();
    ND_SKB_CB(skb)->seq = ntohl(dh->seq);
    // printk("skb len:%d\n", skb->len);
    // printk("segment length:%d\n", ntohl(dh->seg.segment_length));
    ND_SKB_CB(skb)->end_seq = ND_SKB_CB(skb)->seq + skb->len - dh->doff / 4;
    // TCP_SKB_CB(skb)->ack_seq = ntohl(th->ack_seq);
        // TCP_SKB_CB(skb)->tcp_flags = tcp_flag_byte(th);
        // TCP_SKB_CB(skb)->tcp_tw_isn = 0;
        // TCP_SKB_CB(skb)->ip_dsfield = ipv4_get_dsfield(iph);
        // TCP_SKB_CB(skb)->sacked  = 0;
        // TCP_SKB_CB(skb)->has_rxtstamp =
        //                 skb->tstamp || skb_hwtstamps(skb)->hwtstamp;
}


/**
 * nd_try_coalesce - try to merge skb to prior one
 * @sk: socket
 * @dest: destination queue
 * @to: prior buffer
 * @from: buffer to add in queue
 * @fragstolen: pointer to boolean
 *
 * Before queueing skb @from after @to, try to merge them
 * to reduce overall memory use and queue lengths, if cost is small.
 * Packets in ofo or receive queues can stay a long time.
 * Better try to coalesce them right now to avoid future collapses.
 * Returns true if caller should free @from instead of queueing it
 */
static bool nd_try_coalesce(struct sock *sk, struct sk_buff *to, struct sk_buff *from, bool *fragstolen)
{
	int delta;
	// int skb_truesize = from->truesize;
	*fragstolen = false;
	/* Its possible this segment overlaps with prior segment in queue */
	if (ND_SKB_CB(from)->seq != ND_SKB_CB(to)->end_seq)//验证序列号
		return false;
	// pr_info("to len: %d\n", to->len);
	// pr_info("to truesize len: %d\n", to->truesize);

	// pr_info("from truesize: %d\n", from->truesize);
	// if (skb_headlen(from) != 0) { 
	// 	delta = from->truesize - SKB_DATA_ALIGN(sizeof(struct sk_buff));
	// } else {
	// 	delta = from->truesize - SKB_TRUESIZE(skb_end_offset(from);
	// }
	// pr_info("from skb len :%d\n", from->len);
	// pr_info(" SKB_TRUESIZE(skb_end_offset(from):%d\n", skb_end_offset(from));s
	if (!skb_try_coalesce(to, from, fragstolen, &delta))//尝试合并
		return false;
	/* assume we have alrady add true size beforehand*/
	atomic_add(delta, &sk->sk_rmem_alloc);//更新接收缓冲区的内存分配
	// sk_mem_charge(sk, delta);
	// NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPRCVCOALESCE);
	ND_SKB_CB(to)->end_seq = ND_SKB_CB(from)->end_seq;//合并完成后更新to的end_seq
	// ND_SKB_CB(to)->ack_seq = ND_SKB_CB(from)->ack_seq;
	// ND_SKB_CB(to)->tcp_flags |= ND_SKB_CB(from)->tcp_flags;

	// if (ND_SKB_CB(from)->has_rxtstamp) {
	// 	TCP_SKB_CB(to)->has_rxtstamp = true;
	// 	to->tstamp = from->tstamp;
	// 	skb_hwtstamps(to)->hwtstamp = skb_hwtstamps(from)->hwtstamp;
	// }

	return true;
}

// u32 ofo_queue = 0;
static int nd_data_queue_ofo(struct sock *sk, struct sk_buff *skb)
{
	struct nd_sock *dsk = nd_sk(sk);
	struct rb_node **p, *parent;
	struct sk_buff *skb1;
	u32 seq, end_seq;
	/* Disable header prediction. */
	// tp->pred_flags = 0;
	// inet_csk_schedule_ack(sk);
	// pr_info("get outof order packet\n");
	// tp->rcv_ooopack += max_t(u16, 1, skb_shinfo(skb)->gso_segs);
	// NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPOFOQUEUE);
	seq = ND_SKB_CB(skb)->seq;
	end_seq = ND_SKB_CB(skb)->end_seq;

	// printk("insert to data queue ofo:%d\n", seq);

	p = &dsk->out_of_order_queue.rb_node;//指向红黑树的根节点
	if (RB_EMPTY_ROOT(&dsk->out_of_order_queue)) {//红黑树为空，直接插入
		/* Initial out of order segment, build 1 SACK. */
		// if (tcp_is_sack(tp)) {
		// 	tp->rx_opt.num_sacks = 1;
		// 	tp->selective_acks[0].start_seq = seq;
		// 	tp->selective_acks[0].end_seq = end_seq;
		// }
		rb_link_node(&skb->rbnode, NULL, p);
		rb_insert_color(&skb->rbnode, &dsk->out_of_order_queue);
		// tp->ooo_last_skb = skb;
		goto end;
	}

	/* In the typical case, we are adding an skb to the end of the list.
	 * Use of ooo_last_skb avoids the O(Log(N)) rbtree lookup.
	 */
// 	if (tcp_ooo_try_coalesce(sk, tp->ooo_last_skb,
// 				 skb, &fragstolen)) {
// coalesce_done:
// 		tcp_grow_window(sk, skb);
// 		kfree_skb_partial(skb, fragstolen);
// 		skb = NULL;
// 		goto add_sack;
// 	}
// 	 Can avoid an rbtree lookup if we are adding skb after ooo_last_skb 
// 	if (!before(seq, TCP_SKB_CB(tp->ooo_last_skb)->end_seq)) {
// 		parent = &tp->ooo_last_skb->rbnode;
// 		p = &parent->rb_right;
// 		goto insert;
// 	}

	/* Find place to insert this segment. Handle overlaps on the way. */
	parent = NULL;
	while (*p) {//在红黑树中找到合适的位置
		parent = *p;
		skb1 = rb_to_skb(parent);
		if (before(seq, ND_SKB_CB(skb1)->seq)) {//在其seq之前，继续遍历左子树
			p = &parent->rb_left;
			continue;
		}
		//seq>=skb1->seq
		if (before(seq, ND_SKB_CB(skb1)->end_seq)) {//skb1->seq<=seq<skb1->end_seq

			if (!after(end_seq, ND_SKB_CB(skb1)->end_seq)) {//skb1->seq<=seq<end_seq<skb1->end_seq，即skb被skb1包含，直接丢弃
				/* All the bits are present. Drop. */
				nd_rmem_free_skb(sk, skb);
				nd_drop(sk, skb);
				skb = NULL;

				// tcp_dsack_set(sk, seq, end_seq);
				goto add_sack;
			}
			if (after(seq, ND_SKB_CB(skb1)->seq)) {//skb1->seq<seq<end_seq<skb1->end_seq，即部分重叠
			//直接插入不做任何处理吗？？？
				/* Partial overlap. */
				// tcp_dsack_set(sk, seq, TCP_SKB_CB(skb1)->end_seq);
			} else {
				/* skb's seq == skb1's seq and skb covers skb1.
				 * Replace skb1 with skb.
				 */
				//新的skb和skb1有相同的seq，并且完全包含了skb1，利用skb替换skb1，并且将skb1从红黑树中删除
				rb_replace_node(&skb1->rbnode, &skb->rbnode, &dsk->out_of_order_queue);
				// tcp_dsack_extend(sk,
				// 		 TCP_SKB_CB(skb1)->seq,
				// 		 TCP_SKB_CB(skb1)->end_seq);
				// NET_INC_STATS(sock_net(sk),
				// 	      LINUX_MIB_TCPOFOMERGE);
				nd_rmem_free_skb(sk, skb1);
				nd_drop(sk, skb1);
				goto merge_right;
			}
		} 
		// else if (tcp_ooo_try_coalesce(sk, skb1,
		// 				skb, &fragstolen)) {
		// 	goto coalesce_done;
		// }
		//seq在skb1->end_seq之后，继续遍历右子树
		p = &parent->rb_right;
	}
// insert:
	/* Insert segment into RB tree. */
	rb_link_node(&skb->rbnode, parent, p);//在p的位置进行插入
	rb_insert_color(&skb->rbnode, &dsk->out_of_order_queue);
merge_right:
	/* Remove other segments covered by skb. */
	while ((skb1 = skb_rb_next(skb)) != NULL) {//这里next已经隐含了seq<skb1_seq
		if (!after(end_seq, ND_SKB_CB(skb1)->seq))//end<=skb1->seq，即skb1在skb之后
			break;
		if (before(end_seq, ND_SKB_CB(skb1)->end_seq)) {//end_seq<skb1->end_seq，当前包没有完全覆盖skb1
			// tcp_dsack_extend(sk, TCP_SKB_CB(skb1)->seq,
			// 		 end_seq);
			break;
		}
		//end_seq>skb1->seq，并且end_seq>=skb1_end_seq
		//这里为什么仅仅判断结束序列号而不判断开始序列号？？？
		//skb1完全被skb包含，进行清除
		rb_erase(&skb1->rbnode, &dsk->out_of_order_queue);
		// tcp_dsack_extend(sk, TCP_SKB_CB(skb1)->seq,
		// 		 TCP_SKB_CB(skb1)->end_seq);
		// NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPOFOMERGE);
		nd_rmem_free_skb(sk, skb1);
		nd_drop(sk, skb1);

	}
	/* If there is no skb after us, we are the last_skb ! */
	// if (!skb1)
	// 	tp->ooo_last_skb = skb;
add_sack:
	// if (tcp_is_sack(tp))
	// nd_sack_new_ofo_skb(sk, seq, end_seq);
end:
	if(skb) {//skb没有被丢弃，设置相关的属性标识如sk和回收函数
		skb->sk = sk;
		skb->destructor = nd_rfree;
		atomic_add(skb->truesize, &sk->sk_rmem_alloc);//增加套接字接收内存的大小
		// sk_mem_charge(sk, skb->truesize);
		// ofo_queue += skb->len;
		// pr_info("ofo queue length:%u\n", ofo_queue);
	}
	return 0;
	// if (skb) {
	// 	tcp_grow_window(sk, skb);
	// 	skb_condense(skb);
	// 	skb_set_owner_r(skb, sk);
	// }
}

static void nd_ofo_queue(struct sock *sk)//针对out_of_order_queue中的skb，如果其为现在所需的下一个skb，将其移动到receive_queue中
{
	struct nd_sock *dsk = nd_sk(sk);
	// __u32 dsack_high = nd->receiver.rcv_nxt;
	bool fragstolen, eaten;
	// bool fin;
	struct sk_buff *skb, *tail;
	struct rb_node *p;
	// bool first = true;
	// u32 start = 0, end = 0;
	p = rb_first(&dsk->out_of_order_queue);//红黑树的第一个节点指针
	while (p) {
		skb = rb_to_skb(p);
		if (after(ND_SKB_CB(skb)->seq,(u32)atomic_read(&dsk->receiver.rcv_nxt)))//红黑树中最小的seq仍然过大，直接break
			break;
		// ofo_queue -= skb->len;
	
		// if (before(ND_SKB_CB(skb)->seq, dsack_high)) {
		// 	// __u32 dsack = dsack_high;
		// 	// if (before(TCP_SKB_CB(skb)->end_seq, dsack_high))
		// 	// 	dsack_high = TCP_SKB_CB(skb)->end_seq;
		// 	// tcp_dsack_extend(sk, TCP_SKB_CB(skb)->seq, dsack);
		// }
		//此时当前的节点的开始seq小于等于rcv_nxt
		p = rb_next(p);//指向下一个节点
		rb_erase(&skb->rbnode, &dsk->out_of_order_queue);//将当前节点从红黑树中删除
		if (unlikely(!after(ND_SKB_CB(skb)->end_seq, (u32)atomic_read(&dsk->receiver.rcv_nxt)))) {//end_seq<=rcv_nxt，即当前的数据包已经被接受了，该skb已经无效
			nd_rmem_free_skb(sk, skb);
			nd_drop(sk, skb);
			continue;
		}
		// if (first) {
		// 	first = false;
		// 	start =  ND_SKB_CB(skb)->seq;
		// }
		// end = ND_SKB_CB(skb)->end_seq;
		//此时当前的skb满足seq<=rcv_nxt<end_seq，即有内容可以进行交付
		tail = skb_peek_tail(&sk->sk_receive_queue);//从receive_queue中取出最后一个skb
		eaten = tail && nd_try_coalesce(sk, tail, skb, &fragstolen);//尝试合并
		//这里只是比较了seq是否能够接上，但是并没有考虑到两个包之间有一部分数据重合的场景？？？？
		nd_rcv_nxt_update(dsk, ND_SKB_CB(skb)->end_seq);//更新recv_next
		// fin = TCP_SKB_CB(skb)->tcp_flags & TCPHDR_FIN;
		if (!eaten)//合并失败，将当前的skb插入到receive_queue中
			__skb_queue_tail(&sk->sk_receive_queue, skb);
		else
			kfree_skb_partial(skb, fragstolen);//合并成功，释放当前skb的内存

		// if (unlikely(fin)) {
		// 	tcp_fin(sk);
		// 	 tcp_fin() purges tp->out_of_order_queue,
		// 	 * so we must end this loop right now.
			 
		// 	break;
		// }
	}
	// if(end - start != 0)
	// 	pr_info("diff:%d\n", end - start);
}

// void nd_data_ready(struct sock *sk)
// {
//         const struct nd_sock *dsk = nd_sk(sk);
//         int avail = dsk->receiver.rcv_nxt - dsk->receiver.copied_seq;

//         if ((avail < sk->sk_rcvlowat && dsk->receiver.rcv_nxt != dsk->total_length) && !sock_flag(sk, SOCK_DONE)) {
//         	return;
//         }
//         sk->sk_data_ready(sk);
// }

int nd_handle_sync_pkt(struct sk_buff *skb) {
	// struct nd_sock *dsk;
	// struct inet_sock *inet;
	// struct nd_peer *peer;
	// struct iphdr *iph;
	// struct message_hslot* slot;
	struct ndhdr *fh;
	struct sock *sk = NULL, *child;
	struct nd_sock *nsk;
	int sdif = inet_sdif(skb);
	bool refcounted = false;
	if (!pskb_may_pull(skb, sizeof(struct ndhdr))) {//检查是否至少包含ndhdr
		goto drop;		/* No space for header. */
	}
	fh =  nd_hdr(skb);//这里是直接得到的数据包的传输层头部指针
	// sk = skb_steal_sock(skb);
	// if(!sk) {
		// printk("fh->source:%d\n", ntohs(fh->source));
		// printk("fh->dest:%d\n", ntohs(fh->dest));
	// printk ("dev_net(skb_dst(skb)->dev): %d \n",(skb_dst(skb) == NULL));
	// printk("sdif:%d\n", sdif);
	sk = __nd_lookup_skb(&nd_hashinfo, skb, __nd_hdrlen(fh), fh->source, fh->dest, sdif, &refcounted);//根据源目的地址查找套接字
		// sk = __nd4_lib_lookup_skb(skb, fh->common.source, fh->common.dest, &nd_table);
	// }
	if(sk) {
		child = nd_conn_request(sk, skb);//在收到连接建立请求的时候生成一个子套接字，并且通过该子套接字来进行传输吗？？？
		if(child) {
			nsk = nd_sk(child);
			// struct nd_sock *dsk = nd_sk(child);
			// if(dsk->total_length >= nd_params.short_flow_size) {
			// 	rcv_handle_new_flow(dsk);
			// } else {
			// 	/* set short flow timer */
			// 	hrtimer_start(&dsk->receiver.flow_wait_timer, ns_to_ktime(nd_params.rtt * 1000), 
			// 	HRTIMER_MODE_REL_PINNED_SOFT);
			// }
			/* currently assume at the target side */
			/* ToDo: sync can be true; */
			nd_conn_queue_request(construct_sync_ack_req(child), nsk, false, true, true);
		}
	} else {
		goto free;
	}


drop:
    if (refcounted) {
        sock_put(sk);
    }
free:
	kfree_skb(skb);

	return 0;
}

// ktime_t start, end;
// __u32 backlog_time = 0;
int nd_handle_token_pkt(struct sk_buff *skb) {
	struct nd_sock *dsk;
	// struct inet_sock *inet;
	// struct nd_peer *peer;
	// struct iphdr *iph;
	struct nd_token_hdr *th;
	struct sock *sk;
	int sdif = inet_sdif(skb);
	bool refcounted = false;

	if (!pskb_may_pull(skb, sizeof(struct nd_token_hdr))) {
		kfree_skb(skb);
		return 0;
	}
	th = nd_token_hdr(skb);
	sk = __nd_lookup_skb(&nd_hashinfo, skb, __nd_hdrlen(&th->common), th->common.source,
            th->common.dest, sdif, &refcounted);
	if(sk) {
 		dsk = nd_sk(sk);
 		bh_lock_sock(sk);
 		skb->sk = sk;
 		// if (!sock_owned_by_user(sk)) {
			/* clean rtx queue */
		dsk->sender.snd_una = th->rcv_nxt > dsk->sender.snd_una ? th->rcv_nxt: dsk->sender.snd_una;
		/* add token */
 		// dsk->grant_nxt = th->grant_nxt > dsk->grant_nxt ? th->grant_nxt : dsk->grant_nxt;
 	// 	/* add sack info */
 	// 	nd_get_sack_info(sk, skb);
		// /* start doing transmission (this part may move to different places later)*/
	    if(!sock_owned_by_user(sk)) {
	    	// sock_rps_save_rxhash(sk, skb);
	 		nd_clean_rtx_queue(sk);
	    } else {
	 		test_and_set_bit(ND_CLEAN_TIMER_DEFERRED, &sk->sk_tsq_flags);
	    }
	 //    if(!sock_owned_by_user(sk) || dsk->num_sacks == 0) {
	 // 		nd_write_timer_handler(sk);
	 //    } else {
	 // 		test_and_set_bit(ND_RTX_DEFERRED, &sk->sk_tsq_flags);
	 //    }
	 //
        // } else {
        // 	// if(backlog_time % 100 == 0) {
        // 		// end = ktime_get();
        // 		// printk("time diff:%llu\n", ktime_to_us(ktime_sub(end, start)));
        // 		// printk("num of backlog_time:%d\n", backlog_time);
        // 	// }
        //     nd_add_backlog(sk, skb, true);
        // }
        bh_unlock_sock(sk);
		// xmit_handle_new_token(&xmit_core_tab, skb);
	} else {
		kfree_skb(skb);
	};
	// kfree_skb(skb);

    if (refcounted) {
        sock_put(sk);
    }
	return 0;
}

int nd_handle_ack_pkt(struct sk_buff *skb) {
	struct nd_sock *dsk;
	// struct inet_sock *inet;
	// struct nd_peer *peer;
	// struct iphdr *iph;
	// struct ndhdr *dh;
	struct ndhdr *ah;
	struct sock *sk;
	int sdif = inet_sdif(skb);
	bool refcounted = false;
	int err = 0;
	if (!pskb_may_pull(skb, sizeof(struct ndhdr))) {
		kfree_skb(skb);		/* No space for header. */
		return 0;
	}
	ah = nd_hdr(skb);
	// sk = skb_steal_sock(skb);
	// if(!sk) {
	sk = __nd_lookup_skb(&nd_hashinfo, skb, __nd_hdrlen(ah), ah->source,
            ah->dest, sdif, &refcounted);
    // }
	if(nd_params.nd_debug)
		pr_info("receive ack:%u\n", ntohl(ah->grant_seq));
	if(sk) {
 		bh_lock_sock(sk);
		dsk = nd_sk(sk);
	// 	// dsk->sender.snd_una = ah->grant_seq > dsk->sender.snd_una ? ah->rcv_nxt: dsk->sender.snd_una;
		if (!sock_owned_by_user(sk)) {
			if(ntohl(ah->grant_seq) - dsk->sender.sd_grant_nxt <= dsk->default_win) {
				dsk->sender.sd_grant_nxt = ntohl(ah->grant_seq);
				err = nd_push(sk, GFP_ATOMIC);
				if(sk_stream_memory_free(sk)) {
					sk->sk_write_space(sk);
				} 
				/* might need to remove this logic */
				else if(err == -EDQUOT){
					/* push back since there is no space */
					nd_conn_add_sleep_sock(dsk->nd_ctrl, dsk);
				}
			}

			kfree_skb(skb);
        } else {
			nd_add_backlog(sk, skb, true);
	 		// test_and_set_bit(ND_CLEAN_TIMER_DEFERRED, &sk->sk_tsq_flags);
	    }
    	bh_unlock_sock(sk);
	   
	} else {
		kfree_skb(skb);
	}

    if (refcounted) {
        sock_put(sk);
    }

	return 0;
}


int nd_handle_sync_ack_pkt(struct sk_buff *skb) {
	// struct nd_sock *dsk;
	// struct inet_sock *inet;
	// struct nd_peer *peer;
	// struct iphdr *iph;
	// struct ndhdr *dh;
	struct ndhdr *nh;
	struct sock *sk;
	int sdif = inet_sdif(skb);
	bool refcounted = false;
	if (!pskb_may_pull(skb, sizeof(struct ndhdr))) {
		kfree_skb(skb);		/* No space for header. */
		return 0;
	}
	nh = nd_hdr(skb);
	// sk = skb_steal_sock(skb);
	// if(!sk) {
	// pr_info("read src port:%d\n", ntohs(nh->source));
	// pr_info("read dst port:%d\n", ntohs(nh->dest));
	// pr_info("receive sync ack pkt\n");
	sk = __nd_lookup_skb(&nd_hashinfo, skb, __nd_hdrlen(nh), nh->source,
            nh->dest, sdif, &refcounted);
    // }
	if(sk) {
		bh_lock_sock(sk);
		if(!sock_owned_by_user(sk)) {
			sk->sk_state = ND_ESTABLISH;
			sk->sk_data_ready(sk);
			kfree_skb(skb);
		} else {
			nd_add_backlog(sk, skb, true);
		}
		bh_unlock_sock(sk);
		if (refcounted) {
			sock_put(sk);
		}
		return 0;
	} else {
		kfree_skb(skb);
		printk("didn't find the socket\n");
	}
	return 0;
}

int nd_handle_fin_pkt(struct sk_buff *skb) {
	struct nd_sock *dsk;
	// struct inet_sock *inet;
	// struct nd_peer *peer;
	// struct iphdr *iph;
	struct ndhdr *dh;
	struct sock *sk;
	int sdif = inet_sdif(skb);
	bool refcounted = false;

	// if (!pskb_may_pull(skb, sizeof(struct nd_ack_hdr))) {
	// 	kfree_skb(skb);		/* No space for header. */
	// 	return 0;
	// }
	// printk("receive fin pkt\n");
	dh = nd_hdr(skb);
	// sk = skb_steal_sock(skb);
	// if(!sk) {
	sk = __nd_lookup_skb(&nd_hashinfo, skb, __nd_hdrlen(dh), dh->source,
            dh->dest, sdif, &refcounted);
    // }
	if(sk) {
 		bh_lock_sock(sk);
		dsk = nd_sk(sk);
		if (!sock_owned_by_user(sk)) {
			// printk("reach here:%d", __LINE__);

	        nd_set_state(sk, TCP_CLOSE);
	        nd_write_queue_purge(sk);
	        sk->sk_data_ready(sk);
	        kfree_skb(skb);
        } else {
			// printk("put fin to backlog:%d", __LINE__);
            nd_add_backlog(sk, skb, true);
        }
        bh_unlock_sock(sk);

		// printk("socket address: %p LINE:%d\n", dsk,  __LINE__);

	} else {
		kfree_skb(skb);
		printk("doesn't find dsk address LINE:%d\n", __LINE__);
	}

    if (refcounted) {
        sock_put(sk);
    }

	return 0;
}


static int nd_queue_rcv(struct sock *sk, struct sk_buff *skb,  bool *fragstolen)
{
	int eaten;
	struct sk_buff *tail = skb_peek_tail(&sk->sk_receive_queue);//取出接收队列最后一个数据包

	eaten = (tail && nd_try_coalesce(sk, tail, skb, fragstolen)) ? 1 : 0;//尝试与尾部数据包进行合并，eaten为1表示合并成功
	if (!eaten) {//没有合并成功？？为什么会合并失败？不是在调用nd_queue_rcv之前已经确认了当前的skb就是接受队列所需的下一个报文吗？
	//合并失败，手动加入到receive_queue中
		skb->sk = sk;
		skb->destructor = nd_rfree;
		atomic_add(skb->truesize, &sk->sk_rmem_alloc);
		// sk_mem_charge(sk, skb->truesize);
		__skb_queue_tail(&sk->sk_receive_queue, skb);
		
		// skb_set_owner_r(skb, sk);
	}
	//最终增加下一个期望的序列号
	nd_rcv_nxt_update(nd_sk(sk), ND_SKB_CB(skb)->end_seq);
	return eaten;
}

int nd_data_queue(struct sock *sk, struct sk_buff *skb)
{
	struct nd_sock *dsk = nd_sk(sk);
	bool fragstolen;
	int eaten;
	if (ND_SKB_CB(skb)->seq == ND_SKB_CB(skb)->end_seq) {//skb不包含有效数据，直接丢弃这个数据包
		nd_rmem_free_skb(sk, skb);
		return 0;
	}
	// if(WARN_ON(atomic_read(&sk->sk_rmem_alloc) > sk->sk_rcvbuf)) {
	// 	// struct inet_sock *inet = inet_sk(sk);
	//     // printk("seq num:%u\n", ND_SKB_CB(skb)->seq);
	//     // printk("inet sk dport:%d\n", ntohs(inet->inet_dport));
	//     // printk("discard packet due to memory:%d\n", __LINE__);
	// 	// sk_drops_add(sk, skb);
	// 	// kfree_skb(skb);
	// 	// return 0;
	// }
	// if (!sk_rmem_schedule(sk, skb, skb->truesize))
	// 	return -ENOBUFS;
	// atomic_add(skb->truesize, &sk->sk_rmem_alloc);
	//
	// skb_dst_drop(skb);
	// __skb_pull(skb, nd_hdr(skb)->doff >> 2);
	// printk("handle packet data queue?:%d\n", ND_SKB_CB(skb)->seq);

	/*  Queue data for delivery to the user.
	 *  Packets in sequence go to the receive queue.
	 *  Out of sequence packets to the out_of_order_queue.
	 */
	if (ND_SKB_CB(skb)->seq == (u32)atomic_read(&dsk->receiver.rcv_nxt)) {//数据包顺序正确
		// if (tcp_receive_window(tp) == 0) {
		// 	NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPZEROWINDOWDROP);
		// 	goto out_of_window;
		// }

		/* Ok. In sequence. In window. */
// queue_and_out:
		// if (skb_queue_len(&sk->sk_receive_queue) == 0)
		// 	sk_forced_mem_schedule(sk, skb->truesize);
		// else if (tcp_try_rmem_schedule(sk, skb, skb->truesize)) {
		// 	goto drop;
		// }
		// __skb_queue_tail(&sk->sk_receive_queue, skb);
queue_and_out:
		eaten = nd_queue_rcv(sk, skb, &fragstolen);

		if (!RB_EMPTY_ROOT(&dsk->out_of_order_queue)) {//检查out_of_order_queue中是否有数据包，如果有，尝试进行处理
			nd_ofo_queue(sk);
		}

		// 	/* RFC5681. 4.2. SHOULD send immediate ACK, when
		// 	 * gap in queue is filled.
		// 	 */
		// 	if (RB_EMPTY_ROOT(&dsk->out_of_order_queue))
		// 		inet_csk(sk)->icsk_ack.pending |= ICSK_ACK_NOW;
		// }

		// if (dsk->num_sacks)
		// 	nd_sack_remove(dsk);

		// tcp_fast_path_check(sk);

		if (eaten > 0)
			kfree_skb_partial(skb, fragstolen);//当前的skb被成功合并进入前一个数据包中，清除当前skb占用的内存
		return 0;
	}
	if (!after(ND_SKB_CB(skb)->end_seq, (u32)atomic_read(&dsk->receiver.rcv_nxt))) {//end_seq<=rcv_nxt，进行丢包
		printk("duplicate drop\n");
		printk("duplicate seq:%u\n", ND_SKB_CB(skb)->seq);
		nd_rmem_free_skb(sk, skb);
		nd_drop(sk, skb);
		return 0;
	}

	/* Out of window. F.e. zero window probe. */
	// if (!before(ND_SKB_CB(skb)->seq, dsk->rcv_nxt + tcp_receive_window(dsk)))
	// 	goto out_of_window;
	if (unlikely(before(ND_SKB_CB(skb)->seq, (u32)atomic_read(&dsk->receiver.rcv_nxt)))) {
		/* Partial packet, seq < rcv_next < end_seq; unlikely */
		// tcp_dsack_set(sk, ND_SKB_CB(skb)->seq, dsk->rcv_nxt);


		/* If window is closed, drop tail of packet. But after
		 * remembering D-SACK for its head made in previous line.
		 */
		// if (!tcp_receive_window(dsk)) {
		// 	NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPZEROWINDOWDROP);
		// 	goto out_of_window;
		// }
		goto queue_and_out;//部分到达，仍然放入接收队列中吗？？这样是否会导致接收队列出现重复的部分？？？
	}

	nd_data_queue_ofo(sk, skb);//seq>rcv_nxt，放入ofo_queue中
	return 0;
}

bool nd_add_backlog(struct sock *sk, struct sk_buff *skb, bool omit_check)
{//返回true没能放入成功（队列已满），false标识成功加入
		// struct nd_sock *dsk = nd_sk(sk);
        u32 limit = READ_ONCE(sk->sk_rcvbuf) + READ_ONCE(sk->sk_sndbuf);
        // pr_info("put into the backlog\n:wq");
		// skb_condense(skb);

        /* Only socket owner can try to collapse/prune rx queues
         * to reduce memory overhead, so add a little headroom here.
         * Few sockets backlog are possibly concurrently non empty.
         */
        limit += 64*1024;
        if (omit_check) {
        	limit = UINT_MAX;
        }
        if (unlikely(sk_add_backlog(sk, skb, limit))) {//成功放入之后，解除对于socket的锁定
                bh_unlock_sock(sk);
                // __NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPBACKLOGDROP);
                return true;
        }
		/* sk_add_backlog add skb->truesize, but we have fraglist skbs */
		// sk->sk_backlog.len +=  ND_SKB_CB(skb)->total_size - skb->truesize;
        // atomic_add(skb->truesize, &dsk->receiver.backlog_len);

        return false;
 }

static void nd_handle_data_skb_new(struct sock* sk, struct sk_buff* skb) {
		// pr_info("ND_SKB_CB(head)->seq = seq:%u core:%d \n", ND_SKB_CB(skb)->seq, raw_smp_processor_id());
		__skb_pull(skb, nd_hdr(skb)->doff >> 2);//调整数据包的指针位置，跳过自定义报文头ndhdr，使得data指针直接指向数据段（也即真正的TCP字段？？？）
		//在实际的结构中，是ndhdr包着TCP吗？还是反过来？？？
		nd_data_queue(sk, skb);
	return ;
}

/* assuming hold the bh lock of sock */
static void nd_handle_data_pkt_lock(struct sock *sk, struct sk_buff *skb) {
	if (!sock_owned_by_user(sk)) {//检查该套接字是否被用户占用，如果没有，则可以进行包处理
		/* current place to set rxhash for RFS/RPS */
		// printk("skb->hash:%u\n", skb->hash);
		// sock_rps_save_rxhash(sk, skb)
		//  printk("put into the data queue\n");
		nd_handle_data_skb_new(sk, skb);
		// nd_send_grant(dsk, false);
		if (!sock_flag(sk, SOCK_DEAD)) {
			sk->sk_data_ready(sk);//这里的回调函数具体是什么呢？？？？？是默认的吗？？？
		}
		// nd_check_flow_finished_at_receiver(dsk);;
	} else {//否则将数据包放入backlog延迟处理
		// printk("add to backlog: %d\n", raw_smp_processor_id());
		/* omit check for now */
		nd_add_backlog(sk, skb, true);
			// goto discard_and_relse;
	}
	return;
}
/**
 * nd_data_pkt() - Handler for incoming DATA packets
 * @skb:     Incoming packet; size known to be large enough for the header.
 *           This function now owns the packet.
 * 
 * Return: Zero means the function completed successfully. Nonzero means
 * that the RPC had to be unlocked and deleted because the socket has been
 * shut down; the caller should not access the RPC anymore. Note: this method
 * may change the RPC's state to RPC_READY.
 */
int nd_handle_data_pkt(struct sk_buff *skb)
{
	struct nd_sock *dsk;
	struct ndhdr *dh;
	struct sock *sk;
	struct sk_buff *wait_skb, *tmp;
	struct iphdr *iph;
	/* ToDo: get sdif value; now it is polluted by TCP layer */
	// int sdif = inet_sdif(skb);
	int sdif = 0;
	bool refcounted = false;//是否增加了引用计数
	bool discard = false;//是否需要丢弃
	bool oversize = false;//数据包是否超出窗口
	// printk("receive data pkt\n");
	if (!pskb_may_pull(skb, sizeof(struct ndhdr)))
		goto drop;		/* No space for header. */
	dh =  nd_hdr(skb);
	iph = ip_hdr(skb);
	// sk = skb_steal_sock(skb);
	// if(!sk) {
	// WARN_ON(skb_dst(skb) == NULL);
	// WARN_ON(skb_dst(skb)->dev == NULL);
	sk = __nd_lookup_skb(&nd_hashinfo, skb, __nd_hdrlen(dh), dh->source, dh->dest, sdif, &refcounted);//根据源地址和目的地址查找对应的（虚拟）套接字
	// printk("dh->source:%d dh->dest:%d \n", dh->source, dh->dest);
	// printk("iph->saddr:%d iph->daddr:%d\n", iph->saddr, iph->daddr);
	// printk("__nd_hdrlen(dh):%d sdif:%d inet_iif(skb):%d \n", __nd_hdrlen(dh), sdif, inet_iif(skb));
    if(!sk) {
    	goto drop;
	}
	nd_v4_fill_cb(skb, dh);//将ndhdr的seq填充到skb中，便于之后收包时候的处理

    // }
	// printk("packet hash %u\n", skb->hash);
	// printk("oacket is l4 hash:%d\n", skb->l4_hash);
	// printk("receive packet core:%d\n", raw_smp_processor_id());
	// printk("dport:%d\n", ntohs(inet_sk(sk)->inet_dport));
	// printk("skb seq:%u\n", ND_SKB_CB(skb)->seq);
	// printk("skb address:%p\n", skb);
	if(sk) {//查找成功，进行处理，这里sk是与用户进行交互的虚拟套接字
		dsk = nd_sk(sk);
		// iph = ip_hdr(skb);
 		bh_lock_sock(sk);//处理时首先对于该虚拟套接字上锁
		if(sk->sk_state != ND_ESTABLISH){//如果套接字状态不是建立状态，丢弃数据包
			bh_unlock_sock(sk);
			goto drop;
		}
		/* To Do: check sk_hol_queue */
		skb_queue_walk_safe(&dsk->receiver.sk_hol_queue, wait_skb, tmp) {//遍历sk_hol_queue，为什么要遍历？？当前不是处理的skb吗？
			//sk_hol_queue暂存了乱序到达的数据包，以及超过窗口范围的数据包
			/* this might underestimate the current buffer size if socket is handling its backlog */
			if(ND_SKB_CB(wait_skb)->end_seq - (u32)atomic_read(&dsk->receiver.rcv_nxt) >=  nd_window_size(dsk)) {//检查窗口范围
				continue;
			}
			//检查到wait_skb在窗口范围内，对其移除并进行处理
			__skb_unlink(wait_skb, &dsk->receiver.sk_hol_queue);
			atomic_sub(wait_skb->truesize, &tcp_sk(ND_SKB_CB(wait_skb)->queue->sock->sk)->hol_alloc);//减少队列的占用内存
			atomic_sub(wait_skb->len, &tcp_sk(ND_SKB_CB(wait_skb)->queue->sock->sk)->hol_len);//减少队列的数据长度
			// printk("reduce hol alloc:%d\n", atomic_read(&tcp_sk(wait_skb->sk)->hol_alloc));
			if(atomic_read(&tcp_sk(ND_SKB_CB(wait_skb)->queue->sock->sk)->hol_alloc) == 0) {
				//为什么等到hol_alloc被分配完了之后才进行发送ACK？？？
				//等待队列空了标识当前的队列的乱序数据包已经处理完了，此时才算有接收窗口可以接收新的数据包，所以此时才发送ACK
				//在传入当前的skb的queue上通知执行回ACK，仍然基于work_struct
				//注意这里是skb所属的队列通过其队列的socket发送ACK，而不是当前的socket
				//并且发送的时候是直接调用__send_ack直接告诉了期待的下一个序列号，而不是利用skb的序列号（已经被更改）
				if(ndt_conn_is_latency(ND_SKB_CB(skb)->queue)) {
					queue_work_on(queue_cpu(ND_SKB_CB(skb)->queue), ndt_conn_wq_lat, &ND_SKB_CB(skb)->queue->delay_ack_work);
				} else {
					queue_work_on(queue_cpu(ND_SKB_CB(skb)->queue), ndt_conn_wq, &ND_SKB_CB(skb)->queue->delay_ack_work);
				}
				if(hrtimer_active(&ND_SKB_CB(skb)->queue->hol_timer)) {
					hrtimer_cancel(&ND_SKB_CB(skb)->queue->hol_timer);
				}
			}		
			ND_SKB_CB(wait_skb)->queue = NULL;//为什么要清空queue？？？？是因为接收的Channel任务已经完成了吗？？？
			nd_handle_data_pkt_lock(sk, wait_skb);//对于wait_skb进行处理

		}
        // ret = 0;
		// printk("atomic backlog len:%d\n", atomic_read(&dsk->receiver.backlog_len));
		/* this might underestimate the current buffer size if socket is handling its backlog */
		/* this part might needed to be changed later, because rcv_nxt */
		if(ND_SKB_CB(skb)->end_seq - (u32)atomic_read(&dsk->receiver.rcv_nxt) < nd_window_size(dsk)) {
			nd_handle_data_pkt_lock(sk, skb);//在窗口范围内，进行处理
			// printk("handle data pkt lock seq:%u rcv next:%u core:%d\n",
			// 	ND_SKB_CB(skb)->seq, (u32)atomic_read(&dsk->receiver.rcv_nxt),  raw_smp_processor_id());	
			// printk("rcv_nxt:%u\n", (u32)atomic_read(&dsk->receiver.rcv_nxt));
		} else {
			// oversize = true;
			if(ND_SKB_CB(skb)->end_seq == (u32)atomic_read(&dsk->receiver.rcv_nxt)) {
				WARN_ON(true);
			}
			/* increment hol_alloc size of tcp socket */
			atomic_add(skb->truesize, &tcp_sk(ND_SKB_CB(skb)->queue->sock->sk)->hol_alloc);
			atomic_add(skb->len, &tcp_sk(ND_SKB_CB(skb)->queue->sock->sk)->hol_len);

			/* add to hol skb to the socket wait queue */
			__skb_queue_tail(&dsk->receiver.sk_hol_queue, skb);//否则放入hol队列
			/* add to wait queue flags */
			test_and_set_bit(ND_WAIT_DEFERRED, &sk->sk_tsq_flags);//设置标志位，标识存在需要延迟处理的乱序/超过窗口的数据包
			// printk("add hol alloc:%d  seq:%u rcv next:%u copied seq:%u core:%d\n", atomic_read(&tcp_sk(ND_SKB_CB(skb)->queue->sock->sk)->hol_alloc),
			// 	ND_SKB_CB(skb)->seq, (u32)atomic_read(&dsk->receiver.rcv_nxt),  (u32)atomic_read(&dsk->receiver.copied_seq),  raw_smp_processor_id());
			// printk("rmem alloc:%d backlog len:%d \n", atomic_read(&sk->sk_rmem_alloc), sk->sk_backlog.len );	
			// printk("rcv_nxt:%u\n", (u32)atomic_read(&dsk->receiver.rcv_nxt));
		

		}
		/* handle the current pkt */
        bh_unlock_sock(sk);
	} else {
		// printk("discard pkt\n");
		discard = true;
	}
	
	if (discard) {
	    // printk("seq num:%u\n", ND_SKB_CB(skb)->seq);
	    // printk("discard packet:%d\n", __LINE__);
		// skb_dump(KERN_WARNING, skb, false);
		sk_drops_add(sk, skb);//设置丢包计数
		goto drop;
	}

    if (refcounted) {
        sock_put(sk);
    }

	/* packets have to be stuck in the nd channel */
	// if(oversize)
	// 	return -1;
    return 0;
drop:
    if (refcounted) {
        sock_put(sk);
    }
	printk("drop pkt\n");
    /* Discard frame. */
	// skb->queue = NULL;
    kfree_skb(skb);
    return -2;

// discard_and_relse:
//     printk("seq num:%u\n", ND_SKB_CB(skb)->seq);
//     printk("discard packet due to memory:%d\n", __LINE__);
//     sk_drops_add(sk, skb);
//     if (refcounted)
//             sock_put(sk);
//     goto drop;
	// kfree_skb(skb);
}

/* should hold the lock, before calling this function；
 * This function is only called for backlog handling from the release_sock()
 */
int nd_v4_do_rcv(struct sock *sk, struct sk_buff *skb) {
	struct ndhdr* dh;
    struct nd_sock *dsk = nd_sk(sk);
	int err = 0;
	dh = nd_hdr(skb);
	// atomic_sub(skb->truesize, &dsk->receiver.backlog_len);
	/* current place to set rxhash for RFS/RPS */
 	// sock_rps_save_rxhash(sk, skb);

	if(dh->type == DATA) {
		nd_handle_data_skb_new(sk, skb);
		// nd_send_grant(dsk, true);
		if (!sock_flag(sk, SOCK_DEAD)) {
			sk->sk_data_ready(sk);
		}
		return 0;
		// return __nd4_lib_rcv(skb, &nd_table, IPPROTO_VIRTUAL_SOCK);
	} else if (dh->type == FIN) {
		// printk("reach here:%d", __LINE__);

        nd_set_state(sk, TCP_CLOSE);
        nd_write_queue_purge(sk);
		// atomic_sub(skb->truesize, &sk->sk_rmem_alloc);
		sk->sk_data_ready(sk);
	} else if (dh->type == ACK) {
		/*do nd push and check the seq */
		// pr_info("backlog:%u\n", ntohl(dh->grant_seq));
		// pr_info("receive ack in backlog\n");
		// pr_info("handle ack in backlog\n");
		if(ntohl(dh->grant_seq) - dsk->sender.sd_grant_nxt <= dsk->default_win) {
			dsk->sender.sd_grant_nxt = ntohl(dh->grant_seq);
		}
		/*has to do nd push and check seq */
		err = nd_push(sk, GFP_KERNEL);
		if(sk_stream_memory_free(sk)) {
			// pr_info("invoke write space in backlog\n");
			sk->sk_write_space(sk);
		} 
		else if(err == -EDQUOT){
			/* push back since there is no space */
			// pr_info("add sleep sock in backlog\n");
			nd_conn_add_sleep_sock(dsk->nd_ctrl, dsk);
		}
	} else if (dh->type == SYNC_ACK) {
		sk->sk_state = ND_ESTABLISH;
		sk->sk_data_ready(sk);
	}

	// else if (dh->type == TOKEN) {
	// 	/* clean rtx queue */
	// 	struct nd_token_hdr *th = nd_token_hdr(skb);
	// 	dsk->sender.snd_una = th->rcv_nxt > dsk->sender.snd_una ? th->rcv_nxt: dsk->sender.snd_una;
 // 		nd_clean_rtx_queue(sk);
	// 	/* add token */
 // 		dsk->grant_nxt = th->grant_nxt > dsk->grant_nxt ? th->grant_nxt : dsk->grant_nxt;
	//  	/* add sack info */
 // 		nd_get_sack_info(sk, skb);
 // 		// will be handled by nd_release_cb
 // 		test_and_set_bit(ND_CLEAN_TIMER_DEFERRED, &sk->sk_tsq_flags);
	// 	atomic_sub(skb->truesize, &sk->sk_rmem_alloc);
	// }
	kfree_skb(skb);
	return 0;
}


/**
 * nd_release_cb - nd release_sock() callback
 * @sk: socket
 *
 * called from release_sock() to perform protocol dependent
 * actions before socket release.
 */
void nd_release_cb(struct sock *sk)
{
	unsigned long flags, nflags;
	struct nd_sock* nsk = nd_sk(sk);
	struct sk_buff *skb, *tmp;
	/* perform an atomic operation only if at least one flag is set */
	do {
		flags = sk->sk_tsq_flags;
		if (!(flags & ND_DEFERRED_ALL))
			return;
		nflags = flags & ~ND_DEFERRED_ALL;
	} while (cmpxchg(&sk->sk_tsq_flags, flags, nflags) != flags);

	// if (flags & TCPF_TSQ_DEFERRED) {
	// 	tcp_tsq_write(sk);
	// 	__sock_put(sk);
	// }
	/* Here begins the tricky part :
	 * We are called from release_sock() with :
	 * 1) BH disabled
	 * 2) sk_lock.slock spinlock held
	 * 3) socket owned by us (sk->sk_lock.owned == 1)
	 *
	 * But following code is meant to be called from BH handlers,
	 * so we should keep BH disabled, but early release socket ownership
	 */
	sock_release_ownership(sk);

	// if (flags & NDF_CLEAN_TIMER_DEFERRED) {
	// 	nd_clean_rtx_queue(sk);
	// 	// __sock_put(sk);
	// }
	// if (flags & NDF_TOKEN_TIMER_DEFERRED) {
	// 	WARN_ON(true);
	// 	nd_token_timer_defer_handler(sk);
	// 	// __sock_put(sk);
	// }
	// if (flags & NDF_RTX_DEFERRED) {
	// 	WARN_ON(true);
	// 	nd_write_timer_handler(sk);
	// }
	/* handle pkts in the wait queue */
	if (flags & NDF_WAIT_DEFERRED) {
		skb_queue_walk_safe(&nsk->receiver.sk_hol_queue, skb, tmp) {
			/* this might underestimate the current buffer size if socket is handling its backlog */
			if(ND_SKB_CB(skb)->end_seq - (u32)atomic_read(&nsk->receiver.rcv_nxt) >= nd_window_size(nsk)) {
				// printk("release cb hol pkt seq:%u mem:%u rcv nxt:%u \n",ND_SKB_CB(skb)->seq, atomic_read(&sk->sk_rmem_alloc),  nsk->receiver.rcv_nxt );
				continue;
			}
			__skb_unlink(skb, &nsk->receiver.sk_hol_queue);
			/* reduce the truesize of hol_alloc of tcp socket */
			atomic_sub(skb->truesize, &tcp_sk(ND_SKB_CB(skb)->queue->sock->sk)->hol_alloc);
			atomic_sub(skb->len, &tcp_sk(ND_SKB_CB(skb)->queue->sock->sk)->hol_len);
			if(atomic_read(&tcp_sk(ND_SKB_CB(skb)->queue->sock->sk)->hol_alloc) == 0) {
				if(ndt_conn_is_latency(ND_SKB_CB(skb)->queue)) {
					queue_work_on(queue_cpu(ND_SKB_CB(skb)->queue), ndt_conn_wq_lat, &ND_SKB_CB(skb)->queue->delay_ack_work);
				} else {
					queue_work_on(queue_cpu(ND_SKB_CB(skb)->queue), ndt_conn_wq, &ND_SKB_CB(skb)->queue->delay_ack_work);
				}
				if(hrtimer_active(&ND_SKB_CB(skb)->queue->hol_timer)) {
					hrtimer_cancel(&ND_SKB_CB(skb)->queue->hol_timer);
				}
			}
			ND_SKB_CB(skb)->queue = NULL;
			nd_handle_data_skb_new(sk, skb);

			/* To Do: we might need to wake up the corresponding queue to send ack? */
			// nd_send_grant(dsk, true);
		}
		if(skb_peek(&nsk->receiver.sk_hol_queue)) {
			test_and_set_bit(ND_WAIT_DEFERRED, &sk->sk_tsq_flags);
		}

	}
	/* wake up hol channels */
	// if(flags & NDF_CHANNEL_DEFERRED) {
	// 	struct ndt_channel_entry *entry, *temp;
	// 	struct ndt_conn_queue *queue;
	// 	list_for_each_entry_safe(entry, temp, &nsk->receiver.hol_channel_list, list_link) {
	// 		queue = entry->queue;
	// 		if(ndt_conn_is_latency(queue)) {
	// 			queue_work_on(queue_cpu(queue), ndt_conn_wq_lat, &queue->io_work);
	// 		} else {
	// 			queue_work_on(queue_cpu(queue), ndt_conn_wq, &queue->io_work);
	// 		}
	// 		kfree(entry);
	// 	}
	// 	INIT_LIST_HEAD(&nsk->receiver.hol_channel_list);
	// }
	// if (flags & TCPF_MTU_REDUCED_DEFERRED) {
	// 	inet_csk(sk)->icsk_af_ops->mtu_reduced(sk);
	// 	__sock_put(sk);
	// }
}
EXPORT_SYMBOL(nd_release_cb);

/* split skb and push back the new skb into head of the queue */
int nd_split(struct sk_buff_head* queue, struct sk_buff* skb, int need_bytes) {
	//截取前面的 need_bytes 字节保留在原 skb 中，剩余部分放入新数据包，
	struct sk_buff* new_skb;
	int bytes = ND_HEADER_MAX_SIZE, len;
	if(skb->len < need_bytes)
		return -ENOMEM;
	if(skb->len == need_bytes)//正好为需要的长度，没有产生新的skb，直接返回
		return 0;
	/* first split new skb */
	/* this part might need to be changed */
	if(skb_headlen(skb) > need_bytes) {//这里直接用headlen标识直接用指针指向的一大片的内存而不涉及frag_list，即优先处理线性部分
		bytes +=  skb_headlen(skb) - need_bytes;//新的skb的长度，此时数据直接放到线性缓冲区里？？？
	}
	// printk("alloc bytes:%d\n", bytes);
	new_skb = alloc_skb(bytes, GFP_ATOMIC);//alloc_skb(unsigned int size, gfp_t gfp_mask)中的size标识了线性缓冲区的大小，以字节为单位
	if(!new_skb)
		WARN_ON(true);
	// pr_info("reach here:%d\n", __LINE__);
	// skb_dump(KERN_WARNING, skb, false);

	/* set page pool for new_skb */
	skb_shinfo(new_skb)->page_pool = skb_shinfo(skb)->page_pool;//保持数据页的来源一致，方便再后续释放或者处理数据页时能够被正确引用
	/* set the network header, but not tcp header */
	skb_put(new_skb, sizeof(struct iphdr));

	skb_reset_network_header(new_skb);

	memcpy(skb_network_header(new_skb), skb_network_header(skb), sizeof(struct iphdr));//设置新数据包的网络头部（直接将原数据包的头部复制过去）
	skb_pull(new_skb, sizeof(struct iphdr));
	/* change the truesize */
	len = skb->len - need_bytes;
	new_skb->truesize += len;//新数据包长度增加len
	skb->truesize -= len;//原数据包长度减少len
	skb_split(skb, new_skb, need_bytes);//原来的skb的need_bytes字节保留，剩余数据放入新数据包new_skb
	ND_SKB_CB(new_skb)->has_old_frag_list = 0;//原skb经过nd_queue_origin_skb，没有frag_list
	ND_SKB_CB(new_skb)->orig_offset = 0;
	skb_queue_head(queue, new_skb);//新的skb入队
	// pr_info("reach here:%d\n", __LINE__);
	// skb_dump(KERN_WARNING, new_skb, false);
	return 0; 
}

/* handle the skb when they first inserted into the queue; note we have to do this in a delayed manner which allows 
	TCP to clean the cloned skbs;
*/
static void nd_queue_origin_skb(struct sk_buff_head* queue, struct sk_buff *skb) {
	//对于skb进行处理，清理和调整数据包的偏移和frag_list，将清理后数据包插入指定队列
	struct sk_buff *list_skb, *list_skb_next, *list_skb_prev = NULL;
	if(ND_SKB_CB(skb)->orig_offset) {//清理数据包的初始偏移量，使得偏移量为0，数据指针直接指向数据
		/* fraglist could change */
	 	WARN_ON(!pskb_pull(skb, ND_SKB_CB(skb)->orig_offset));//从skb的数据缓冲区中移除指定长度的前置数据，并更新相关元信息
		// __skb_pull(skb, ND_SKB_CB(skb)->orig_offset);
		ND_SKB_CB(skb)->orig_offset = 0;

	}
	if(ND_SKB_CB(skb)->has_old_frag_list) {
		//标识当前的skb是否包含了没有处理的分片列表（frag_list），将一个通过sh_info附带了很多skb的skb结构体拆分成一个个skb
		//将新的结构体放入了队列之后还会被新一轮枚举到？？所以不用担心sh_info嵌套的情况？？？
		ND_SKB_CB(skb)->has_old_frag_list = 0;
		list_skb = skb_shinfo(skb)->frag_list;
		skb_shinfo(skb)->frag_list = NULL;
		while(list_skb) {//遍历frag_list，从中取出每一个skb
			if(refcount_read(&list_skb->users) > 1)//检查引用计数？？？
				WARN_ON(true);
			ND_SKB_CB(list_skb)->has_old_frag_list = 0;//这里实际中skb_shinfo->frag_list不会嵌套
			ND_SKB_CB(list_skb)->orig_offset = 0;
			list_skb_next = list_skb->next;
			skb->truesize -= list_skb->truesize;//更新主skb相应的数据
			skb->data_len -= list_skb->len;
			skb->len -= list_skb->len;
			if(list_skb_prev == NULL)
				 __skb_queue_head(queue, list_skb);//当前分片为第一个分片，直接插入队列头部
			else
				__skb_queue_after(queue, list_skb_prev, list_skb);
			list_skb_prev = list_skb;//不断向下遍历
			list_skb = list_skb_next;
		}
	}
}

int nd_split_and_merge(struct sk_buff_head* queue, struct sk_buff* skb, int need_bytes, bool coalesce) {
	//从queue中提取数据包（skb），将不足的数据（need_bytes）补充到当前的 skb 中，使其满足协议解析的需求
	//这里由于queue的数据都来自于tcp->receive_queue中将大skb拆分得到的，所以保证是有序的
	struct sk_buff* new_skb, *head;
	int delta = 0;
 	bool fragstolen = false;
	head = skb;
	// pr_info("reach here:%d\n", __LINE__);
	while(need_bytes > 0) {
		/* skb_split only handles non-header part */
		fragstolen = false;
		delta = 0;
		new_skb =  __skb_dequeue(queue);//不断取出新的skb
		if(!new_skb)
			return -ENOMEM;
		// if(skb_cloned(new_skb))
		// 	WARN_ON(true);
		nd_queue_origin_skb(queue, new_skb);//从队列头部取出新的skb，对其进行处理(矫正指针指向数据)，这里可能来自于之前的receive_queue，也有可能来自于skb的frag_list
		// pr_info("new_skb->len:%d\n", new_skb->len);
		if(new_skb->len > need_bytes)
			nd_split(queue, new_skb, need_bytes);//数据包进行分割，此时new_skb中恰好包含了所需的数据量（有可能还是不够），多余的数据量被放在了queue中
		need_bytes -= new_skb->len;
		// pr_info("reach here:%d\n", __LINE__);
		// pr_info("new_skb->len:%d\n", new_skb->len);
		// if(coalesce) {
		// 	if (!skb_try_coalesce(head, new_skb, &fragstolen, &delta)) {
		// 		// int i = 0;
		// 		WARN_ON(true);
		// 		// skb_dump(KERN_WARNING, head, false);
		// 		// skb_dump(KERN_WARNING, new_skb, false);
		// 		// pr_info("head has fraglist: %d\n ", skb_has_frag_list(head));
		// 		// pr_info("new_skb has fraglist: %d\n ", skb_has_frag_list(new_skb));
		// 		// pr_info("nrfragment: head:%d\n", skb_shinfo(head)->nr_frags);
		// 		// pr_info("nrfragment: new_skbhead:%d\n", skb_shinfo(new_skb)->nr_frags);
		// 		// pr_info("skb_cloned(skb):%d\n", skb_cloned(skb));
		// 		// pr_info("skb_cloned(new_skb):%d\n", skb_cloned(new_skb));
		// 		// pr_info("skb_head_is_locked:%d\n", skb_head_is_locked(new_skb));
		// 		// pr_info("Coalesce fails:%d\n", __LINE__);
		// 		// pr_info("need bytes:%d\n", need_bytes);
		// 		// pr_info("skb len:%d\n", skb->len);
		// 		// pr_info("skb trusize:%d\n", skb->truesize);
		// 		// pr_info("new skb len:%d\n", new_skb->len);
		// 		// pr_info("bew skb trusize:%d\n", new_skb->truesize);
		// 		// pr_info("skb frags:%d\n", skb_shinfo(skb)->nr_frags);
		// 		// pr_info("new skb frags:%d\n", skb_shinfo(new_skb)->nr_frags);
		// 		// for(i = 0; i <  skb_shinfo(skb)->nr_frags; i++) {
		// 		// 	skb_frag_t *frag = &skb_shinfo(skb)->frags[i];
		// 		// 	pr_info("frag %d size : %d\n ",i, skb_frag_size(frag));
		// 		// }
		// 	} else {
		// 		kfree_skb_partial(new_skb, fragstolen);
		// 	}
		// } else {
			// pr_info("reach here:%d\n", __LINE__);
			if(!skb_shinfo(head)->frag_list) {
				skb_shinfo(head)->frag_list = new_skb;
				//将新的skb放入到head的frag_list中，这样做的目的是什么呢？为什么要先通过queue_origin_skb进行重新组织（主要是使得指针直接指向数据）？
				ND_SKB_CB(head)->tail = new_skb;
				// pr_info("reach here:%d\n", __LINE__);

			} else {
				// pr_info("reach here:%d\n", __LINE__);
				if(!skb_has_frag_list(skb) || ND_SKB_CB(head)->tail == NULL)
					WARN_ON(true);
				// pr_info("!skb_has_frag_list(skb):%d\n",(!skb_has_frag_list(skb)));
                //                 pr_info("ND_SKB_CB(head)->tail:%p\n", ND_SKB_CB(head)->tail);
                //                 pr_info("ND_SKB_CB(head)->tail->next:%p\n", ND_SKB_CB(head)->tail->next);
				ND_SKB_CB(head)->tail->next = new_skb;
				ND_SKB_CB(head)->tail = new_skb;//插入frag_list的尾部
                // pr_info("reach here:%d\n", __LINE__);
			}
			// skb = new_skb;
			/* don't increment truesize and len of head */
			// pr_info("reach here:%d\n", __LINE__);
			head->truesize += new_skb->truesize;
			head->data_len += new_skb->len;
			head->len += new_skb->len;//更新相关的数据
			ND_SKB_CB(head)->count += 1;//frag_list中skb的数量
		// }
	}
	if(need_bytes > 0)
		return -ENOMEM;
	return 0;
}

/* reorganize skb; this part might not need to be used later*/
static void reparse_skb(struct sk_buff* skb) {
		// uint32_t count, total_len, i;
		// struct sk_buff* head = skb_shinfo(skb)->frag_list; 
		// struct iphdr *iph;
		// struct ndhdr *dh;
	
		// iph = ip_hdr(skb);
		// dh =  nd_hdr(skb);
		// /* handle the first packet which contains the header */
		// count = ND_SKB_CB(skb)->count;
		// total_len = ND_SKB_CB(skb)->total_len;

		// ND_SKB_CB(skb)->count = 0;
		// ND_SKB_CB(skb)->total_len = 0;
		// ND_SKB_CB(skb)->total_size = 0;
		// /* handle the rest of packets */
		// for(i = 0; i < count; i++) {
		// 	// WARN_ON(!head);
		// 	// head->next = NULL;
		// 	/* update the len, data_len, truesize */
		// 	skb->truesize += head->truesize;
		// 	skb->data_len += head->len;
		// 	skb->len += head->len;
		// 	head = head->next;
		// }
}

int pass_to_vs_layer(struct ndt_conn_queue *ndt_queue, struct sk_buff_head* queue) {
	//传入的为所属的ndt_queue及其ndt_conn_queue->receive_queue
	//从ndt_conn_queue中不断取出数据包，并且传送给Virtual NetWwork System进行处理
	//传入的queue为对应ndt_queue的receive_queue
	//主要的目的是将TCP的skb_list转化为完整、独立的nhd_list(将多个小skb拼接为多个完整的独立的自定义协议的报文)
	struct sock *sk = ndt_queue->sock->sk;//获得发送过来的套接字标识？？？
	struct sk_buff *skb;
	struct ndhdr* nh;
	int need_bytes = 0;
	int ret;
	struct iphdr* iph;
	bool hol = false;

	// WARN_ON(queue == NULL);
	while ((skb = __skb_dequeue(queue)) != NULL) {//遍历接受队列，不断取出skb
		// pr_info("%d skb->len:%d\n",__LINE__,  skb->len);
		// pr_info("!skb_has_frag_list(skb): %d\n", (!skb_has_frag_list(skb)));
		if(skb_cloned(skb))
			WARN_ON(true);
		nd_queue_origin_skb(queue, skb);
		//首先将当前的skb的指针调整，并且将shinfo_list中附带的skb全部拆分到queue中等待后续的同步调整
		//将所有的skb都拆分出来放到queue(ndt_conn_queue->receive_queue)中，这里可能会有乱序？？？

		// pr_info("start processing\n");
		// pr_info("skb->len:%d\n", skb->len);
		if (!pskb_may_pull(skb, sizeof(struct ndhdr))) {//检查是否至少包含一个ndhdr的长度，并且确保skb的数据指针指向数据
			//确保当前数据包头部数据完整性，数据包头部数据可能由于分片等原因分散在多个skb中，导致单个skb不包含完整的头部
			need_bytes = sizeof(struct ndhdr) - skb->len;//距离拼凑出完整的头部还需要的字节数
			if(need_bytes < 0)
				WARN_ON(true);
			// WARN_ON(need_bytes < 0);
			// pr_info("skb->len:%d\n", skb->len);
			// pr_info("reach here: %d\n", __LINE__);
			ret = nd_split_and_merge(queue, skb, need_bytes, true);//从queue中提取并合并当前skb后续的数据包
			/* No space for header . */
			if(ret == -ENOMEM) {
				goto push_back;
				// pr_info("reach here: %d\n", __LINE__);
			}
			/* pull again */
			pskb_may_pull(skb, sizeof(struct ndhdr));//填充之后重新调整指针，确保data指向实际数据开始的部分
		}
		// pr_info("skb->len:%d\n", skb->len);
		// pr_info("skb->headlen:%d\n", skb_headlen(skb));
		/* reset the transport layer header as nd header; and ignore TCP header */
		skb_set_transport_header(skb, 0);//设置协议头部并且解析，调用 skb_set_transport_header，将传输层头部指针设置为数据起始处
		nh = nd_hdr(skb);//将skb数据包头部解析为自定义协议
		// skb_dump(KERN_WARNING, skb, false);
		// WARN_ON(nh->type != DATA && nh->type != SYNC);
		/* this layer could do sort of GRO stuff later */
		if(nh->type == DATA) {
			if(!skb_has_frag_list(skb)) {
				/* first time to handle the skb */
				// skb_shinfo(head)->frag_list = NULL;
				// ND_SKB_CB(skb)->total_size = skb->truesize;
				// ND_SKB_CB(skb)->total_len = skb->len;
				ND_SKB_CB(skb)->count = 0;
				ND_SKB_CB(skb)->tail = NULL;
				
			}

			need_bytes = (int)(ntohs(nh->len)) + sizeof(struct ndhdr) - skb->len;
			//一个自定义类型nd_hdr头部被还原出来之后，其头部指针包含了其总共的数据段的长度，继续通过nd_split_and_merge进行补全
			// pr_info("ntohs(nh->len):%d\n", ntohs(nh->len));
			// pr_info("ND_SKB_CB(skb)->total_len:%d\n", ND_SKB_CB(skb)->total_len);
			// pr_info("LINE:%d need bytes:%d\n", __LINE__,  need_bytes);
			if(need_bytes > 0) {
				ret = nd_split_and_merge(queue, skb, need_bytes, false);//进行分片合并
				if(ret == -ENOMEM) {
					// pr_info("go to push back\n");
					goto push_back;

				}
			}
			if(need_bytes < 0) {
				nd_split(queue, skb, ntohs(nh->len) + sizeof(struct ndhdr));//如果包含了太多的内容，将多余的内容放入新的skb中
				// ND_SKB_CB(skb)->total_len += need_bytes;
			}
			/* reparse skb */
			reparse_skb(skb);
		}else {
			/* this split should always be suceessful */
			nd_split(queue, skb, sizeof(struct ndhdr));//如果是其他类型（如ACK，FIN等类型的控制报文），则仅仅保留当前的ndhdr信息
		}
		/* pass to the vs layer; local irq should be disabled */
		// skb_dump(KERN_WARNING, skb, false);
		iph = ip_hdr(skb);
		nh = nd_hdr(skb);
		// if(nh->type == 0) {
		// 	pr_info("receive skb:%u\n", ntohl(nh->seq));
		// 	pr_info("type:%d\n", nh->type);
		// }

		// pr_info("receive new ack seq num :%u\n", ntohl(nh->grant_seq));
		// pr_info("total len:%u\n", ND_SKB_CB(skb)->total_len);
		// WARN_ON(READ_ONCE(sk->sk_rx_dst) == NULL);
		skb_dst_set_noref(skb, ndt_queue->dst);//将目标缓存设置为 ndt_queue->dst
		/* To Do: add reference count for sk in the future */
		if(nh->type == DATA)
			ND_SKB_CB(skb)->queue = ndt_queue;
		// pr_info("ND_SKB_CB(skb)->total_len:%u\n", ND_SKB_CB(skb)->total_len);
		// if(nh->type == DATA) {
		// 	pr_info("receive skb:%u CORE:%d\n", ntohl(nh->seq), raw_smp_processor_id());
		// }
		/* disable irq since it is in the process context */
		// if(nh->type == DATA) {
		// 	start_time = ktime_get_ns();
		// 	printk("receive data\n");
		// } else {
		// 	printk("receive ack\n");
		// }
		// 	pr_info("reach here:%d\n", __LINE__);
			// skb_dump(KERN_WARNING, skb, false);
		
		local_bh_disable();//关闭软中断
		/* pass to the virutal socket layer */
		ret = nd_rcv(skb);//调用nd_recv，针对一个个独立有序组织好的ndhd包进行处理
		/* To Do: add hrtimer if fails to adding to the socket and break the loop; */
		// if(ret == -1) {
		// 	int sdif = inet_sdif(skb);
		// 	bool refcounted = false;
		// 	struct sock *vsk;
		// 	struct nd_sock *nsk;
		// 	struct ndt_channel_entry *entry;
		// 	WARN_ON(hrtimer_active(&ndt_queue->hol_timer));
		// 	// WARN_ON(ndt_queue->hol_skb);
		// 	nh =  nd_hdr(skb);
		// 	vsk = __nd_lookup_skb(&nd_hashinfo, skb, __nd_hdrlen(nh), nh->source,
		// 			nh->dest, sdif, &refcounted);
		// 	if(unlikely(!vsk)) {
		// 		kfree_skb(skb);
		// 		goto skip_vsk;
		// 	}
		// 	nsk = nd_sk(vsk);
		// 	entry = kmalloc(sizeof(struct ndt_channel_entry), GFP_ATOMIC);
		// 	if(!entry) {
		// 		WARN_ON(true);
		// 	}
		// 	entry->queue = ndt_queue;
		// 	INIT_LIST_HEAD(&entry->list_link);
		// 	/* get socket lock */
		// 	bh_lock_sock(vsk);
		// 	list_add_tail(&entry->list_link, &nsk->receiver.hol_channel_list);
	 	// 	test_and_set_bit(ND_CHANNEL_DEFERRED, &vsk->sk_tsq_flags);
		// 	bh_unlock_sock(vsk);
		// 	/* set the state of hrtimer and hol_skb */
		// 	spin_lock(&ndt_queue->hol_lock);
		// 	ndt_queue->hol_skb = skb;
		// 	hrtimer_start(&ndt_queue->hol_timer, ns_to_ktime(ndt_queue->hol_timeout_us *
		// 		NSEC_PER_USEC), HRTIMER_MODE_REL_PINNED_SOFT);
		// 	spin_unlock(&ndt_queue->hol_lock);
		// 	hol = true;
		// 	if(refcounted)
		// 		sock_put(vsk);
		// }
skip_vsk:
		local_bh_enable();
		if(hol)
			return - 1;
		//  } else {
		// 	pr_info("finish here:%d\n", __LINE__);
		//  	kfree_skb(skb);
		//  }
	}
	return 0;
push_back://之前的解析出了问题，直接塞回去重新解析
	// printk("push back skb\n");
	skb_queue_head(queue, skb);
	return 0;
}
