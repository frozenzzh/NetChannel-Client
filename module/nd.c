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
#include <linux/net.h>
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
#include <net/tcp.h>
#include <linux/cpufreq.h>
#include <linux/cpumask.h> // cpumask_{first,next}(), cpu_online_mask
#include <linux/delay.h>
#include <linux/sched.h>
// #include "linux_nd.h"
// #include "net_nd.h"
// #include "net_ndlite.h"
#include "uapi_linux_nd.h"
// struct udp_table nd_table __read_mostly;
// EXPORT_SYMBOL(nd_table);
#include "nd_host.h"
#include "nd_data_copy.h"
#include "nd_data_copy_sche.h"

extern int pre_pid;
extern int send_call_times;
extern bool is_1update;
extern bool is_2update;

long sysctl_nd_mem[3] __read_mostly;
EXPORT_SYMBOL(sysctl_nd_mem);

atomic_long_t nd_memory_allocated;
EXPORT_SYMBOL(nd_memory_allocated);

struct nd_params nd_params;//这里具体的数在nd_impl.h中被extern引用了，之后在nd_plumbing.c中的__init部分被初始化
EXPORT_SYMBOL(nd_params);

struct inet_hashinfo nd_hashinfo;
EXPORT_SYMBOL(nd_hashinfo);

#define MAX_ND_PORTS 65536
#define PORTS_PER_CHAIN (MAX_ND_PORTS / ND_HTABLE_SIZE_MIN)

#define MAX_PIN_PAGES 48
static bool local_copy_report=false;
static bool inflight_report=false;
static inline bool page_is_mergeable(const struct bio_vec *bv,
		struct page *page, unsigned int len, unsigned int off,
		bool *same_page)//?????
{
	size_t bv_end = bv->bv_offset + bv->bv_len;//页面中数据结尾在页面中的偏移量
	phys_addr_t vec_end_addr = page_to_phys(bv->bv_page) + bv_end - 1;//获取页面的物理地址
	//以上使用物理地址是因为有可能有不同的虚拟地址对应于同一个物理地址？？？
	phys_addr_t page_addr = page_to_phys(page);

	if (vec_end_addr + 1 != page_addr + off)//两个在地址上不连续，这里通常只考虑连续的顺序合并？？？
		return false;
	// if (xen_domain() && !xen_biovec_phys_mergeable(bv, page))
	// 	return false;
	//以下为地址连续的情况，判断是否在同一个页面中
	*same_page = ((vec_end_addr & PAGE_MASK) == page_addr);//判断bv的结束地址是否与page的开始地址在同一个页面中
	if (*same_page)
		return true;
	return (bv->bv_page + bv_end / PAGE_SIZE) == (page + off / PAGE_SIZE);
}

//__nd_try_merge_page(bv_arr, nr_segs, page, len, offset, &same_page)
//参数分别表示bio_vec数组，bio_vec数组的长度，新的页面，新的页面的长度，新的页面的偏移量，是否是同一个页面
bool __nd_try_merge_page(struct bio_vec *bv_arr, int nr_segs,  struct page *page,
		unsigned int len, unsigned int off, bool *same_page)//判断一个新的页面是否与之前的页面是同一个页面
{
	if (nr_segs > 0) {
		struct bio_vec *bv = &bv_arr[nr_segs - 1];

		if (page_is_mergeable(bv, page, len, off, same_page)) {
			// if (bio->bi_iter.bi_size > UINT_MAX - len) {
			// 	*same_page = false;
			// 	return false;
			// }
			bv->bv_len += len;//如果可以合并，更新上一个的长度
			return true;
		}
	}
	return false;
}

//blen = nd_dcopy_iov_init(msg, &biter, bv_arr, bsize, max_segs);
static ssize_t nd_dcopy_iov_init(struct msghdr *msg, struct iov_iter *iter, struct bio_vec *vec_p, u32 bytes, int max_segs) {
	//初始化 I/O 向量（I/O vector），用于远程数据复制过程，从msg中获取用户空间的数据，锁定（固定）这些数据所在的物理内存页，生成用于远程传输的 I/O 向量结构
	ssize_t copied, offset, left;
	struct bio_vec *bv_arr;
	struct page *pages[MAX_PIN_PAGES];
	unsigned nr_segs = 0, i, len = 0;
	bool same_page = false;

	// pr_info("reach here:%d\n",  __LINE__);
	// pages = kmalloc_array(max_segs, sizeof(struct page*), GFP_KERNEL);
	// WARN_ON(pages == NULL);
	// pr_info("size of pages*:%d\n",  sizeof(struct page*));
	// *vec_p = kmalloc_array(max_segs, sizeof(struct bio_vec), GFP_KERNEL);
	// WARN_ON(*vec_p == NULL);
	bv_arr = vec_p;
	// pr_info("reach here:%d\n",  __LINE__);

	copied = iov_iter_get_pages(&msg->msg_iter, pages, bytes, max_segs, &offset);
	//将msg->msg_iter所指向的页面固定在内核中，固定的页面用pages指针数组保存
	//返回值为实际获取的字节数量，之后被固定住的页面需要通过put_page进行手动释放
	// pr_info("reach here:%d\n",  __LINE__);
	if(copied < 0) WARN_ON(true);

	for (left = copied, i = 0; left > 0; left -= len, i++) {
		struct page *page = pages[i];

		len = min_t(size_t, PAGE_SIZE - offset, left);//计算当前页面剩余数据量，取当前页和总的剩余数据量的最小值

		if (__nd_try_merge_page(bv_arr, nr_segs, page, len, offset, &same_page)) {
			if (same_page)
				put_page(page);//如果是同一个页面，释放多余的页面
			// pr_info("merge page\n");
		} else {//不为同一个页面，新建一个bio_vec，具体为指向bv_arr末尾的一片空间，并在该空间上填充相应的信息
			struct bio_vec *bv = &bv_arr[nr_segs];
			bv->bv_page = page;
			bv->bv_offset = offset;
			bv->bv_len = len;
			nr_segs++;
		}
		offset = 0;//除了第一个页面之后offset为0
	}
	// pr_info("advance:%ld\n", copied);
	iov_iter_bvec(iter, WRITE, bv_arr, nr_segs, copied);//用于初始化iov_iter，使其能够表示一个bvec类型的I/O向量
	//将iov_iter结构体初始化为一个 bvec 类型的 I/O 向量迭代器
	
	iov_iter_advance(&msg->msg_iter, copied);//将msg_iter前进copied个字节，表示已经处理了copied个字节的数据
	// kfree(pages);
	// pr_info("kfree:%ld\n", __LINE__);

	return copied;
}

static inline bool nd_next_segment(struct bio_vec* bv_arr,
				    struct bvec_iter_all *iter, int max_segs)
{
	/*hard code for now */
	if (iter->idx >= max_segs)
		return false;

	bvec_advance(&bv_arr[iter->idx], iter);
	return true;
}

#define nd_for_each_segment_all(bvl, bv_arr, iter, max_segs) \
	for (bvl = bvec_init_iter_all(&iter); nd_next_segment((bv_arr), &iter, max_segs); )

void nd_release_pages(struct bio_vec* bv_arr, bool mark_dirty, int max_segs)
{
	struct bvec_iter_all iter_all;
	struct bio_vec *bvec;

	nd_for_each_segment_all(bvec, bv_arr, iter_all, max_segs) {
		if (mark_dirty && !PageCompound(bvec->bv_page))
			set_page_dirty_lock(bvec->bv_page);
		put_page(bvec->bv_page);//释放锁定的页面
	}
}

// u64 total_send_ack = 0;
// void nd_try_send_ack(struct sock *sk, int copied) {
// 	struct nd_sock *nsk = nd_sk(sk);
// 	u32 new_grant_nxt;
// 	// struct inet_sock *inet = inet_sk(sk);
// 	if(copied > 0) {
// 		new_grant_nxt = nd_window_size(nsk) + (u32)atomic_read(&nsk->receiver.rcv_nxt);
// 		if(new_grant_nxt - nsk->receiver.grant_nxt <= nsk->default_win && new_grant_nxt != nsk->receiver.grant_nxt && 
// 			new_grant_nxt - nsk->receiver.grant_nxt >= nsk->default_win / 16) {
// 			/* send ack pkt for new window */
// 			// printk("nd window size:%u\n",  nd_window_size(nsk));
// 			nsk->receiver.grant_nxt = new_grant_nxt;
// 			nd_conn_queue_request(construct_ack_req(sk, GFP_KERNEL), nsk, false, true, true);
// 			// pr_info("grant next update:%u\n", nsk->receiver.grant_nxt);
// 			// total_send_ack++;
// 		}
// 		// int grant_len = min_t(int, len, dsk->receiver.max_gso_data);
// 		// int available_space = nd_space(sk);
// 		// if(grant_len > available_space || grant_len < )
// 		// 	return;
// 		// printk("try to send ack \n");
// 	}
// }

void nd_clean_dcopy_pages(struct sock *sk) {
	struct nd_sock *nsk = nd_sk(sk);
	struct nd_dcopy_page *resp;
	struct llist_node *node;
	for (node = llist_del_all(&nsk->receiver.clean_page_list); node;) {
		resp = llist_entry(node, struct nd_dcopy_page, lentry);
		node = node->next;
		if(resp->bv_arr) {
			nd_release_pages(resp->bv_arr, true, resp->max_segs);
			kfree(resp->bv_arr);
		}
		if(resp->skb){
			kfree_skb(resp->skb);
			nsk->receiver.free_skb_num += 1;
		}
		kfree(resp);
	}
	return;
}

void nd_fetch_dcopy_response(struct sock *sk) {
	struct nd_sock *nsk = nd_sk(sk);
	struct nd_dcopy_response *resp;
	struct llist_node *node;
	for (node = llist_del_all(&nsk->sender.response_list); node;) {//遍历并且清空response_list
		resp = llist_entry(node, struct nd_dcopy_response, lentry);
		/* reuse tcp_rtx_queue due to the mess-up order */
		nd_rbtree_insert(&sk->tcp_rtx_queue, resp->skb);//将其插入到tcp_rtx_queue中，其中tcp_rtx_queue是一个红黑树
		node = node->next;
		sk_wmem_queued_add(sk, resp->skb->truesize);//马上将进入实际的发送环节，所以更新套接字已用内存计数
		// sk_mem_charge(sk, resp->skb->len);
		// printk("sk->sk_forward alloc:%d\n", sk->sk_forward_alloc);

		nsk->sender.pending_queue -= resp->skb->len;//pending_queue表示正在进行远程data_copy的字节数量，此处减去resp->skb->len表示已经完成了一个resp->skb->len的数据copy
		WARN_ON(nsk->sender.pending_queue < 0);
		kfree(resp);
		if(nd_params.nd_debug) {
			pr_info("push seq:%d\n", ND_SKB_CB(resp->skb)->seq);
		}
	}
	return;
}

static int sk_wait_data_copy(struct sock *sk, long *timeo)
{
	DEFINE_WAIT_FUNC(wait, woken_wake_function);
	int rc = 0;
	struct nd_sock* nsk = nd_sk(sk);
	while(atomic_read(&nsk->receiver.in_flight_copy_bytes) != 0) {
		nd_clean_dcopy_pages(sk);
		schedule();
		// schedule();
		// nd_try_send_ack(sk, 1);
		// add_wait_queue(sk_sleep(sk), &wait);
		// sk_set_bit(SOCKWQ_ASYNC_WAITDATA, sk);
		// rc = sk_wait_event(sk, timeo, atomic_read(&nsk->receiver.in_flight_copy_bytes) != 0, &wait);
		// sk_clear_bit(SOCKWQ_ASYNC_WAITDATA, sk);
		// remove_wait_queue(sk_sleep(sk), &wait);
	}
	nd_clean_dcopy_pages(sk);
	return rc;
}

static int sk_wait_sender_data_copy(struct sock *sk, long *timeo)
{
	DEFINE_WAIT_FUNC(wait, woken_wake_function);
	int rc= 0;
	struct nd_sock* nsk = nd_sk(sk);
	while(atomic_read(&nsk->sender.in_flight_copy_bytes) != 0) {
		nd_push(sk, GFP_KERNEL);//在轮询等待的时候不断读取之后的逻辑，也即将数据包继续放入网络层中进行处理
		// nd_fetch_dcopy_response(sk);
		schedule();
		// nd_try_send_ack(sk, 1);
		// add_wait_queue(sk_sleep(sk), &wait);
		// sk_set_bit(SOCKWQ_ASYNC_WAITDATA, sk);
		// rc = sk_wait_event(sk, timeo, atomic_read(&nsk->receiver.in_flight_copy_bytes) != 0, &wait);
		// sk_clear_bit(SOCKWQ_ASYNC_WAITDATA, sk);
		// remove_wait_queue(sk_sleep(sk), &wait);
	}
	return rc;
}

void nd_rbtree_insert(struct rb_root *root, struct sk_buff *skb)//依据序列号进行红黑树的插入
{
        struct rb_node **p = &root->rb_node;//p为指向一棵由指针构成的红黑树的指针
        struct rb_node *parent = NULL;
        struct sk_buff *skb1;

        while (*p) {
                parent = *p;
                skb1 = rb_to_skb(parent);
                if (before(ND_SKB_CB(skb)->seq, ND_SKB_CB(skb1)->seq))
                        p = &parent->rb_left;
                else
                        p = &parent->rb_right;
        }
        rb_link_node(&skb->rbnode, parent, p);//插入到红黑树中
        rb_insert_color(&skb->rbnode, root);//进行平衡
}

static void nd_rtx_queue_purge(struct sock *sk)
{
	struct rb_node *p = rb_first(&sk->tcp_rtx_queue);

	// nd_sk(sk)->highest_sack = NULL;
	while (p) {
		struct sk_buff *skb = rb_to_skb(p);

		p = rb_next(p);
		/* Since we are deleting whole queue, no need to
		 * list_del(&skb->tcp_tsorted_anchor)
		 */
		nd_rtx_queue_unlink(skb, sk);
		nd_wmem_free_skb(sk, skb);
	}
}

static void nd_ofo_queue_purge(struct sock *sk)
{
	struct nd_sock * dsk = nd_sk(sk);
	struct rb_node *p = rb_first(&dsk->out_of_order_queue);

	// nd_sk(sk)->highest_sack = NULL;
	while (p) {
		struct sk_buff *skb = rb_to_skb(p);

		p = rb_next(p);
		/* Since we are deleting whole queue, no need to
		 * list_del(&skb->tcp_tsorted_anchor)
		 */
		nd_ofo_queue_unlink(skb, sk);
		nd_rmem_free_skb(sk, skb);
	}
}

void nd_write_queue_purge(struct sock *sk)
{
	// struct nd_sock *dsk;
	struct sk_buff *skb;

	while ((skb = skb_dequeue(&sk->sk_write_queue)) != NULL) {
		nd_wmem_free_skb(sk, skb);
	}
	nd_rtx_queue_purge(sk);
	skb = sk->sk_tx_skb_cache;
	if (skb) {
		__kfree_skb(skb);
		sk->sk_tx_skb_cache = NULL;
	}
	// sk_mem_reclaim(sk);
}

void nd_read_queue_purge(struct sock* sk) {
	struct sk_buff *skb;
	while ((skb = __skb_dequeue(&sk->sk_receive_queue)) != NULL) {
		nd_rmem_free_skb(sk, skb);
	}
	nd_ofo_queue_purge(sk);
}

int nd_err(struct sk_buff *skb, u32 info)
{
	return 0;
	// return __nd4_lib_err(skb, info, &nd_table);
}

struct sk_buff* nd_dequeue_snd_q(struct sock *sk) {//取出一个数据包进行处理
	struct sk_buff *skb = NULL;
	struct nd_sock *nsk = nd_sk(sk);
	/* only one queue can be non-empty */
	WARN_ON(skb_peek(&sk->sk_write_queue) && rb_first(&sk->tcp_rtx_queue));
	//wriet_queue:发送队列，处理尚未发送的数据包
	//tcp_tx_queue：重传队列，处理已经发出，但是还没有收到ACK的包，当一个skb收到ACK之后会从重传队列中移除
	//为什么以上两个不能都有内容？？？？
	if(skb_peek(&sk->sk_write_queue)) {
		skb = skb_peek(&sk->sk_write_queue);
		ND_SKB_CB(skb)->seq = nsk->sender.write_seq;//更新序列号设置为当前的写序列号
		nsk->sender.write_seq += skb->len;//更新写序列号
		//实际上写序列号即为下一个要发送的包的序列号
		skb_dequeue(&sk->sk_write_queue);

	} else if(rb_first(&sk->tcp_rtx_queue)){
		struct rb_node *p = rb_first(&sk->tcp_rtx_queue);
		skb = rb_to_skb(p);
		if(nsk->sender.snd_una == ND_SKB_CB(skb)->seq) {
			//snd_una表示第一个未确认的包，这里是只要发出去就能保证确认了？？？？
			//un-ack的数据包恰好为当前的数据包序列号
			nsk->sender.snd_una += skb->len;//更新未确认序列号？？？？
			nd_rtx_queue_unlink(skb, sk);
		} else
			skb = NULL;
	}
	return skb;
}

bool nd_snd_q_ready(struct sock *sk) {//检测是否有数据需要发送，数据可能存在于发送队列（存储尚未发送的数据包sk_write_queue链表）和重传队列(存储乱序需要重传的数据包tcp_rtx_queue)中
	struct sk_buff *skb;

	if(skb_peek(&sk->sk_write_queue)) {//发送队列是否存在
		return true;
	}
	if(rb_first(&sk->tcp_rtx_queue)) {
		struct rb_node *p = rb_first(&sk->tcp_rtx_queue);
		skb = rb_to_skb(p);
		if(ND_SKB_CB(skb)->seq == nd_sk(sk)->sender.snd_nxt)//重传队列中头部的数据包恰好是下一个要重传的数据包
			return true;

	}
	return false;
}

int nd_push(struct sock *sk, gfp_t flag) {//将skb构造未nd_conn_request经过底层的发送队列发送掉
	struct inet_sock *inet = inet_sk(sk);
	struct sk_buff *skb;
	struct nd_sock *nsk = nd_sk(sk);
	bool push_success;
	struct nd_conn_request* req;
	struct ndhdr* hdr;
	int ret = 0;
	u32 seq;
	
	nd_fetch_dcopy_response(sk);//将之前data_copy完成的表示data_copy_response list push到红黑树sk->tcp_rtx_queue中
	while(nd_snd_q_ready(sk) || nsk->sender.pending_req) {

		if(nsk->sender.pending_req) {//有之前未处理的挂起conn_request，直接进入queue_req
			WARN_ON(nsk->sender.pending_req == NULL);
			req = nsk->sender.pending_req;
			nsk->sender.pending_req = NULL;
			skb = req->skb;
			goto queue_req;
		}

		/* construct nd_conn_request */
		skb = nd_dequeue_snd_q(sk);
		/* out-of-order pkt */
		if(skb == NULL) {
			return  -EMSGSIZE;
		}
		req = kzalloc(sizeof(*req), flag);
		if(!req) {
			WARN_ON(true);
		}

		if(skb->len == 0 || skb->data_len == 0) {
			WARN_ON(true);
		}
		nd_init_request(sk, req);//分配conn_request以及req->hdr的内存空间，并初始化conn_request的优先级信息
		req->state = ND_CONN_SEND_CMD_PDU;
		// req->pdu_len = sizeof(struct ndhdr) + skb->len;
		// req->data_len = skb->len;
		hdr = req->hdr;
	// struct sk_buff* skb = __construct_control_skb(sk, 0);
	// struct nd_flow_sync_hdr* fh;
	// struct ndhdr* dh; 
	// if(unlikely(!req || !sync)) {
	// 	return -N;
	// }
	// fh = (struct nd_flow_sync_hdr *) skb_put(skb, sizeof(struct nd_flow_sync_hdr));
	
	// dh = (struct ndhdr*) (&sync->common);
		// pr_info("skb->data_len:%d\n", skb->data_len);
		// pr_info(" htons(skb->len):%d\n",  htons(skb->len));

		req->skb = skb;

		hdr->len = htons(skb->len);//头部实现了一个简单的TCP的功能，len表示skb的长度
		hdr->type = DATA;//类型未DATA
		hdr->source = inet->inet_sport;//地址表示源端口号和目的端口号
		hdr->dest = inet->inet_dport;
		// hdr->check = 0;
		hdr->doff = (sizeof(struct ndhdr)) << 2;//高4位表示数据的偏移量，为了和TCP头部保持一致这样设置
		hdr->seq = htonl(ND_SKB_CB(skb)->seq);
		// skb_dequeue(&sk->sk_write_queue);
			// kfree_skb(skb);
		sk_wmem_queued_add(sk, -skb->truesize);//truesize表示总长度，包含头部和有效负载，减少发送缓冲区计时器用于流量控制
		// sk_mem_uncharge(sk, skb->truesize);
		WARN_ON(nsk->sender.snd_nxt != ND_SKB_CB(skb)->seq);
		nsk->sender.snd_nxt += skb->len;//更新发送端要发送的下一个序列号
		// if(ND_SKB_CB(skb)->seq == 0)
		// 	skb_dump(KERN_WARNING, skb, true);

		// sk->sk_wmem_queued -= skb->len;
		/*increment write seq */
		// nsk->sender.write_seq += skb->len;
queue_req:
		/* check the window is available */
		// if(nsk->sender.sd_grant_nxt - (ND_SKB_CB(skb)->seq + skb->len) > nsk->default_win) {
		// 	WARN_ON(nsk->sender.pending_req);
		// 	// if(ntohs(inet->inet_dport) == 4000) {
		// 	// 	printk("window is insufficient:%d %d \n", (ND_SKB_CB(skb)->seq), nsk->sender.sd_grant_nxt);
		// 	// }
		// 	// WARN_ON(nsk->sender.sd_grant_nxt - (ND_SKB_CB(skb)->seq + skb->len) < (1<<30));
		// 	if(nd_params.nd_debug) {
		// 		pr_info("nsk->sender.sd_grant_nxt:%u\n", nsk->sender.sd_grant_nxt);
		// 		pr_info(" (ND_SKB_CB(skb)->seq + skb->len):%u\n",  (ND_SKB_CB(skb)->seq + skb->len));
		// 	}
		// 	nsk->sender.pending_req = req;
		// 	ret = -EMSGSIZE;
		// 	break;
		// }
		seq = ND_SKB_CB(skb)->seq + skb->len;//更新seq
		/* queue the request */
		// req->queue = &nd_ctrl->queues[htons(inet->inet_sport) % nd_params.nd_num_queue];
		push_success = nd_conn_queue_request(req, nsk, false, false, !nd_snd_q_ready(sk));
		if(!push_success) {
			WARN_ON(nsk->sender.pending_req);
			// pr_info("add to sleep sock:%d\n", __LINE__);
			nsk->sender.pending_req = req;//发送失败，将请求挂起等待下次再发
			ret = -EDQUOT;
			break;
		}
		nsk->sender.snd_nxt = seq;//更行下一次发送的报文的seq
		// printk(" dequeue forward alloc:%d\n", sk->sk_forward_alloc);
	}
	return ret;
}

void nd_tx_work(struct work_struct *w)//？？？和之前的调度的关系是什么呢？？？
{
	struct nd_sock *nsk = container_of(w, struct nd_sock, tx_work);
	struct sock *sk = (struct sock*)nsk;
	int err;
	lock_sock(sk);
	if(sk->sk_state == TCP_CLOSE) {
		 goto out;
	}
	/* Primarily for SOCK_DGRAM sockets, also handle asynchronous tx
	 * aborts
	 */
	err = nd_push(sk, GFP_KERNEL);
	/* Primarily for SOCK_SEQPACKET sockets */
	if (likely(sk->sk_socket)) {
		if(sk_stream_memory_free(sk)) {
			sk->sk_write_space(sk);
		} 
		if(err == -EDQUOT){
			/* push back since there is no space */
			nd_conn_add_sleep_sock(nsk->nd_ctrl, nsk);
		}
	} 	
out:
	release_sock(sk);
}

static inline bool nd_stream_memory_free(const struct sock *sk, int pending)//检测是否有足够的缓冲区用于发送数据
{
	/* this is roung calc, since pending queue only consider payload */
	if (READ_ONCE(sk->sk_wmem_queued) + pending >= READ_ONCE(sk->sk_sndbuf))
	//sk->sk_wmem_queued当前套接字已经分配的发送缓冲区大小，pending等待发送的数据大小，sk->sk_sndbuf套接字发送缓冲区上限
		return false;

	return true;
}
/* copy from kcm sendmsg */
static int nd_sender_local_dcopy(struct sock* sk, struct msghdr *msg, int req_len, u32 seq, long timeo) {
	//负责将msghdr 消息结构中复制数据到内核的 sk_buff 中
	struct sk_buff *skb = NULL;
	struct nd_sock *nsk = nd_sk(sk);
	struct nd_dcopy_response *resp;
	size_t copy;
	int err, i = 0;
	while (req_len > 0) {
		bool merge = true;
		struct page_frag *pfrag = sk_page_frag(sk);//从sock关联的内存中分配一部分出来
		if (!sk_page_frag_refill(sk, pfrag))//如果当前的页片段（page_frag）中的可用内存不足，sk_page_frag_refill 会尝试分配新的内存页，并更新page_frag结构的状态
			goto wait_for_memory;
		if(!skb) 
			goto create_new_skb;
		if(skb->len == ND_MAX_SKB_LEN)//有效负载总长度达到上限，进行push操作，同时将当前的skb置为NULL
			goto push_skb;
		i = skb_shinfo(skb)->nr_frags;
		if (!skb_can_coalesce(skb, i, pfrag->page, pfrag->offset)) {//查看当前的碎片能否和skb的shinfo中的内存页末尾进行合并
			if (i == MAX_SKB_FRAGS) {
				goto push_skb;
			}
			merge = false;
		}
		copy = min_t(int, ND_MAX_SKB_LEN - skb->len, req_len);
		copy = min_t(int, copy, pfrag->size - pfrag->offset);
		
		err = nd_copy_to_page_nocache(sk, &msg->msg_iter, skb,
					       pfrag->page,
					       pfrag->offset,
					       copy);
		if (err)
			goto out_error;
		/* Update the skb. */
		if (merge) {
			skb_frag_size_add(&skb_shinfo(skb)->frags[i - 1], copy);
		} else {
			skb_fill_page_desc(skb, i, pfrag->page, pfrag->offset, copy);
			get_page(pfrag->page);
		}
		pfrag->offset += copy;
		req_len -= copy;
		/* last request */
		if(req_len == 0)
			goto push_skb;
		continue;

create_new_skb:
		WARN_ON(skb != NULL);
		skb = alloc_skb(0, sk->sk_allocation);
		skb->ip_summed = CHECKSUM_PARTIAL;//数据包的校验和已经由硬件或其他层计算完成
		// printk("create new skb\n");
		if(!skb)
			goto wait_for_memory;
		continue;

push_skb:
		/* push the new skb */
		ND_SKB_CB(skb)->seq = seq;
		resp = kmalloc(sizeof(struct nd_dcopy_response), GFP_KERNEL);//分配一个相应结构体
		resp->skb = skb;
		//也就是说，实际发送的数据存储在skb的shinfo_list中，而skb被放在了nd_dcopy_response中，
		//nd_dcopy_response被组织成了一个sender.response_list中
		llist_add(&resp->lentry, &nsk->sender.response_list);
		seq += skb->len;
		nsk->sender.pending_queue += skb->len;//表示等待队列的长度吗？？？
		// if(skb && ntohs(inet->inet_dport) == 4000)
		// printk("data copy: %d \n", (ND_SKB_CB(skb)->seq));
		skb = NULL;
		resp = NULL;
		continue;
wait_for_memory:
		/* wait for pending requests to be done */
		sk_wait_sender_data_copy(sk, &timeo);
		// nd_fetch_dcopy_response(sk);
		err = nd_push(sk, GFP_KERNEL);//当前的data_copy完成之后继续将内容下方到网络层中进行处理
		WARN_ON(nsk->sender.pending_queue != 0);//此处表示等待处理的数据量pending_queue应当为空
		// set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
		/* hard code nd_ctrl for now */
		if(err == -EDQUOT){//资源耗尽，将当前套接字添加到对应的等待队列中
			// pr_info("add to sleep sock send msg\n");
			nd_conn_add_sleep_sock(nsk->nd_ctrl, nsk);
		} 
		err = sk_stream_wait_memory(sk, &timeo);//阻塞等待资源释放或者超时
		// pr_info("end wait \n");
		if (err) {
			goto out_error;
		}
	}
	return 0;
out_error:
	/* To Do: need to check whether kfree_skb should be called */
	if(skb) {//不为空的话仍然放到dcopy_resp_list中等待处理
		ND_SKB_CB(skb)->seq = seq;
		resp = kmalloc(sizeof(struct nd_dcopy_response), GFP_KERNEL);
		resp->skb = skb;
		llist_add(&resp->lentry, &nsk->sender.response_list);
		seq += skb->len;
		nsk->sender.pending_queue += skb->len;
		skb = NULL;
		resp = NULL;
	}

	return err;
}

static inline bool nd_wmem_schedule(struct sock *sk, int size)
{
	if (!sk_has_account(sk))
		return true;
	return __sk_mem_schedule(sk, size, SK_MEM_SEND);
}

static int nd_sendmsg_new2_locked(struct sock *sk, struct msghdr *msg, size_t len)
{
	struct nd_sock *nsk = nd_sk(sk);
	// struct sk_buff *skb = NULL;
	size_t copy, copied = 0;
	long timeo = sock_sndtimeo(sk, msg->msg_flags & MSG_DONTWAIT);//获取超时时间
	int eor = (sk->sk_socket->type == SOCK_DGRAM) ?
		  !(msg->msg_flags & MSG_MORE) : !!(msg->msg_flags & MSG_EOR);//根据不同的消息类型，判断是否是最后一个消息
	int err = -EPIPE;// 表示"Broken pipe" 错误，表示向一端已经关闭的管道或套接字写数据
	// int i = 0;
	/* hardcode for now */
	struct nd_dcopy_request *request;
	struct iov_iter biter;
	struct bio_vec *bv_arr = NULL;
	// ssize_t bremain = msg->iter->count, blen;
	ssize_t blen;
	int max_segs = MAX_PIN_PAGES;
	int nr_segs = 0;
	int next_cpu = 0;
	// int pending = 0;
	WARN_ON(msg->msg_iter.count != len);
	if ((1 << sk->sk_state) & ~(NDF_ESTABLISH)) {//检查是否建立连接
		err = nd_wait_for_connect(sk, &timeo);
		if (err != 0) goto out_error;
	}
	/* Per tcp_sendmsg this should be in poll */
	sk_clear_bit(SOCKWQ_ASYNC_NOSPACE, sk);//清除套接字写队列已满标志位

	if (sk->sk_err)	goto out_error;

	/* intialize the nxt_dcopy_cpu */
	nsk->sender.nxt_dcopy_cpu = nd_params.data_cpy_core;

	while (msg_data_left(msg)) {

		if (!nd_stream_memory_free(sk, nsk->sender.pending_queue)) {//检查是否有足够内存空间发送
			// set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
			goto wait_for_memory;
		}

		/* this part might need to change latter */
		/* decide to do local or remote data copy */
		copy = min_t(int, max_segs * PAGE_SIZE / ND_MAX_SKB_LEN * ND_MAX_SKB_LEN, msg_data_left(msg));
		//为什么要除了ND_MAX_SKB_LEN又乘上去？？？起一个取整的作用吗
		if(copy == 0) {
			WARN_ON(true);
		}

		// if (!nd_wmem_schedule(sk, copy)) {
		// 	WARN_ON_ONCE(true);
		// 	goto wait_for_memory;

		// } 
		if(atomic_read(&nsk->sender.in_flight_copy_bytes) > nd_params.ldcopy_tx_inflight_thre || 
			copied <  nd_params.ldcopy_min_thre || nd_params.nd_num_dc_thread == 0) {
			if (inflight_report==false) {
				pr_info("NetChannel: sender.in_flight_copy_bytes=%d, ldcopy_tx_inflight_thre=%d, ldcopy_min_thre=%d", 
				atomic_read(&nsk->sender.in_flight_copy_bytes), nd_params.ldcopy_tx_inflight_thre, nd_params.ldcopy_min_thre);
				inflight_report = true;
			}
			goto local_sender_copy;
			//仍然为三个条件：正在传输的数据字节数是否超过了限制
			//本地copy的字节数是否还小于阈值
			//是否支持remote_data_copy
		}
		next_cpu = nd_dcopy_sche_rr(nsk->sender.nxt_dcopy_cpu);
		if(next_cpu == -1) {
			/* data copy worker threads are all busy */
			goto local_sender_copy;
		} else
			nsk->sender.nxt_dcopy_cpu = next_cpu;
		/* remote data copy */
		/* construct biov and data copy request */
		bv_arr = kmalloc(MAX_PIN_PAGES * sizeof(struct bio_vec), GFP_KERNEL);
		blen = nd_dcopy_iov_init(msg, &biter, bv_arr, copy, max_segs);
		nr_segs = biter.nr_segs;
		nsk->sender.pending_queue += blen;//pending_queue表示等待队列的长度
		if(blen < copy) {
			// sk_mem_charge(sk, copy - blen);
			// printk("wmem schedule 2: %d\n", sk->sk_forward_alloc);

		} else {
			WARN_ON_ONCE(blen != copy);
		}
		/* create new request */
		request = kzalloc(sizeof(struct nd_dcopy_request) ,GFP_KERNEL);
		request->state = ND_DCOPY_SEND;
		request->sk = sk;
		request->io_cpu = nsk->sender.nxt_dcopy_cpu;
		request->len = blen;
		request->remain_len = blen;
		request->seq = nsk->sender.write_seq;
		request->iter = biter;
		request->bv_arr = bv_arr;
		request->max_segs = nr_segs;
		
		nd_dcopy_queue_request(request);

		bv_arr = NULL;
		nr_segs = 0;
		atomic_add(blen, &nsk->sender.in_flight_copy_bytes);
		nsk->sender.write_seq += blen;
		copied += blen;
		continue;

local_sender_copy:
		// copy = min_t(int, ND_MAX_SKB_LEN, msg_data_left(msg));
		// if(copy == 0) {
		// 	WARN_ON(true);
		// }
		// if (!sk_wmem_schedule(sk, copy)) {
		// 	WARN_ON_ONCE(true);
		// 	goto wait_for_memory;

		// }
// local_sender_copy_skip_schedule:
		if (local_copy_report==false) {
			pr_info("NetChannel: Error, should not use local copy in send!\n");
			local_copy_report = true;
		}
		err = nd_sender_local_dcopy(sk, msg, copy, nsk->sender.write_seq, timeo);
		if(err != 0)
			goto out_error;
		nsk->sender.write_seq += copy;
		copied += copy;
		if(eor) {
			err = nd_push(sk, GFP_KERNEL);//当最后一个消息处理完毕时push到网络层进行处理
		}
		if(READ_ONCE(sk->sk_backlog.tail) && nsk->sender.snd_una > nsk->sender.sd_grant_nxt) {
			//backlog中有待处理的数据，并且发送窗口已经满了，释放锁并且暂停处理逻辑？？？
			release_sock(sk);
			lock_sock(sk);
		}
		continue;
wait_for_memory:
		/* wait for pending requests to be done */
		sk_wait_sender_data_copy(sk, &timeo);
		// nd_fetch_dcopy_response(sk);
		err = nd_push(sk, GFP_KERNEL);
		WARN_ON(nsk->sender.pending_queue != 0);
		// set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
		/* hard code nd_ctrl for now */
		if(err == -EDQUOT){
			// pr_info("add to sleep sock send msg\n");
			nd_conn_add_sleep_sock(nsk->nd_ctrl, nsk);
		} 
		err = sk_stream_wait_memory(sk, &timeo);
		// pr_info("end wait \n");
		if (err) {
			goto out_error;
		}
	}
	sk_wait_sender_data_copy(sk, &timeo);
	// nd_fetch_dcopy_response(sk);
	if (eor) {//如果已经是最后一部分消息，push到网络层进行处理
		// if(!skb_queue_empty(&sk->sk_write_queue)) {
			err = nd_push(sk, GFP_KERNEL);
			if(err == -EDQUOT){
				// pr_info("add to sleep sock send msg\n");
				nd_conn_add_sleep_sock(nsk->nd_ctrl, nsk);
			} 
		// }
	}

	// ND_STATS_ADD(nsk->stats.tx_bytes, copied);
	release_sock(sk);
	return copied;

out_error:
	/* wait for pending requests to be done */
	sk_wait_sender_data_copy(sk, &timeo);
	/* ToDo: might need to wait as well */
	// nd_push(sk);

	// if (copied && sock->type == SOCK_SEQPACKET) {
	// 	/* Wrote some bytes before encountering an
	// 	 * error, return partial success.
	// 	 */
	// 	goto partial_message;
	// }

	// if (head != nsk->seq_skb)
	// 	kfree_skb(head);

	err = sk_stream_error(sk, msg->msg_flags, err);

	/* make sure we wake any epoll edge trigger waiter */
	if (unlikely(skb_queue_len(&sk->sk_write_queue) == 0 && err == -EAGAIN))//发送队列为空但是可以重试
		sk->sk_write_space(sk);

	return err;
}

static int nd_sendmsg_new_locked(struct sock *sk, struct msghdr *msg, size_t len)
{
	struct nd_sock *nsk = nd_sk(sk);
	// struct sk_buff *skb = NULL;
	size_t copy, copied = 0;
	long timeo = sock_sndtimeo(sk, msg->msg_flags & MSG_DONTWAIT);
	int eor = (sk->sk_socket->type == SOCK_DGRAM) ?
		  !(msg->msg_flags & MSG_MORE) : !!(msg->msg_flags & MSG_EOR);
	int err = -EPIPE;
	// int i = 0;
	
	/* hardcode for now */
	struct nd_dcopy_request *request;
	struct iov_iter biter;
	struct bio_vec *bv_arr = NULL;
	// ssize_t bremain = msg->iter->count, blen;
	ssize_t blen;
	int max_segs = MAX_PIN_PAGES;
	int nr_segs = 0;
	int next_cpu = 0;
	// int pending = 0;
	WARN_ON(msg->msg_iter.count != len);
	if ((1 << sk->sk_state) & ~(NDF_ESTABLISH)) {
		err = nd_wait_for_connect(sk, &timeo);
		if (err != 0)
			goto out_error;
	}
	/* Per tcp_sendmsg this should be in poll */
	sk_clear_bit(SOCKWQ_ASYNC_NOSPACE, sk);

	if (sk->sk_err)
		goto out_error;
	nsk->sender.nxt_dcopy_cpu =  nd_params.data_cpy_core;
	while (msg_data_left(msg)) {

		if (!nd_stream_memory_free(sk, nsk->sender.pending_queue)) {
			// set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
			goto wait_for_memory;
		}

		/* this part might need to change latter */
		copy = min_t(int, max_segs * PAGE_SIZE / ND_MAX_SKB_LEN * ND_MAX_SKB_LEN, msg_data_left(msg));
		if(copy == 0) {
			WARN_ON(true);
		}
		if (!sk_wmem_schedule(sk, copy)) {
			WARN_ON_ONCE(true);
			goto wait_for_memory;

		}
		/* construct biov and data copy request */
		bv_arr = kmalloc(MAX_PIN_PAGES * sizeof(struct bio_vec), GFP_KERNEL);
		blen = nd_dcopy_iov_init(msg, &biter, bv_arr, copy, max_segs);
		nr_segs = biter.nr_segs;
		nsk->sender.pending_queue += blen;

		/* create new request */
		request = kzalloc(sizeof(struct nd_dcopy_request) ,GFP_KERNEL);
		request->state = ND_DCOPY_SEND;
		request->sk = sk;
		request->io_cpu = nsk->sender.nxt_dcopy_cpu;
		request->len = blen;
		request->remain_len = blen;
		request->seq = nsk->sender.write_seq;
		request->iter = biter;
		request->bv_arr = bv_arr;
		request->max_segs = nr_segs;
		
		nd_dcopy_queue_request(request);

		bv_arr = NULL;
		nr_segs = 0;
		atomic_add(blen, &nsk->sender.in_flight_copy_bytes);
		nsk->sender.write_seq += blen;

		copied += blen;
		
		next_cpu = nd_dcopy_sche_rr(nsk->sender.nxt_dcopy_cpu);
		if(next_cpu != -1)
			nsk->sender.nxt_dcopy_cpu = next_cpu;
		continue;

wait_for_memory:
		/* wait for pending requests to be done */
		sk_wait_sender_data_copy(sk, &timeo);
		// nd_fetch_dcopy_response(sk);
		err = nd_push(sk, GFP_KERNEL);
		WARN_ON(nsk->sender.pending_queue != 0);
		// set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
		/* hard code nd_ctrl for now */
		if(err == -EDQUOT){
			// pr_info("add to sleep sock send msg\n");
			nd_conn_add_sleep_sock(nsk->nd_ctrl, nsk);
		} 
		err = sk_stream_wait_memory(sk, &timeo);
		// pr_info("end wait \n");
		if (err) {
			goto out_error;
		}
	}
	sk_wait_sender_data_copy(sk, &timeo);
	// nd_fetch_dcopy_response(sk);
	if (eor) {
		// if(!skb_queue_empty(&sk->sk_write_queue)) {
			// printk("call nd push\n");
			err = nd_push(sk, GFP_KERNEL);
		// }
	}

	// ND_STATS_ADD(nsk->stats.tx_bytes, copied);

	release_sock(sk);
	return copied;

out_error:
	/* wait for pending requests to be done */
	sk_wait_sender_data_copy(sk, &timeo);
	/* ToDo: might need to wait as well */
	// nd_push(sk);

	// if (copied && sock->type == SOCK_SEQPACKET) {
	// 	/* Wrote some bytes before encountering an
	// 	 * error, return partial success.
	// 	 */
	// 	goto partial_message;
	// }

	// if (head != nsk->seq_skb)
	// 	kfree_skb(head);

	err = sk_stream_error(sk, msg->msg_flags, err);

	/* make sure we wake any epoll edge trigger waiter */
	if (unlikely(skb_queue_len(&sk->sk_write_queue) == 0 && err == -EAGAIN))
		sk->sk_write_space(sk);

	return err;
}

/* copy from kcm sendmsg */
static int nd_sendmsg_locked(struct sock *sk, struct msghdr *msg, size_t len)
{
	struct nd_sock *nsk = nd_sk(sk);
	struct sk_buff *skb = NULL;
	size_t copy, copied = 0;
	long timeo = sock_sndtimeo(sk, msg->msg_flags & MSG_DONTWAIT);
	/* SOCK DGRAM? */
	// timeo = 20000;
	// printk("timeo:%ld\n", timeo);
	// printk("long max:%ld\n", LONG_MAX);
	int eor = (sk->sk_socket->type == SOCK_DGRAM) ?
		  !(msg->msg_flags & MSG_MORE) : !!(msg->msg_flags & MSG_EOR);
	int err = -EPIPE;
	int i = 0;
	
	if ((1 << sk->sk_state) & ~(NDF_ESTABLISH)) {
		err = nd_wait_for_connect(sk, &timeo);
		if (err != 0)
			goto out_error;
	}
	/* Per tcp_sendmsg this should be in poll */
	sk_clear_bit(SOCKWQ_ASYNC_NOSPACE, sk);

	if (sk->sk_err)
		goto out_error;

	while (msg_data_left(msg)) {
		bool merge = true;
		struct page_frag *pfrag = sk_page_frag(sk);
		if (!sk_page_frag_refill(sk, pfrag))
			goto wait_for_memory;
		skb = nd_write_queue_tail(sk);
		if(!skb || skb->len == ND_MAX_SKB_LEN) 
			goto create_new_skb;
		i = skb_shinfo(skb)->nr_frags;
		if (!skb_can_coalesce(skb, i, pfrag->page,
			 pfrag->offset)) {
			if (i == MAX_SKB_FRAGS) {
				goto create_new_skb;
			}
			merge = false;
		}
		copy = min_t(int, ND_MAX_SKB_LEN - skb->len, msg_data_left(msg));
		copy = min_t(int, copy,
			     pfrag->size - pfrag->offset);
		
		if(copy == 0) {
			WARN_ON(true);
			pr_info("skb->len: %d\n",skb->len);
			pr_info("msg_data_left(msg): %ld\n",msg_data_left(msg));
			pr_info("pfrag->size - pfrag->offset: %d\n", pfrag->size - pfrag->offset);

		}
		if (!sk_wmem_schedule(sk, copy))
			goto wait_for_memory;

		err = skb_copy_to_page_nocache(sk, &msg->msg_iter, skb,
					       pfrag->page,
					       pfrag->offset,
					       copy);
		if (err)
			goto out_error;
		/* Update the skb. */
		if (merge) {
			skb_frag_size_add(&skb_shinfo(skb)->frags[i - 1], copy);
		} else {
			skb_fill_page_desc(skb, i, pfrag->page,
					   pfrag->offset, copy);
			get_page(pfrag->page);
		}
		pfrag->offset += copy;
		copied += copy;

		continue;

create_new_skb:
		if (!sk_stream_memory_free(sk)) {
			// set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
			goto wait_for_memory;
		}
		skb = alloc_skb(0, sk->sk_allocation);
		// printk("create new skb\n");
		if(!skb)
			goto wait_for_memory;
		/* add truesize of skb */
		sk_wmem_queued_add(sk, skb->truesize);
		sk_mem_charge(sk, skb->truesize);
		__skb_queue_tail(&sk->sk_write_queue, skb);
		continue;


wait_for_memory:
		err = nd_push(sk, GFP_KERNEL);
		// pr_info("start wait \n");
		// pr_info("timeo:%ld\n", timeo);
		// set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
		/* hard code nd_ctrl for now */
		if(err == -EDQUOT){
			// pr_info("add to sleep sock send msg\n");
			nd_conn_add_sleep_sock(nsk->nd_ctrl, nsk);
		} 
		// else {
		// 	pr_info("nsk->sender.sd_grant_nxt:%u\n", nsk->sender.sd_grant_nxt);
		// 	pr_info("nsk->sender.write_seq:%u\n", nsk->sender.write_seq);
		// }
		err = sk_stream_wait_memory(sk, &timeo);
		// pr_info("end wait \n");
		if (err) {
			pr_info("out error \n");
			goto out_error;
		}
	}
	if (eor) {
		if(!skb_queue_empty(&sk->sk_write_queue)) {
			// printk("call nd push\n");
			nd_push(sk, GFP_KERNEL);
		}
	}

	// ND_STATS_ADD(nsk->stats.tx_bytes, copied);

	release_sock(sk);
	return copied;

out_error:
	// nd_push(sk);

	// if (copied && sock->type == SOCK_SEQPACKET) {
	// 	/* Wrote some bytes before encountering an
	// 	 * error, return partial success.
	// 	 */
	// 	goto partial_message;
	// }

	// if (head != nsk->seq_skb)
	// 	kfree_skb(head);

	err = sk_stream_error(sk, msg->msg_flags, err);

	/* make sure we wake any epoll edge trigger waiter */
	if (unlikely(skb_queue_len(&sk->sk_write_queue) == 0 && err == -EAGAIN))
		sk->sk_write_space(sk);

	return err;
}

int nd_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
{
	int ret = 0;
	lock_sock(sk);
	int curr_pid=current->pid;//获得当前进程的pid
	if (curr_pid != pre_pid) {
		pre_pid = curr_pid;
		send_call_times=1;
		is_1update=false;
		is_2update=false;
	} else if ((send_call_times==1)||(send_call_times==2)) send_call_times++;
	// nd_rps_record_flow(sk);
	ret = nd_sendmsg_new2_locked(sk, msg, len);
	release_sock(sk);//解锁套接字，允许其他线程继续使用该套接字
	return ret;
}
EXPORT_SYMBOL(nd_sendmsg);

int nd_sendpage(struct sock *sk, struct page *page, int offset, size_t size, int flags)
{
	printk(KERN_WARNING "unimplemented sendpage invoked on nd socket\n");
	return -ENOSYS;
}


void nd_destruct_sock(struct sock *sk)
{

	/* reclaim completely the forward allocated memory */
	// unsigned int total = 0;
	struct nd_sock *nsk = nd_sk(sk);
	// struct sk_buff *skb;
	// struct udp_hslot* hslot = udp_hashslot(sk->sk_prot->h.udp_table, sock_net(sk),
	// 				     nd_sk(sk)->nd_port_hash);
	/* clean the message*/
	// skb_queue_splice_tail_init(&sk->sk_receive_queue, &dsk->reader_queue);
	// while ((skb = __skb_dequeue(&dsk->reader_queue)) != NULL) {
	// 	total += skb->truesize;
	// 	kfree_skb(skb);
	// }
	WARN_ON(nsk->sender.pending_req);
	// pr_info("0: %llu\n", bytes_recvd[0]);
	// pr_info("4: %llu\n", bytes_recvd[4]);
	// pr_info("8: %llu\n", bytes_recvd[8]);

	// pr_info("max queue length:%d\n", max_queue_length);
	// pr_info("dsk->receiver.copied_seq:%u\n", (u32)atomic_read(&dsk->receiver.copied_seq));
	// pr_info("nsk->sender.snd_nxt:%u\n", (u32)(nsk->sender.snd_nxt));
	// pr_info("nsk->sender.snd_una:%u\n", (u32)(nsk->sender.snd_una));
	// pr_info("atomic_read(&sk->sk_rmem_alloc):%d\n", atomic_read(&sk->sk_rmem_alloc));
	// pr_info("total_send_ack:%llu\n", total_send_ack);
	// pr_info("total_send_grant:%llu\n", total_send_grant);
	/* clean sk_forward_alloc*/
	sk_mem_reclaim(sk);

	// sk->sk_forward_alloc = 0;
	// nd_rmem_release(sk, total, 0, true);
	inet_sock_destruct(sk);
	// printk("sk_memory_allocated:%ld\n", sk_memory_allocated(sk));

	/* unclear part */
	// printk("sk_memory_allocated:%ld\n", sk_memory_allocated(sk));

}
EXPORT_SYMBOL_GPL(nd_destruct_sock);

int nd_init_sock(struct sock *sk)
{
	struct nd_sock* dsk = nd_sk(sk);
	nd_set_state(sk, TCP_CLOSE);//设置套接字状态
	skb_queue_head_init(&nd_sk(sk)->reader_queue);//初始化reader_queue
	dsk->core_id = raw_smp_processor_id();//创建并初始化该套接字的CPU id
	// initialize the ready queue and its lock
	sk->sk_destruct = nd_destruct_sock;//回收函数
	// sk->sk_write_space = sk_stream_write_space;
	dsk->unsolved = 0;
	// WRITE_ONCE(dsk->num_sacks, 0);


	/* initialize the sndbuf and rcvbuf */
	WRITE_ONCE(sk->sk_sndbuf, nd_params.wmem_default);
	WRITE_ONCE(sk->sk_rcvbuf, nd_params.rmem_default);
	WRITE_ONCE(dsk->default_win , min_t(uint32_t, nd_params.bdp, READ_ONCE(sk->sk_rcvbuf)));//初始窗口大小，为接收缓冲区与bdp的较小值

	// INIT_LIST_HEAD(&dsk->match_link);
	INIT_WORK(&dsk->tx_work, nd_tx_work);//设置发送工作队列函数
	INIT_LIST_HEAD(&dsk->tx_wait_list);
	WRITE_ONCE(dsk->sender.wait_cpu, 0);
	WRITE_ONCE(dsk->sender.wait_on_nd_conns, false);
	WRITE_ONCE(dsk->sender.wait_queue, NULL);
	WRITE_ONCE(dsk->sender.write_seq, 0);
	WRITE_ONCE(dsk->sender.snd_nxt, 0);
	WRITE_ONCE(dsk->sender.snd_una, 0);
	WRITE_ONCE(dsk->sender.pending_req, NULL);
	WRITE_ONCE(dsk->sender.nxt_dcopy_cpu, -1);	
	WRITE_ONCE(dsk->sender.pending_queue, 0);
    init_llist_head(&dsk->sender.response_list);
	WRITE_ONCE(dsk->sender.sd_grant_nxt, dsk->default_win);
	WRITE_ONCE(dsk->sender.con_queue_id, 0);
	WRITE_ONCE(dsk->sender.con_accumu_count, 0);

	atomic_set(&dsk->receiver.rcv_nxt, 0);
	WRITE_ONCE(dsk->receiver.last_ack, 0);
	atomic_set(&dsk->receiver.copied_seq, 0);
	WRITE_ONCE(dsk->receiver.grant_nxt, dsk->default_win);
	WRITE_ONCE(dsk->receiver.nxt_dcopy_cpu, nd_params.data_cpy_core);
	WRITE_ONCE(dsk->receiver.rmem_exhausted, 0);
	WRITE_ONCE(dsk->receiver.prev_grant_bytes, 0);
	INIT_LIST_HEAD(&dsk->receiver.hol_channel_list);
	skb_queue_head_init(&dsk->receiver.sk_hol_queue);

	atomic_set(&dsk->receiver.in_flight_copy_bytes, 0);
	dsk->receiver.free_skb_num = 0;
	init_llist_head(&dsk->receiver.clean_page_list);
	WRITE_ONCE(dsk->sche_policy, nd_params.nd_default_sche_policy);

	kfree_skb(sk->sk_tx_skb_cache);
	sk->sk_tx_skb_cache = NULL;
	/* reuse tcp rtx queue*/
	sk->tcp_rtx_queue = RB_ROOT;
	dsk->out_of_order_queue = RB_ROOT;
	// printk("flow wait at init:%d\n", dsk->receiver.flow_wait);
	dsk->nd_ctrl = NULL;
	return 0;
}
EXPORT_SYMBOL_GPL(nd_init_sock);

/*
 *	IOCTL requests applicable to the ND protocol
 */

int nd_ioctl(struct sock *sk, int cmd, unsigned long arg)
{
	struct net *net;
	void __user *argp = (void __user *)arg;
	int pid, err;
	net = sock_net(sk);
	if (cmd == SIOCGIFCONF) {
		struct ifconf ifc;
		if (copy_from_user(&ifc, argp, sizeof(struct ifconf)))
			return -EFAULT;
		rtnl_lock();
		err = dev_ifconf(net, &ifc, sizeof(struct ifreq));
		rtnl_unlock();
		if (!err && copy_to_user(argp, &ifc, sizeof(struct ifconf)))
			err = -EFAULT;
		return 0;
	} else {
		struct ifreq ifr;
		bool need_copyout;
		if (copy_from_user(&ifr, argp, sizeof(struct ifreq)))
			return -EFAULT;
		err = dev_ioctl(net, cmd, &ifr, &need_copyout);
		if (!err && need_copyout)
			if (copy_to_user(argp, &ifr, sizeof(struct ifreq)))
				return -EFAULT;
		return 0;
	}
	printk(KERN_WARNING "unimplemented ioctl invoked on ND socket:%d \n", cmd);

	return -ENOSYS;
}
EXPORT_SYMBOL(nd_ioctl);

// int nd_recvmsg_new(struct sock *sk, struct msghdr *msg, size_t len, int nonblock,
// 		int flags, int *addr_len)
// {
//
// 	struct nd_sock *dsk = nd_sk(sk);
// 	int copied = 0;
// 	// u32 peek_seq;
// 	u32 *seq;
// 	unsigned long used;
// 	int err;
// 	// int inq;
// 	int target;		/* Read at least this many bytes */
// 	long timeo;
// 	// int trigger_tokens = 1;
// 	struct sk_buff *skb, *last, *tmp;
// 	struct nd_dcopy_request *request;
// 	// u32 urg_hole = 0;
// 	// struct scm_timestamping_internal tss;
// 	// int cmsg_flags;
// 	// printk("recvmsg start \n");
// 	// printk("rcvmsg core:%d\n", raw_smp_processor_id());
	//
// 	/* hardcode for now */ 
// 	// struct page *bpages[48];
// 	// struct bio_vec bvec;
// 	struct iov_iter biter;
// 	struct bio_vec *bv_arr;
// 	ssize_t bremain = len, blen;
// 	int max_segs = MAX_PIN_PAGES;
// 	int nr_segs = 0;
// 	int qid;
// 	// printk("convert bytes:%ld\n", ret);
//
// 	// nd_rps_record_flow(sk);
// 	WARN_ON(atomic_read(&dsk->receiver.in_flight_copy_bytes) != 0);
// 	WARN_ON(!llist_empty(&dsk->receiver.clean_page_list));
// 	// if (unlikely(flags & MSG_ERRQUEUE))
// 	// 	return inet_recv_error(sk, msg, len, addr_len);
// 	// printk("start recvmsg \n");
// 	target = sock_rcvlowat(sk, flags & MSG_WAITALL, len);
//
// 	// printk("target bytes:%d\n", target);
//
// 	if (sk_can_busy_loop(sk) && skb_queue_empty_lockless(&sk->sk_receive_queue) &&
// 	    (sk->sk_state == ND_ESTABLISH))
// 		sk_busy_loop(sk, nonblock);
//
// 	lock_sock(sk);
// 	err = -ENOTCONN;
//
//
// 	// cmsg_flags = tp->recvmsg_inq ? 1 : 0;
// 	timeo = sock_rcvtimeo(sk, nonblock);
//
// 	if (sk->sk_state != ND_ESTABLISH)
// 		goto out;
//
// 	/* init bvec page */	
// 	bv_arr = kmalloc(MAX_PIN_PAGES * sizeof(struct bio_vec), GFP_KERNEL);
// 	blen = nd_dcopy_iov_init(msg, &biter, bv_arr,  bremain, max_segs);
// 	nr_segs = biter.nr_segs;
// 	bremain -= blen;
//
//
//
// 	seq = &dsk->receiver.copied_seq;
// 	dsk->receiver.nxt_dcopy_cpu = nd_params.data_cpy_core;
// 	// printk("start queue\n");
// 	do {
// 		u32 offset;
// 		/* Next get a buffer. */
//
// 		last = skb_peek_tail(&sk->sk_receive_queue);
// 		skb_queue_walk_safe(&sk->sk_receive_queue, skb, tmp) {
// 			last = skb;
//
// 			/* Now that we have two receive queues this
// 			 * shouldn't happen.
// 			 */
// 			if (WARN(before(*seq, ND_SKB_CB(skb)->seq),
// 				 "ND recvmsg seq # bug: copied %X, seq %X, rcvnxt %X, fl %X\n",
// 				 *seq, ND_SKB_CB(skb)->seq, (u32)atomic_read(&dsk->receiver.rcv_nxt),
// 				 flags))
// 				break;
//
// 			offset = *seq - ND_SKB_CB(skb)->seq;
//
// 			if (offset < skb->len) {
// 				goto found_ok_skb; 
// 			}
// 			else {
// 				WARN_ON(true);
// 			}
// 		}
//
//
// 		/* ToDo: we have to check whether pending requests are done */
// 		/* Well, if we have backlog, try to process it now yet. */
//
// 		if (copied >= target && !READ_ONCE(sk->sk_backlog.tail)) {
// 			break;
// 		}
//
// 		if (copied) {
// 			if (sk->sk_err ||
// 			    sk->sk_state == TCP_CLOSE ||
// 			    (sk->sk_shutdown & RCV_SHUTDOWN) ||
// 			    !timeo ||
// 			    signal_pending(current))
// 				break;
// 		} else {
// 			if (sock_flag(sk, SOCK_DONE))
// 				break;
//
// 			if (sk->sk_err) {
// 				copied = sock_error(sk);
// 				break;
// 			}
//
// 			if (sk->sk_shutdown & RCV_SHUTDOWN)
// 				break;
//
// 			if (sk->sk_state == TCP_CLOSE) {
// 				/* This occurs when user tries to read
// 				 * from never connected socket.
// 				 */
// 				copied = -ENOTCONN;
// 				break;
// 			}
//
// 			if (!timeo) {
// 				copied = -EAGAIN;
// 				break;
// 			}
//
// 			if (signal_pending(current)) {
// 				copied = sock_intr_errno(timeo);
// 				break;
// 			}
// 		}
//
// 		// tcp_cleanup_rbuf(sk, copied);
// 		// nd_try_send_ack(sk, copied);
// 		// printk("release sock");
// 		if (copied >= target) {
// 			/* Do not sleep, just process backlog. */
// 			/* Release sock will handle the backlog */
// 			release_sock(sk);
// 			lock_sock(sk);
// 		} else {
// 			sk_wait_data(sk, &timeo, last);
// 		}
//
// 		continue;
//
// found_ok_skb:
// 		/* Ok so how much can we use? */
// 		used = skb->len - offset;
//		
// 		// if(blen == 0) {
// 		// 	// pr_info("free bvec bv page:%d\n", __LINE__);
// 		// 	// pr_info("biter.bvec->bv_page:%p\n", bv_arr->bv_page);
// 		// 	// kfree(bv_arr);
// 		// 	// pr_info("done:%d\n", __LINE__);
// 		// 	// bv_arr = NULL;
// 		// 	sk_wait_data_copy(sk, &timeo);
// 		// 	nd_release_pages(bv_arr, true, nr_segs);
// 		// 	kfree(bv_arr);
// 		// }
// 		if(blen < used)
// 			used = blen;
//
// 		if (len < used) {
// 			WARN_ON(true);
// 			used = len;
// 		}
//
//         // unsigned cpu = cpumask_first(cpu_online_mask);
//
//         // while (cpu < nr_cpu_ids) {
//         //         pr_info("CPU: %u, freq: %u kHz\n", cpu, cpufreq_get(cpu));
//         //         cpu = cpumask_next(cpu, cpu_online_mask);
//         // }
// 		/* construct data copy request */
// 		request = kzalloc(sizeof(struct nd_dcopy_request) ,GFP_KERNEL);
// 		request->state = ND_DCOPY_RECV;
// 		request->sk = sk;
// 		request->clean_skb = (used + offset == skb->len);
// 		request->io_cpu = dsk->receiver.nxt_dcopy_cpu;
// 		request->skb = skb;
// 		request->offset = offset;
// 		request->len = used;
// 		request->remain_len = used;
// 		// dup_iter(&request->iter, &biter, GFP_KERNEL);
// 		request->iter = biter;
// 		// printk("cpu:%d req bytes:%d skb bytes:%d frags:%d\n", request->io_cpu,  request->len, skb->len, skb_shinfo(skb)->nr_frags);
// 		// bytes_recvd[request->io_cpu] += request->len;
// 		// pr_info("request:%p\n", request);
// 		// pr_info("sizeof(struct nd_dcopy_request):%d\n", sizeof(struct nd_dcopy_request));
// 		// request->iter = msg->msg_iter;
// 		// pr_info("request->len: %d\n", request->len);
// 		/* update the biter */
// 		iov_iter_advance(&biter, used);
// 		blen -= used;
//
// 		if(blen == 0) {
// 			request->bv_arr = bv_arr;
// 			request->max_segs = nr_segs;
// 			bv_arr = NULL;
// 			nr_segs = 0;
// 		}
// 		// if (!(flags & MSG_TRUNC)) {
// 		// 	err = skb_copy_datagram_msg(skb, offset, msg, used);
// 		// 	// printk("copy data done: %d\n", used);
// 		// 	if (err) {
// 		// 		/* Exception. Bailout! */
// 		// 		if (!copied)
// 		// 			copied = -EFAULT;
// 		// 		break;
// 		// 	}
// 		// }
//
// 		WRITE_ONCE(*seq, *seq + used);
// 		copied += used;
// 		len -= used;
// 		if (used + offset < skb->len)
// 			goto queue_request;
// 		// pr_info("copied_seq:%d\n", seq);
// 		WARN_ON(used + offset > skb->len);
// 		__skb_unlink(skb, &sk->sk_receive_queue);
// 		// atomic_sub(skb->truesize, &sk->sk_rmem_alloc);
// 		// kfree_skb(skb);
//
// queue_request:
// 		atomic_add(used, &dsk->receiver.in_flight_copy_bytes);
// 		/* queue the data copy request */
// 		// pr_info("old msg->msg_iter.iov_base:%p\n", msg->msg_iter.iov->iov_base);
// 		// pr_info("old msg->msg_iter.iov_len:%ld\n", msg->msg_iter.iov->iov_len);
//		
// 		qid = nd_dcopy_queue_request(request);
// 		// pr_info("queue request:%d, skb->len:%d req->len:%d \n", qid, skb->len, request->len);
//
// 		// if(dsk->receiver.nxt_dcopy_cpu == -1) {
// 		// 	dsk->receiver.nxt_dcopy_cpu = qid;
// 		// 	// printk("new qid:%d\n", qid);
// 		// }
// 		if(blen == 0 && bremain > 0) {
// 			ssize_t bsize = bremain;
// 			int next_cpu = 0;
// 			if(used + offset < skb->len) {
// 				bsize =  min_t(ssize_t, bsize, skb->len - offset - used);
// 			} else {
// 				next_cpu = nd_dcopy_sche_rr(dsk->receiver.nxt_dcopy_cpu);
// 				if(next_cpu != -1)
// 					dsk->receiver.nxt_dcopy_cpu = next_cpu;
// 			}
// 			bv_arr = kmalloc(MAX_PIN_PAGES * sizeof(struct bio_vec), GFP_KERNEL);
// 			blen = nd_dcopy_iov_init(msg, &biter, bv_arr, bsize, max_segs);
// 			nr_segs = biter.nr_segs;
// 			bremain -= blen;
// 			// sk_wait_data_copy(sk, &timeo);
// 		}
// 		// pr_info("skb_headlen(skb):%d\n", skb_headlen(skb));
// 		// pr_info("start wait \n");
// 		// sk_wait_data_copy(sk, &timeo);
// 		// pr_info("finish wait \n");
//
// 		// dsk->receiver.nxt_dcopy_cpu = (dsk->receiver.nxt_dcopy_cpu + 4) % 32;
// 		// if(dsk->receiver.nxt_dcopy_cpu == 0)
// 		// 	dsk->receiver.nxt_dcopy_cpu = 4;
// 		// pr_info("msg->msg_iter.count:%ld\n", msg->msg_iter.count);
// 		// pr_info("msg->msg_iter.iov_offset:%ld\n", msg->msg_iter.iov_offset);
// 		// iov_iter_advance(&msg->msg_iter, used);
// 		// pr_info("advance \n");
// 		continue;
//
// 		// if (copied > 3 * trigger_tokens * dsk->receiver.max_gso_data) {
// 		// 	// nd_try_send_token(sk);
// 		// 	trigger_tokens += 1;
//			
// 		// }
// 		// nd_try_send_token(sk);
//
// 		// tcp_rcv_space_adjust(sk);
//
// // skip_copy:
// 		// if (tp->urg_data && after(tp->copied_seq, tp->urg_seq)) {
// 		// 	tp->urg_data = 0;
// 		// 	tcp_fast_path_check(sk);
// 		// }
// 		// if (used + offset < skb->len)
// 		// 	continue;
//
// 		// if (TCP_SKB_CB(skb)->has_rxtstamp) {
// 		// 	tcp_update_recv_tstamps(skb, &tss);
// 		// 	cmsg_flags |= 2;
// 		// }
// 		// if (TCP_SKB_CB(skb)->tcp_flags & TCPHDR_FIN)
// 		// 	goto found_fin_ok;
// 		// if (!(flags & MSG_PEEK))
// 		// 	sk_eat_skb(sk, skb);
// 		// continue;
//
// // found_fin_ok:
// 		/* Process the FIN. */
// 		// WRITE_ONCE(*seq, *seq + 1);
// 		// if (!(flags & MSG_PEEK))
// 		// 	sk_eat_skb(sk, skb);
// 		// break;
// 	} while (len > 0);
//	
// 	/* free the bvec memory */
//
//
// 	/* According to UNIX98, msg_name/msg_namelen are ignored
// 	 * on connected socket. I was just happy when found this 8) --ANK
// 	 */
// 	 	/* waiting data copy to be finishede */
// 	// while(atomic_read(&nsk->receiver.in_flight_copy_bytes) != 0) {
// 	// printk("start wait\n");
// 	sk_wait_data_copy(sk, &timeo);
// 	if(bv_arr) {
// 		nd_release_pages(bv_arr, true, nr_segs);
// 		kfree(bv_arr);
// 	}
// 	// pr_info("free bvec:%d\n", __LINE__);
// 	// pr_info("biter.bvec:%p\n", biter.bvec);
// 	// nd_release_pages(bv_arr, true, nr_segs);
// 	// kfree(bv_arr);
// 	// }
// 	/* Clean up data we have read: This will do ACK frames. */
// 	// tcp_cleanup_rbuf(sk, copied);
// 	// nd_try_send_ack(sk, copied);
// 	// if (dsk->receiver.copied_seq == dsk->total_length) {
// 	// 	printk("call tcp close in the recv msg\n");
// 	// 	nd_set_state(sk, TCP_CLOSE);
// 	// } else {
// 	// 	// nd_try_send_token(sk);
// 	// }
// 	release_sock(sk);
// 	// printk("return");
// 	// if (cmsg_flags) {
// 	// 	if (cmsg_flags & 2)
// 	// 		tcp_recv_timestamp(msg, sk, &tss);
// 	// 	if (cmsg_flags & 1) {
// 	// 		inq = tcp_inq_hint(sk);
// 	// 		put_cmsg(msg, SOL_TCP, TCP_CM_INQ, sizeof(inq), &inq);
// 	// 	}
// 	// }
// 	// printk("recvmsg\n");
//
// 	return copied;
//
// out:
// 	release_sock(sk);
// 	return err;
//
// // recv_urg:
// // 	err = tcp_recv_urg(sk, msg, len, flags);
// // 	goto out;
//
// // recv_sndq:
// // 	// err = tcp_peek_sndq(sk, msg, len);
// // 	goto out;
// }*/


//接收消息代码
int nd_recvmsg_new_2(struct sock *sk, struct msghdr *msg, size_t len, int nonblock, int flags, int *addr_len)
{//实际上是套接字层读取然后向应用层交付的？？？？

	struct nd_sock *dsk = nd_sk(sk);//将传入的sk转换为nd_sock结构（自定义协议的套接字扩展）
	int copied = 0;
	// u32 peek_seq;
	// u32 *seq;
	unsigned long used;
	int err;
	int target;		/* Read at least this many bytes */
	long timeo;
	struct sk_buff *skb, *last, *tmp;
	struct nd_dcopy_request *request;
	/* hardcode for now */ 
	struct iov_iter biter;
	struct bio_vec *bv_arr = NULL;
	ssize_t blen = 0;
	int max_segs = MAX_PIN_PAGES;
	int nr_segs = 0;
	int qid;
	int next_cpu;
	bool in_remote_cpy;
	target = sock_rcvlowat(sk, flags & MSG_WAITALL, len);
	//确定当前接收操作的最小字节数，len为期望接收的数据，如果flags中MSG_WAITALL位被置为1，则返回len，否则返回sk->sk_rcvlowat和len中的最小值

	//如果当前套接字处于ND_ESTABLISH状态（连接建立），且接收队列为空，并且可以进入忙等待（不睡眠或者阻塞，而是一直轮询）则调用sk_busy_loop等待收包
	if (sk_can_busy_loop(sk) && skb_queue_empty_lockless(&sk->sk_receive_queue) && (sk->sk_state == ND_ESTABLISH))
		sk_busy_loop(sk, nonblock);

	lock_sock(sk);//锁定套接字防止并发问题
	err = -ENOTCONN;//套接字未连接错误码

	// cmsg_flags = tp->recvmsg_inq ? 1 : 0;
	timeo = sock_rcvtimeo(sk, nonblock);
	//用于计算接收数据时的超时时间。它根据传入的套接字状态和是否为非阻塞模式，决定接收操作的等待时间
	//该函数返回的是一个 long 类型的值，表示接收数据的超时时间，以“内核 jiffies”为单位
	//nonblock为真，表示以非阻塞模式运行，超时时间通常设置为 0，如果没有数据可接收，操作将立即返回
	//nonblock为假，表示允许阻塞，超时时间由套接字的接收超时设置决定。它通常根据套接字的 SO_RCVTIMEO 选项（接收超时）来确定。

	if (sk->sk_state == ND_LISTEN) goto out;

	/* init bvec page */	
	// bv_arr = kmalloc(MAX_PIN_PAGES * sizeof(struct bio_vec), GFP_KERNEL);
	// blen = nd_dcopy_iov_init(msg, &biter, bv_arr,  bremain, max_segs);
	// nr_segs = biter.nr_segs;
	// bremain -= blen;
	
	/* set nxt_dcopy_cpu to be -1 */
	in_remote_cpy = false;//标识是否正在使用远程拷贝
	dsk->receiver.nxt_dcopy_cpu = nd_params.data_cpy_core;//这里dsk和sk是同一个结构体，只是类型不同，那为什么不直接对sk进行操作呢？？？
	//获得用于数据拷贝的CPU核心编号，nd_params.data_cpy_core被初始化为0号CPU

	// seq = &dsk->receiver.copied_seq;
	do {
		u32 offset;
		/* Next get a buffer. */

		last = skb_peek_tail(&sk->sk_receive_queue);//？？？？有什么用？？？
		//是从sk_buff_head队列中获取最后的sk_buff 数据包，不会修改队列本身，只是返回了尾部的缓冲区指针
		skb_queue_walk_safe(&sk->sk_receive_queue, skb, tmp) {
		//遍历接收队列，但是仅仅能保证在仅可能删除当前节点下是安全的，删除next或者在并发条件下都不能保证是安全的
			last = skb;

			/* Now that we have two receive queues this
			 * shouldn't happen.
			 */
			//copied_seq通常表示已经从接收缓冲区（sk_buff，简称 skb）成功复制到用户空间的数据序列号，通常是一个全局计数器
			//TCP协议的receiver_queue应该是保序的，所以copied_seq应该是大于等于第一个skb的sqeq
			if (WARN(before((u32)atomic_read(&dsk->receiver.copied_seq), ND_SKB_CB(skb)->seq),
				 "ND recvmsg seq # bug: copied %X, seq %X, rcvnxt %X, fl %X\n",
				 (u32)atomic_read(&dsk->receiver.copied_seq), ND_SKB_CB(skb)->seq, (u32)atomic_read(&dsk->receiver.rcv_nxt),
				 flags))
				break;

			offset = (u32)atomic_read(&dsk->receiver.copied_seq) - ND_SKB_CB(skb)->seq;

			if (offset < skb->len) {//此时这个数据包还有内容没有读取完，对其进行处理
				goto found_ok_skb; 
			}
			else {
				WARN_ON(true);
			}
		}

		//此时不再有数据包需要进行拷贝处理，现在等待所有数据包拷贝完成之后进行交付
		/* ToDo: we have to check whether pending requests are done */
		/* Well, if we have backlog, try to process it now yet. */

		if (copied >= target && !READ_ONCE(sk->sk_backlog.tail))
			break;

		if (copied) {
			if (sk->sk_err ||
			    sk->sk_state == TCP_CLOSE ||
			    (sk->sk_shutdown & RCV_SHUTDOWN) ||
			    !timeo ||
			    signal_pending(current))
				break;
		} else {
			if (sock_flag(sk, SOCK_DONE))
				break;

			if (sk->sk_err) {
				copied = sock_error(sk);
				break;
			}

			if (sk->sk_shutdown & RCV_SHUTDOWN)
				break;

			if (sk->sk_state == TCP_CLOSE) {
				/* This occurs when user tries to read
				 * from never connected socket.
				 */
//				copied = -ENOTCONN;
				break;
			}

			if (!timeo) {
				copied = -EAGAIN;
				break;
			}

			if (signal_pending(current)) {
				copied = sock_intr_errno(timeo);
				break;
			}
		}

		// tcp_cleanup_rbuf(sk, copied);
		// nd_try_send_ack(sk, copied);
		// printk("release sock");
		if (copied >= target) {
			/* Do not sleep, just process backlog. */
			/* Release sock will handle the backlog */
			release_sock(sk);
			lock_sock(sk);
		} else {
			sk_wait_data(sk, &timeo, last);
		}

		continue;

found_ok_skb:
		/* Ok so how much can we use? */
		used = skb->len - offset;//当前skb内剩余需要拷贝长度
		if (len < used) used = len;//根据目前的最大拷贝长度len进行调整，取二者中较小的，得到当前skb中剩余需要拷贝的数据长度

		/* decide to do local or remote data copy*/
		if(blen == 0) {//blen究竟有什么用？？？？
			ssize_t bsize = len;
			/* the same skb can either do local or remote but not both */
			if(in_remote_cpy && offset != 0) {//in_remote_cpy初始为false
				bsize =  min_t(ssize_t, bsize, used);
				goto pin_user_page;
			}

			/* check the current CPU util */
			if(atomic_read(&dsk->receiver.in_flight_copy_bytes) > nd_params.ldcopy_rx_inflight_thre || 
				copied <  nd_params.ldcopy_min_thre || nd_params.nd_num_dc_thread == 0){
				//如果远程拷贝的数据量大于阈值，或者拷贝的内容小于最小的阈值，或者没有用于数据拷贝的线程，选择本地拷贝
				//远程数据拷贝可能会有上下文的切换开销？？？所有不适合在负载较大的情况下使用？？？
				/* do local */
				in_remote_cpy = false;
				goto local_copy;
			}

			//进行远程data copy
			/* set up the remote data copy core and state */
			next_cpu = nd_dcopy_sche_rr(dsk->receiver.nxt_dcopy_cpu);//获得一个用于data_copy的CPU编号
			if(next_cpu == -1) goto local_copy;/* worker thread are all busy */
			//如果没有找到，进行local_copy；如果找到了，记录这次找到的CPU编号，并将in_remote_cpy置为true
			else dsk->receiver.nxt_dcopy_cpu = next_cpu;
			in_remote_cpy = true;
			
			// printk("dsk->receiver.nxt_dcopy_cpu:%d\n", dsk->receiver.nxt_dcopy_cpu);
pin_user_page://固定页框，确保数据所在的页面不会被换出
			bv_arr = kmalloc(MAX_PIN_PAGES * sizeof(struct bio_vec), GFP_KERNEL);
			//分配bv_arr数组，用于存放bio_vec结构体，GFP_KERNEL表示普通内核分配，内存不足时可以阻塞等待
			blen = nd_dcopy_iov_init(msg, &biter, bv_arr, bsize, max_segs);//返回初始化了的字节数
			//msg是用户空间的消息头，biter是将要被生成的iov_iter结构体，bv_arr是bio_vec数组，bsize是需要拷贝的数据长度，max_segs是最大的bio_vec数组长度

			nr_segs = biter.nr_segs;
		} 

		if(!in_remote_cpy || blen == 0) {
			WARN_ON_ONCE(true);
			goto local_copy;
		}
		
		/* do remote data copy */
		if(blen < used && blen > 0)
			used = blen;
		/* construct data copy request */
		request = kzalloc(sizeof(struct nd_dcopy_request) ,GFP_KERNEL);
		request->state = ND_DCOPY_RECV;
		request->sk = sk;
		request->clean_skb = (used + offset == skb->len);//？？？？
		request->io_cpu = dsk->receiver.nxt_dcopy_cpu;
		request->skb = skb;
		request->offset = offset;
		request->len = used;
		request->remain_len = used;
		// dup_iter(&request->iter, &biter, GFP_KERNEL);
		request->iter = biter;
		// printk("queue_request:%d len:%d \n", dsk->receiver.nxt_dcopy_cpu, used);
		/* update the biter */
		iov_iter_advance(&biter, used);//？？？？
		blen -= used;

		if(blen == 0) {
			request->bv_arr = bv_arr;
			request->max_segs = nr_segs;
			bv_arr = NULL;
			nr_segs = 0;
		}
		atomic_set(&dsk->receiver.copied_seq, atomic_read(&dsk->receiver.copied_seq) + used);
		// WRITE_ONCE(*seq, *seq + used);
		copied += used;
		len -= used;
		if (used + offset < skb->len)
			goto queue_request;
		// pr_info("copied_seq:%d\n", seq);
		WARN_ON(used + offset > skb->len);
		__skb_unlink(skb, &sk->sk_receive_queue);
		// atomic_sub(skb->truesize, &sk->sk_rmem_alloc);
		// kfree_skb(skb);

queue_request:
		atomic_add(used, &dsk->receiver.in_flight_copy_bytes);
		/* queue the data copy request */
		
		qid = nd_dcopy_queue_request(request);
		// if(dsk->receiver.nxt_dcopy_cpu == -1) {
		// 	dsk->receiver.nxt_dcopy_cpu = qid;
		// 	// printk("new qid:%d\n", qid);
		// }
		// if(blen == 0 && bremain > 0) {
		// 	ssize_t bsize = bremain;
		// 	if(used + offset < skb->len) {
		// 		bsize =  min_t(ssize_t, bsize, skb->len - offset - used);
		// 	} else {
		// 		dsk->receiver.nxt_dcopy_cpu = -1;
		// 	}
		// 	bv_arr = kmalloc(MAX_PIN_PAGES * sizeof(struct bio_vec), GFP_KERNEL);
		// 	blen = nd_dcopy_iov_init(msg, &biter, bv_arr, bsize, max_segs);
		// 	nr_segs = biter.nr_segs;
		// 	bremain -= blen;
		// 	// sk_wait_data_copy(sk, &timeo);
		// }
		continue;
local_copy:
		if (!(flags & MSG_TRUNC)) {//MSG_TRUNC表示用户只关心接收到的数据的长度，而不需要进行copy
			err = skb_copy_datagram_msg(skb, offset, msg, used);//本地进行data copy
			// printk("copy data done: %d\n", used);
			if (err) {//错误处理
				WARN_ON(true);
				/* Exception. Bailout! */
				if (!copied)//如果没有成功复制任何数据（!copied），则将copied设置为-EFAULT，表示发生了错误，终止数据接收循环 (break)，退出数据处理
					copied = -EFAULT;
				break;
			}
		}
		//更新相应的计数器
		atomic_set(&dsk->receiver.copied_seq, atomic_read(&dsk->receiver.copied_seq) + used);//更新copied_seq
		// WRITE_ONCE(*seq, *seq + used);
		copied += used;
		len -= used;
		if (used + offset < skb->len) continue;
		//当前skb中数据没有拷贝完，暂时不释放该skb的空间（可能由于最大拷贝长度len的限制导致末尾的没有拷贝完）
		__skb_unlink(skb, &sk->sk_receive_queue);//将当前的skb从receive_queue的双向链表中移除
		// atomic_sub(skb->truesize, &sk->sk_rmem_alloc);
		kfree_skb(skb);//释放skb占用的内存空间
		/* might need to call clean pages here */
	} while (len > 0);//一直循环直到还需拷贝的数据长度len降低为0
	
	/* free the bvec memory */


	/* According to UNIX98, msg_name/msg_namelen are ignored
	 * on connected socket. I was just happy when found this 8) --ANK
	 */
	 	/* waiting data copy to be finishede */
	// while(atomic_read(&nsk->receiver.in_flight_copy_bytes) != 0) {
	sk_wait_data_copy(sk, &timeo);
	if(bv_arr) {
		nd_release_pages(bv_arr, true, nr_segs);
		kfree(bv_arr);
	}

	// nd_try_send_ack(sk, copied);
	release_sock(sk);
	return copied;

out:
	release_sock(sk);//释放套接字锁并返回错误码
	return err;
}



/*
 * 	This should be easy, if there is something there we
 * 	return it, otherwise we block.
 */
// int nd_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int nonblock,
// 		int flags, int *addr_len)
// {
// 	struct nd_sock *dsk = nd_sk(sk);
// 	int copied = 0;
// 	// u32 peek_seq;
// 	u32 *seq;
// 	unsigned long used;
// 	int err;
// 	// int inq;
// 	int target;		/* Read at least this many bytes */
// 	long timeo;
// 	// int trigger_tokens = 1;
// 	struct sk_buff *skb, *last, *tmp;
// 	// u32 urg_hole = 0;
// 	// struct scm_timestamping_internal tss;
// 	// int cmsg_flags;
// 	// printk("recvmsg: sk->rxhash:%u\n", sk->sk_rxhash);
// 	// printk("rcvmsg core:%d\n", raw_smp_processor_id());
// 	// nd_rps_record_flow(sk);
// 	// if (unlikely(flags & MSG_ERRQUEUE))
// 	// 	return inet_recv_error(sk, msg, len, addr_len);
// 	// printk("start recvmsg \n");
// 	target = sock_rcvlowat(sk, flags & MSG_WAITALL, len);
// 	// printk("target bytes:%d\n", target);
// 	if (sk_can_busy_loop(sk) && skb_queue_empty_lockless(&sk->sk_receive_queue) &&
// 	    (sk->sk_state == ND_ESTABLISH))
// 		sk_busy_loop(sk, nonblock);
// 	lock_sock(sk);
// 	err = -ENOTCONN;
// 	// cmsg_flags = tp->recvmsg_inq ? 1 : 0;
// 	timeo = sock_rcvtimeo(sk, nonblock);
// 	if (sk->sk_state != ND_ESTABLISH)
// 		goto out;
// 	/* Urgent data needs to be handled specially. */
// 	// if (flags & MSG_OOB)
// 	// 	goto recv_urg;
// 	// if (unlikely(tp->repair)) {
// 	// 	err = -EPERM;
// 		// if (!(flags & MSG_PEEK))
// 		// 	goto out;
// 		// if (tp->repair_queue == TCP_SEND_QUEUE)
// 		// 	goto recv_sndq;
// 		// err = -EINVAL;
// 		// if (tp->repair_queue == TCP_NO_QUEUE)
// 		// 	goto out;
// 		/* 'common' recv queue MSG_PEEK-ing */
// //	}
// 	seq = &dsk->receiver.copied_seq;
// 	// if (flags & MSG_PEEK) {
// 	// 	peek_seq = dsk->receiver.copied_seq;
// 	// 	seq = &peek_seq;
// 	// }
// 	do {
// 		u32 offset;
// 		/* Are we at urgent data? Stop if we have read anything or have SIGURG pending. */
// 		// if (tp->urg_data && tp->urg_seq == *seq) {
// 		// 	if (copied)
// 		// 		break;
// 		// 	if (signal_pending(current)) {
// 		// 		copied = timeo ? sock_intr_errno(timeo) : -EAGAIN;
// 		// 		break;
// 		// 	}
// 		// }
// 		/* Next get a buffer. */
// 		last = skb_peek_tail(&sk->sk_receive_queue);
// 		skb_queue_walk_safe(&sk->sk_receive_queue, skb, tmp) {
// 			last = skb;
// 			/* Now that we have two receive queues this
// 			 * shouldn't happen.
// 			 */
// 			if (WARN(before(*seq, ND_SKB_CB(skb)->seq),
// 				 "ND recvmsg seq # bug: copied %X, seq %X, rcvnxt %X, fl %X\n",
// 				 *seq, ND_SKB_CB(skb)->seq, (u32)atomic_read(&dsk->receiver.rcv_nxt),
// 				 flags))
// 				break;
// 			offset = *seq - ND_SKB_CB(skb)->seq;
// 			// if (unlikely(TCP_SKB_CB(skb)->tcp_flags & TCPHDR_SYN)) {
// 			// 	pr_err_once("%s: found a SYN, please report !\n", __func__);
// 			// 	offset--;
// 			// }
// 			if (offset < skb->len) {
// 				goto found_ok_skb; 
// 			}
// 			else {
// 				WARN_ON(true);
// 				// __skb_unlink(skb, &sk->sk_receive_queue);
// 				// kfree_skb(skb);
// 				// atomic_sub(skb->truesize, &sk->sk_rmem_alloc);
// 			}
// 			// if (TCP_SKB_CB(skb)->tcp_flags & TCPHDR_FIN)
// 			// 	goto found_fin_ok;
// 			// WARN(!(flags & MSG_PEEK),
// 			//      "TCP recvmsg seq # bug 2: copied %X, seq %X, rcvnxt %X, fl %X\n",
// 			//      *seq, ND_SKB_CB(skb)->seq, dsk->receiver.rcv_nxt, flags);
// 		}
// 		/* ToDo: we have to check whether pending requests are done */
// 		/* Well, if we have backlog, try to process it now yet. */
// 		if (copied >= target && !READ_ONCE(sk->sk_backlog.tail))
// 			break;
// 		if (copied) {
// 			if (sk->sk_err ||
// 			    sk->sk_state == TCP_CLOSE ||
// 			    (sk->sk_shutdown & RCV_SHUTDOWN) ||
// 			    !timeo ||
// 			    signal_pending(current))
// 				break;
// 		} else {
// 			if (sock_flag(sk, SOCK_DONE))
// 				break;
// 			if (sk->sk_err) {
// 				copied = sock_error(sk);
// 				break;
// 			}
// 			if (sk->sk_shutdown & RCV_SHUTDOWN)
// 				break;
// 			if (sk->sk_state == TCP_CLOSE) {
// 				/* This occurs when user tries to read
// 				 * from never connected socket.
// 				 */
// 				copied = -ENOTCONN;
// 				break;
// 			}
// 			if (!timeo) {
// 				copied = -EAGAIN;
// 				break;
// 			}
// 			if (signal_pending(current)) {
// 				copied = sock_intr_errno(timeo);
// 				break;
// 			}
// 		}
// 		// tcp_cleanup_rbuf(sk, copied);
// 		// nd_try_send_ack(sk, copied);
// 		// printk("release sock");
// 		if (copied >= target) {
// 			/* Do not sleep, just process backlog. */
// 			/* Release sock will handle the backlog */
// 			// printk("call release sock1\n");
// 			release_sock(sk);
// 			lock_sock(sk);
// 		} else {
// 			sk_wait_data(sk, &timeo, last);
// 		}
// 		// if ((flags & MSG_PEEK) &&
// 		//     (peek_seq - copied - urg_hole != tp->copied_seq)) {
// 		// 	net_dbg_ratelimited("TCP(%s:%d): Application bug, race in MSG_PEEK\n",
// 		// 			    current->comm,
// 		// 			    task_pid_nr(current));
// 		// 	peek_seq = dsk->receiver.copied_seq;
// 		// }
// 		continue;
// found_ok_skb:
// 		/* Ok so how much can we use? */
// 		used = skb->len - offset;
// 		if (len < used)
// 			used = len;
// 		// nd_try_send_token(sk);
// 		/* Do we have urgent data here? */
// 		// if (tp->urg_data) {
// 		// 	u32 urg_offset = tp->urg_seq - *seq;
// 		// 	if (urg_offset < used) {
// 		// 		if (!urg_offset) {
// 		// 			if (!sock_flag(sk, SOCK_URGINLINE)) {
// 		// 				WRITE_ONCE(*seq, *seq + 1);
// 		// 				urg_hole++;
// 		// 				offset++;
// 		// 				used--;
// 		// 				if (!used)
// 		// 					goto skip_copy;
// 		// 			}
// 		// 		} else
// 		// 			used = urg_offset;
// 		// 	}
// 		// }
// 		if (!(flags & MSG_TRUNC)) {
// 			err = skb_copy_datagram_msg(skb, offset, msg, used);
// 			// printk("copy data done: %d\n", used);
// 			if (err) {
// 				WARN_ON(true);
// 				/* Exception. Bailout! */
// 				if (!copied)
// 					copied = -EFAULT;
// 				break;
// 			}
// 		}
// 		WRITE_ONCE(*seq, *seq + used);
// 		copied += used;
// 		len -= used;
// 		if (used + offset < skb->len)
// 			continue;
// 		__skb_unlink(skb, &sk->sk_receive_queue);
// 		// atomic_sub(skb->truesize, &sk->sk_rmem_alloc);
// 		kfree_skb(skb);
// 		// if (copied > 3 * trigger_tokens * dsk->receiver.max_gso_data) {
// 		// 	// nd_try_send_token(sk);
// 		// 	trigger_tokens += 1;			
// 		// }
// 		// nd_try_send_token(sk);
// 		// tcp_rcv_space_adjust(sk);
// // skip_copy:
// 		// if (tp->urg_data && after(tp->copied_seq, tp->urg_seq)) {
// 		// 	tp->urg_data = 0;
// 		// 	tcp_fast_path_check(sk);
// 		// }
// 		// if (used + offset < skb->len)
// 		// 	continue;
// 		// if (TCP_SKB_CB(skb)->has_rxtstamp) {
// 		// 	tcp_update_recv_tstamps(skb, &tss);
// 		// 	cmsg_flags |= 2;
// 		// }
// 		// if (TCP_SKB_CB(skb)->tcp_flags & TCPHDR_FIN)
// 		// 	goto found_fin_ok;
// 		// if (!(flags & MSG_PEEK))
// 		// 	sk_eat_skb(sk, skb);
// 		continue;
// // found_fin_ok:
// 		/* Process the FIN. */
// 		// WRITE_ONCE(*seq, *seq + 1);
// 		// if (!(flags & MSG_PEEK))
// 		// 	sk_eat_skb(sk, skb);
// 		// break;
// 	} while (len > 0);
// 	/* According to UNIX98, msg_name/msg_namelen are ignored
// 	 * on connected socket. I was just happy when found this 8) --ANK
// 	 */
// 	/* Clean up data we have read: This will do ACK frames. */
// 	// tcp_cleanup_rbuf(sk, copied);
// 	// nd_try_send_ack(sk, copied);
// 	// if (dsk->receiver.copied_seq == dsk->total_length) {
// 	// 	printk("call tcp close in the recv msg\n");
// 	// 	nd_set_state(sk, TCP_CLOSE);
// 	// } else {
// 	// 	// nd_try_send_token(sk);
// 	// }
// 	release_sock(sk);
// 	// if (cmsg_flags) {
// 	// 	if (cmsg_flags & 2)
// 	// 		tcp_recv_timestamp(msg, sk, &tss);
// 	// 	if (cmsg_flags & 1) {
// 	// 		inq = tcp_inq_hint(sk);
// 	// 		put_cmsg(msg, SOL_TCP, TCP_CM_INQ, sizeof(inq), &inq);
// 	// 	}
// 	// }
// 	// printk("recvmsg\n");
// 	return copied;
// out:
// 	release_sock(sk);
// 	return err;
// // recv_urg:
// // 	err = tcp_recv_urg(sk, msg, len, flags);
// // 	goto out;
// // recv_sndq:
// // 	// err = tcp_peek_sndq(sk, msg, len);
// // 	goto out;
// }

int nd_pre_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
	if (addr_len < sizeof(struct sockaddr_in))
 		return -EINVAL;

 	return BPF_CGROUP_RUN_PROG_INET4_CONNECT_LOCK(sk, uaddr);
}
EXPORT_SYMBOL(nd_pre_connect);

int nd_disconnect(struct sock *sk, int flags)
{
	struct inet_sock *inet = inet_sk(sk);
 	/*
 	 *	1003.1g - break association.
 	 */

 	sk->sk_state = TCP_CLOSE;
 	inet->inet_daddr = 0;
 	inet->inet_dport = 0;
 	// sock_rps_reset_rxhash(sk);
 	sk->sk_bound_dev_if = 0;
 	if (!(sk->sk_userlocks & SOCK_BINDADDR_LOCK)) {
 		inet_reset_saddr(sk);
 		if (sk->sk_prot->rehash &&
 		    (sk->sk_userlocks & SOCK_BINDPORT_LOCK))
 			sk->sk_prot->rehash(sk);
 	}

 	if (!(sk->sk_userlocks & SOCK_BINDPORT_LOCK)) {
 		sk->sk_prot->unhash(sk);
 		inet->inet_sport = 0;
 	}
 	sk_dst_reset(sk);
 	return 0;
}
EXPORT_SYMBOL(nd_disconnect);

int nd_v4_early_demux(struct sk_buff *skb)
{
	return 0; 
}

/* oversize: -1, drop: -2, normal: 0 */
int nd_rcv(struct sk_buff *skb)
{	//根据包的不同类型进行处理
	// printk("receive nd rcv\n");
	// skb_dump(KERN_WARNING, skb, false);
	struct ndhdr* dh;
	// printk("skb->len:%d\n", skb->len);
	WARN_ON(skb == NULL);

	if (!pskb_may_pull(skb, sizeof(struct ndhdr))) {//检查头部是否完整
		printk("header space not enough\n");
		goto drop;		/* No space for header. */
	}

	dh = nd_hdr(skb);
	// printk("dh == NULL?: %d\n", dh == NULL);
	// printk("receive pkt: %d\n", dh->type);
	// printk("end ref \n");
	if(dh->type == DATA) {
		return nd_handle_data_pkt(skb);
		// return __nd4_lib_rcv(skb, &nd_table, IPPROTO_VIRTUAL_SOCK);
	} else if (dh->type == SYNC) {
		return nd_handle_sync_pkt(skb);
	} else if (dh->type == TOKEN) {
		WARN_ON(true);
		return nd_handle_token_pkt(skb);
	} else if (dh->type == FIN) {
		return nd_handle_fin_pkt(skb);
	} else if (dh->type == ACK) {
		return nd_handle_ack_pkt(skb);
	} else if (dh->type == SYNC_ACK) {
		return nd_handle_sync_ack_pkt(skb);
	}

drop:
	printk("drop randomly:%d\n", raw_smp_processor_id());
	kfree_skb(skb);
	return -2;
	// return __nd4_lib_rcv(skb, &nd_table, IPPROTO_VIRTUAL_SOCK);
}


void nd_destroy_sock(struct sock *sk)
{
	// struct udp_hslot* hslot = udp_hashslot(sk->sk_prot->h.udp_table, sock_net(sk),
	// 				     nd_sk(sk)->nd_port_hash);
	struct nd_sock *up = nd_sk(sk);
	struct ndt_channel_entry *entry, *temp;
	struct ndt_conn_queue *queue;
	struct sk_buff *skb, *tmp;

	// struct inet_sock *inet = inet_sk(sk);
	// struct rcv_core_entry *entry = &rcv_core_tab.table[raw_smp_processor_id()];
	// local_bh_disable();
	// bh_lock_sock(sk);
	// hrtimer_cancel(&up->receiver.flow_wait_timer);
	// test_and_clear_bit(ND_WAIT_DEFERRED, &sk->sk_tsq_flags);
	lock_sock(sk);
	local_bh_disable();
	bh_lock_sock(sk);
	up->receiver.flow_finish_wait = false;
	if(sk->sk_state == ND_ESTABLISH) {
		nd_conn_queue_request(construct_fin_req(sk), up, false, true, true);
		// nd_xmit_control(construct_fin_pkt(sk), sk, inet->inet_dport); 
	}      
	// printk("reach here:%d", __LINE__);
	// pr_info("up->sender.snd_una:%u\n", up->sender.snd_una);
	// pr_info("up->sender.grant_nxt:%u\n", up->sender.sd_grant_nxt);
	// pr_info("up->sender.write_seq:%u\n", up->sender.write_seq);
	// pr_info("up->receiver.grant_nxt:%u\n", up->receiver.grant_nxt);
	// pr_info("up->receiver.free_skb_num:%llu\n", up->receiver.free_skb_num);
	nd_set_state(sk, TCP_CLOSE);
	// nd_flush_pendfing_frames(sk);
	if(up->sender.pending_req) {
		// pr_info("up->sender.pending_req seq:%u\n", ND_SKB_CB(up->sender.pending_req->skb)->seq);
		kfree_skb(up->sender.pending_req->skb);
		kfree(up->sender.pending_req);
		up->sender.pending_req = NULL;
	}
	nd_write_queue_purge(sk);
	nd_read_queue_purge(sk);
	// pr_info("sk->sk_wmem_queued:%u\n", sk->sk_wmem_queued);
	/* hol state are protected by the spin lock */
	skb_queue_walk_safe(&up->receiver.sk_hol_queue, skb, tmp) {
		__skb_unlink(skb, &up->receiver.sk_hol_queue);
		atomic_sub(skb->truesize, &tcp_sk(ND_SKB_CB(skb)->queue->sock->sk)->hol_alloc);
		atomic_sub(skb->len, &tcp_sk(ND_SKB_CB(skb)->queue->sock->sk)->hol_len);
		ND_SKB_CB(skb)->queue = NULL;
		kfree_skb(skb);
	}
	
	list_for_each_entry_safe(entry, temp, &up->receiver.hol_channel_list, list_link) {
		queue = entry->queue;
		if(ndt_conn_is_latency(queue)) {
			queue_work_on(queue_cpu(queue), ndt_conn_wq_lat, &queue->io_work);
		} else {
			queue_work_on(queue_cpu(queue), ndt_conn_wq, &queue->io_work);
		}
		kfree(entry);
	}
	bh_unlock_sock(sk);
	local_bh_enable();
	release_sock(sk);
	/* remove from sleep wait queue */
	nd_conn_remove_sleep_sock(up->sender.wait_queue, up);
	cancel_work_sync(&up->tx_work);
	/*  */
	// bh_unlock_sock(sk);
	// local_bh_enable();
	// printk("sk->sk_wmem_queued:%d\n",sk->sk_wmem_queued);
	// spin_lock_bh(&entry->lock);
	// printk("dsk->match_link:%p\n", &up->match_link);
	// if(up->receiver.in_pq)
		// nd_pq_delete(&entry->flow_q, &up->match_link);
	// spin_unlock_bh(&entry->lock);
	// if (static_branch_unlikely(&nd_encap_needed_key)) {
	// 	if (up->encap_type) {
	// 		void (*encap_destroy)(struct sock *sk);
	// 		encap_destroy = READ_ONCE(up->encap_destroy);
	// 		if (encap_destroy)
	// 			encap_destroy(sk);
	// 	}
	// 	if (up->encap_enabled)
	// 		static_branch_dec(&nd_encap_needed_key);
	// }
}


int nd_setsockopt(struct sock *sk, int level, int optname,
		   char __user *optval, unsigned int optlen)
{
	int val;
	if (get_user(val, (int __user *)optval))
		return -EFAULT;
	printk(KERN_WARNING "unimplemented setsockopt invoked on ND socket:"
			" level %d, optname %d, optlen %d\n",
			level, optname, optlen);
	return 0;
	return -EINVAL;
	// if (level == SOL_VIRTUAL_SOCK)
	// 	return nd_lib_setsockopt(sk, level, optname, optval, optlen,
	// 				  nd_push_pending_frames);
	// return ip_setsockopt(sk, level, optname, optval, optlen);
}

// #ifdef CONFIG_COMPAT
// int compat_nd_setsockopt(struct sock *sk, int level, int optname,
// 			  char __user *optval, unsigned int optlen)
// {
// 	if (level == SOL_VIRTUAL_SOCK)
// 		return nd_lib_setsockopt(sk, level, optname, optval, optlen,
// 					  nd_push_pending_frames);
// 	return compat_ip_setsockopt(sk, level, optname, optval, optlen);
// }
// #endif

int nd_lib_getsockopt(struct sock *sk, int level, int optname,
		       char __user *optval, int __user *optlen)
{
	printk(KERN_WARNING "unimplemented getsockopt invoked on ND socket:"
			" level %d, optname %d\n", level, optname);
	return -EINVAL;
}
EXPORT_SYMBOL(nd_lib_getsockopt);

int nd_getsockopt(struct sock *sk, int level, int optname,
		   char __user *optval, int __user *optlen)
{
	printk(KERN_WARNING "unimplemented getsockopt invoked on ND socket:"
			" level %d, optname %d\n", level, optname);
	return -EINVAL;
}

// __poll_t nd_poll(struct file *file, struct socket *sock, poll_table *wait)
// {
// 	printk(KERN_WARNING "unimplemented poll invoked on ND socket\n");
// 	return -ENOSYS;
// }
// EXPORT_SYMBOL(nd_poll);

int nd_abort(struct sock *sk, int err)
{
	printk(KERN_WARNING "unimplemented abort invoked on ND socket\n");
	return -ENOSYS;
}
EXPORT_SYMBOL_GPL(nd_abort);

u32 nd_flow_hashrnd(void)
{
	static u32 hashrnd __read_mostly;

	net_get_random_once(&hashrnd, sizeof(hashrnd));

	return hashrnd;
}
EXPORT_SYMBOL(nd_flow_hashrnd);

// static void __nd_sysctl_init(struct net *net)
// {
// 	net->ipv4.sysctl_udp_rmem_min = SK_MEM_QUANTUM;
// 	net->ipv4.sysctl_udp_wmem_min = SK_MEM_QUANTUM;
// #ifdef CONFIG_NET_L3_MASTER_DEV
// 	net->ipv4.sysctl_udp_l3mdev_accept = 0;
// #endif
// }

// static int __net_init nd_sysctl_init(struct net *net)
// {
// 	__nd_sysctl_init(net);
// 	return 0;
// }

// static struct pernet_operations __net_initdata nd_sysctl_ops = {
// 	.init	= nd_sysctl_init,
// };

static inline bool nd_stream_is_readable(const struct nd_sock *nsk,
					  int target, struct sock *sk)
{
	return  ((u32)atomic_read(&nsk->receiver.rcv_nxt) - (u32)atomic_read(&nsk->receiver.copied_seq))
			 - (u32)atomic_read(&nsk->receiver.in_flight_copy_bytes);
}

__poll_t nd_poll(struct file *file, struct socket *sock,
		struct poll_table_struct *wait) {
		struct sock *sk = sock->sk;
		struct nd_sock *nsk = nd_sk(sk);
		__poll_t mask = 0;
		int state = smp_load_acquire(&sk->sk_state);
		// int target = sock_rcvlowat(sk, 0, INT_MAX);	
		sock_poll_wait(file, sock, wait);
		if(state == ND_LISTEN) {
			if(!reqsk_queue_empty(&nsk->icsk_accept_queue)) 
				return EPOLLIN | EPOLLRDNORM;
			else 
				return 0;
		}
		/* copy from datagram poll*/
		if (sk->sk_shutdown & RCV_SHUTDOWN)
			mask |= EPOLLRDHUP | EPOLLIN | EPOLLRDNORM;
		if (sk->sk_shutdown == SHUTDOWN_MASK)
			mask |= EPOLLHUP;

		/* Socket is not locked. We are protected from async events
		* by poll logic and correct handling of state changes
		* made by other threads is impossible in any case.
		*/
		if(nd_stream_memory_free(sk, nsk->sender.pending_queue))
			mask |= POLLOUT | POLLWRNORM | EPOLLWRBAND;
		else
			sk_set_bit(SOCKWQ_ASYNC_NOSPACE, sk);

		if (nd_stream_is_readable(nsk, 0, sk))
			mask |= EPOLLIN | EPOLLRDNORM;
		return mask;
}

EXPORT_SYMBOL(nd_poll);


static struct sk_buff *nd_recv_skb(struct sock *sk, u32 seq, u32 *off)
{
	struct sk_buff *skb;
	u32 offset;

	while ((skb = skb_peek(&sk->sk_receive_queue)) != NULL) {
		offset = seq - ND_SKB_CB(skb)->seq;

		if (offset < skb->len) {
			*off = offset;
			return skb;
		}
		__skb_unlink(skb, &sk->sk_receive_queue);
		// atomic_sub(skb->truesize, &sk->sk_rmem_alloc);
		kfree_skb(skb);
	}
	return NULL;
}

int nd_read_sock(struct sock *sk, read_descriptor_t *desc,
		  sk_read_actor_t recv_actor)
{
	struct sk_buff *skb;
	struct nd_sock *nsk = nd_sk(sk);
	u32 seq = (u32)atomic_read(&nsk->receiver.copied_seq);
	u32 offset;
	int copied = 0;

	if (sk->sk_state == ND_LISTEN)
		return -ENOTCONN;
	while ((skb = nd_recv_skb(sk, seq, &offset)) != NULL) {
		if (offset < skb->len) {
			int used;
			size_t len;

			len = skb->len - offset;
			used = recv_actor(desc, skb, offset, len);
			if (used <= 0) {
				if (!copied)
					copied = used;
				break;
			} else if (used <= len) {
				seq += used;
				copied += used;
				offset += used;
			}
			/* this follows tcp_read_sock which assuming recv_actor will drop the lock; 
			it is unclear whether we need it */
			skb = nd_recv_skb(sk, seq - 1, &offset);
			if (!skb)
				break;
			if (offset + 1 != skb->len)
				continue;
		}
		__skb_unlink(skb, &sk->sk_receive_queue);
		// atomic_sub(skb->truesize, &sk->sk_rmem_alloc);
		kfree_skb(skb);
		if (!desc->count)
			break;
		atomic_set(&nsk->receiver.copied_seq, seq);
	}
	atomic_set(&nsk->receiver.copied_seq, seq);

	/* Clean up data we have read. */
	if (copied > 0) {
		nd_recv_skb(sk, seq, &offset);
	}
	return copied;
}

void __init nd_init(void)
{
	unsigned long limit;
	// unsigned int i;

	printk("try to add nd table \n");

	nd_hashtable_init(&nd_hashinfo, 0);

	limit = nr_free_buffer_pages() / 8;
	limit = max(limit, 128UL);
	sysctl_nd_mem[0] = limit / 4 * 3;
	sysctl_nd_mem[1] = limit;
	sysctl_nd_mem[2] = sysctl_nd_mem[0] * 2;

	// __nd_sysctl_init(&init_net);
	// /* 16 spinlocks per cpu */
	// // nd_busylocks_log = ilog2(nr_cpu_ids) + 4;
	// // nd_busylocks = kmalloc(sizeof(spinlock_t) << nd_busylocks_log,
	// // 			GFP_KERNEL);
	// // if (!nd_busylocks)
	// // 	panic("ND: failed to alloc nd_busylocks\n");
	// // for (i = 0; i < (1U << nd_busylocks_log); i++)
	// // 	spin_lock_init(nd_busylocks + i);
	// if (register_pernet_subsys(&nd_sysctl_ops)) 
	// 	panic("ND: failed to init sysctl parameters.\n");

	printk("ND init complete\n");

}

void nd_destroy() {
	printk("try to destroy peer table\n");
	printk("try to destroy nd socket table\n");
	nd_hashtable_destroy(&nd_hashinfo);
	// kfree(nd_busylocks);
}
