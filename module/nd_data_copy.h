#ifndef _ND_DATA_COPY_H
#define _ND_DATA_COPY_H

#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/err.h>
// #include <linux/nvme-tcp.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <linux/inet.h>
#include <linux/llist.h>
#include <linux/spinlock.h>
#include <crypto/hash.h>
#include "uapi_linux_nd.h"

enum nd_conn_dcopy_state {//表示data copy的状态
	ND_DCOPY_SEND = 0,
	ND_DCOPY_RECV,
	ND_DCOPY_DONE,
};


struct nd_dcopy_response {
	struct llist_node	lentry;//无锁单链表
	struct sk_buff *skb;//网络数据包
};

struct nd_dcopy_page {//统一管理数据包传输之后的内存空间
	struct llist_node	lentry;
	struct bio_vec *bv_arr;//bio 本身用于表示一个 I/O 请求，其中 bio_vec 则描述了请求中的一个或多个数据片段。
	struct sk_buff* skb;
	int max_segs;
};

struct nd_dcopy_request {//描述数据复制请求
	enum nd_conn_dcopy_state state;

	bool clean_skb;
	int io_cpu;//处理此请求的cpu
    struct sock *sk;//套接字相关
	struct sk_buff *skb;//数据包相关
	struct iov_iter iter;//用于抽象和管理复杂的 I/O 操作，指向拷贝数据的目标缓冲区，提供了统一的接口来处理来自用户空间和内核空间的多片段数据传输，
	struct bio_vec *bv_arr;//用于描述内存片段
	struct list_head	entry;//用于被queue的copy_list链表所引用
	struct llist_node	lentry;//用于被queue的req_list链表所引用
	union{
		u32 offset;//拷贝时数据在buffer中的偏移量
		u32 seq;//发送时的序列号
	};
    int len;
	int remain_len;//剩余的数据长度
	int max_segs;
	struct nd_dcopy_queue *queue;//指向所属的队列
};

struct nd_dcopy_queue {
    struct llist_head	req_list;
	struct list_head	copy_list;//两个为什么一个为无锁链表，一个为带锁的链表？
    int io_cpu;
	struct work_struct	io_work;
	struct mutex		copy_mutex;

    struct nd_dcopy_request *request;//和以上的nd_data_request是相互指向
    size_t			offset;
	int queue_threshold;
	atomic_t	queue_size;//表示队列中所有的请求的包的长度之和
};

// inline void nd_init_data_copy_request(struct nd_dcopy_request *request) {
//     request->clean_skb = false;
//     // INIT_LIST_HEAD();
//     // init_llist_head
// }
int nd_dcopy_sche_rr(int last_qid);
int nd_dcopy_queue_request(struct nd_dcopy_request *req);
int nd_try_dcopy(struct nd_dcopy_queue *queue);
void nd_dcopy_io_work(struct work_struct *w);
void nd_dcopy_flush_req_list(struct nd_dcopy_queue *queue);
void nd_dcopy_free_queue(struct nd_dcopy_queue *queue);
int nd_dcopy_alloc_queue(struct nd_dcopy_queue *queue, int io_cpu);
int nd_dcopy_alloc_queues(struct nd_dcopy_queue *queues);
int nd_dcopy_init(void);
void nd_dcopy_exit(void);

static inline int nd_copy_to_page_nocache(struct sock *sk, struct iov_iter *from,
					   struct sk_buff *skb,
					   struct page *page,
					   int off, int copy)
{//将用户空间的数据从 iov_iter 结构中复制到指定的内核页片段（page）
	int err;

	err = skb_do_copy_data_nocache(sk, skb, from, page_address(page) + off,
				       copy, skb->len);//最后一个参数skb_len: sk_buff 的当前长度。这个参数用于确保数据不会超出 sk_buff 的缓冲区
	if (err)
		return err;

	skb->len	     += copy;
	skb->data_len	     += copy;
	skb->truesize	     += copy;//更行skb的相关信息
	// sk_wmem_queued_add(sk, copy);
	// sk_mem_charge(sk, copy);
	return 0;
}

#endif /* _ND_DATA_COPY_H */
