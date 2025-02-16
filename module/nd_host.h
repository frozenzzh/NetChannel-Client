#ifndef _ND_HOST_H
#define _ND_HOST_H

#include <linux/module.h>
#include <linux/inet.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/err.h>
// #include <linux/nvme-tcp.h>
#include <net/sock.h>
#include <net/tcp.h>
// #include <linux/blk-mq.h>
#include <crypto/hash.h>
#include <net/busy_poll.h>
#include "uapi_linux_nd.h"
#include "linux_nd.h"
extern struct nd_conn_ctrl* nd_ctrl;
//PDU protocol data unit协议传输单元
#define ND_CONN_AQ_DEPTH		32
enum hctx_type {
	HCTX_TYPE_DEFAULT,
	HCTX_TYPE_READ,
	HCTX_TYPE_POLL,

	HCTX_MAX_TYPES,
};

enum nd_conn_send_state {
	ND_CONN_SEND_CMD_PDU = 0,//用于建立连接？？？表示正要开始发送数据？？？
	ND_CONN_SEND_H2C_PDU,//Hos-to-Controller，表示一个发送数据的请求
	ND_CONN_SEND_DATA,//正在发送数据类型的PUD，通常是实际传输的数据内容
	ND_CONN_SEND_DDGST,//完整性验证
	ND_CONN_PDU_DONE,//PDU成功发送
};

enum nd_conn_queue_flags {
	ND_CONN_Q_ALLOCATED	= 0,//队列分配
	ND_CONN_Q_LIVE		= 1,//队列活跃
	ND_CONN_Q_POLLING	= 2,//队列轮询
};

struct nd_conn_ctrl_options {
	// unsigned		mask;
	// char			*transport;
	// char			*subsysnqn;
	char			*traddr;//远端服务器的IP地址
	char			*trsvcid;//目标服务ID，用于标识端口号？
	char			*host_traddr;//源IP地址
    // char            *host_port;
	size_t			queue_size;
	size_t 			compact_low_thre;//在控制队列中合并多个I/O或者协议请求的最小以及最大阈值
	size_t			compact_high_thre;
	unsigned int		nr_io_queues;//IO队列数量，可以用于存储/网络设备的读/写请求，即conn_queue的数量
	// unsigned int		reconnect_delay;
	// bool			discovery_nqn;
	// bool			duplicate_connect;
	// unsigned int		kato;
	struct nvmf_host	*host;//配置的主机的信息？？？
	// int			max_reconnects;
	// bool			disable_sqflow;
	// bool			hdr_digest;
	// bool			data_digest;
	unsigned int		nr_write_queues;
	unsigned int		nr_poll_queues;//写队列与轮询队列数量
	int			tos;//服务类型，如标准、最高优先级、低延迟
};


struct nd_conn_request {
	// struct nvme_request	req;
	struct ndhdr	*hdr;
	struct sk_buff	*skb;
	struct nd_conn_queue	*queue;//所属请求队列
	int prio_class;
	// u32			data_len;
	// u32			pdu_len;
	// u32			pdu_sent;
	
	u16			ttag;//传输标签？？？

	struct list_head	entry;
	struct llist_node	lentry;
	// __le32			ddgst;

	// struct bio		*curr_bio;
	struct iov_iter		iter;

	/* send state */
	size_t			offset;//
	size_t			data_sent;
	size_t			frag_offset;//skb中shared info中的数据在头一个frag中的偏移量
	size_t			fragidx;
	enum nd_conn_send_state state;
};

struct nd_conn_ctrl {
	struct nd_conn_queue	*queues;//连接控制指针，可能会有多个不同的指针？？？
    uint32_t queue_count;
	// struct blk_mq_tag_set	tag_set;

	/* other member variables */
	struct hlist_node hlist;//???hash list???

	// struct list_head	list;
	// /* socket wait list */
	// spinlock_t sock_wait_lock;
	// struct list_head sock_wait_list;
	// struct workqueue_struct *sock_wait_wq;

	// struct blk_mq_tag_set	admin_tag_set;
	struct sockaddr_storage addr;//通用目的地址结构
	uint32_t dst_addr;
	struct sockaddr_storage src_addr;//源地址结构，用于构造套接字
	// struct nvme_ctrl	ctrl;
    struct nd_conn_ctrl_options *opts;//连接控制配置信息
    // uint32_t sqsize;
	struct mutex		teardown_lock;
	// struct work_struct	err_work;
	// struct delayed_work	connect_work;
	// struct nd_conn_request async_req;
	// u32			io_queues[32];
	// struct page_frag_cache	pf_cache;

};

struct nd_conn_queue {//和data_copy_request中的queue有什么关系？？？分布在不同的层次吗？
//这里有两个work_struct，是说每一个队列只有一个io_work，但是多个队列可能共享sock_wait_wq吗？？？
	int prio_class;//优先级类
	struct socket		*sock;
	struct work_struct	io_work;//这里也有一个io_work，需要找到具体是在哪里注册的
	int			io_cpu;
	int 	qid;//？？？队列id？？？
	struct mutex		send_mutex;
	struct llist_head	req_list;
	struct list_head	send_list;
	bool			more_requests;//队列中是否还有更多请求

	/* recv state */
	// void			*pdu;
	// int			pdu_remaining;
	// int			pdu_offset;
	// size_t			data_remaining;
	// size_t			ddgst_remaining;
	// unsigned int		nr_cqe;

	/* send state */
	struct nd_conn_request *request;//正在处理的请求对象
	atomic_t	cur_queue_size;
	int			queue_size;//队列最大容量
	int			compact_high_thre;
	int 		compact_low_thre;//压缩阈值
	// int			cur_queue_size;
	// size_t			cmnd_capsule_len;
	struct nd_conn_ctrl	*ctrl;//管理连接信息？？？
	unsigned long		flags;
	bool			rd_enabled;//？？？队列是否可读？？？

	// bool			hdr_digest;
	// bool			data_digest;
	// struct ahash_request	*rcv_hash;
	// struct ahash_request	*snd_hash;
	// __le32			exp_ddgst;
	// __le32			recv_ddgst;

	// struct page_frag_cache	pf_cache;
	/* socket wait list */
	spinlock_t sock_wait_lock;
	struct list_head sock_wait_list;
	struct workqueue_struct *sock_wait_wq;
	
	void (*state_change)(struct sock *);//套接字状态变化触发
	void (*data_ready)(struct sock *);//接受时候数据包到达了内核缓冲区时触发
	void (*write_space)(struct sock *);//？？？这里的缓冲区是网卡的还是内核态的？？
};

struct nd_conn_pdu {
	struct ndhdr hdr;//用于携带报文头
};

void nd_conn_add_sleep_sock(struct nd_conn_ctrl *ctrl, struct nd_sock* nsk);
void nd_conn_remove_sleep_sock(struct nd_conn_queue *queue, struct nd_sock* nsk);
void nd_conn_wake_up_all_socks(struct nd_conn_queue *queue);

// int nd_conn_init_request(struct nd_conn_request *req, int queue_id);
int nd_conn_try_send_cmd_pdu(struct nd_conn_request *req); 
int nd_conn_try_send_data_pdu(struct nd_conn_request *req);
int nd_conn_try_send(struct nd_conn_queue *queue);
void nd_conn_restore_sock_calls(struct nd_conn_queue *queue);
void __nd_conn_stop_queue(struct nd_conn_queue *queue);
void nd_conn_stop_queue(struct nd_conn_ctrl *ctrl, int qid);
void nd_conn_free_queue(struct nd_conn_ctrl *ctrl, int qid);
void nd_conn_free_io_queues(struct nd_conn_ctrl *ctrl);
void nd_conn_stop_io_queues(struct nd_conn_ctrl *ctrl);
int nd_conn_start_queue(struct nd_conn_ctrl *ctrl, int idx);
// int nd_conn_configure_admin_queue(struct nd_conn_ctrl *ctrl, bool new);
// int nd_conn_alloc_admin_queue(struct nd_conn_ctrl *ctrl);
// void nd_conn_free_admin_queue(struct nd_conn_ctrl *ctrl);
// void nd_conn_destroy_admin_queue(struct nd_conn_ctrl *ctrl, bool remove);
void nd_conn_io_work(struct work_struct *w);
void nd_conn_data_ready(struct sock *sk);
void nd_conn_write_space(struct sock *sk);
void nd_conn_state_change(struct sock *sk);
void nd_conn_data_ready(struct sock *sk);
int nd_conn_alloc_queue(struct nd_conn_ctrl *ctrl,
		int qid);
bool nd_conn_queue_request(struct nd_conn_request *req, struct nd_sock *nsk,
		bool sync, bool avoid_check, bool last);
void* nd_conn_find_nd_ctrl(__be32 dst_addr);

// void nd_conn_error_recovery_work(struct work_struct *work);
void nd_conn_teardown_ctrl(struct nd_conn_ctrl *ctrl, bool shutdown);
void nd_conn_delete_ctrl(struct nd_conn_ctrl *ctrl);
// void nd_conn_teardown_admin_queue(struct nd_conn_ctrl *ctrl,
// 		bool remove);
void nd_conn_teardown_io_queues(struct nd_conn_ctrl *ctrl,
		bool remove);
unsigned int nd_conn_nr_io_queues(struct nd_conn_ctrl *ctrl);
int __nd_conn_alloc_io_queues(struct nd_conn_ctrl *ctrl);
void nd_conn_destroy_io_queues(struct nd_conn_ctrl *ctrl, bool remove);
int nd_conn_setup_ctrl(struct nd_conn_ctrl *ctrl, bool new);
struct nd_conn_ctrl *nd_conn_create_ctrl(struct nd_conn_ctrl_options *opts);
int nd_conn_init_module(void);
void nd_conn_cleanup_module(void);
#endif
