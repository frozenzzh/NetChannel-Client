
#ifndef _ND_TARGET_H
#define _ND_TARGET_H

#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/err.h>
// #include <linux/nvme-tcp.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <linux/inet.h>
#include <linux/llist.h>
#include <crypto/hash.h>
#include "uapi_linux_nd.h"
// #include "nd_host.h"
/* ND Connection Listerning Port */
extern struct workqueue_struct *ndt_conn_wq;
extern struct workqueue_struct *ndt_conn_wq_lat;
struct ndt_conn_port {
	struct socket		*sock;//指向端口
	struct work_struct	accept_work;//异步处理接收的work_struct
	// struct nvmet_port	*nport;
	struct sockaddr_storage addr;
	char* local_ip;
	char* local_port;
	void (*data_ready)(struct sock *);//data_ready时候的回调函数
	
};

enum ndt_conn_queue_state {//队列状态，分别表示正在建立连接、活跃以及失联这些状态
	NDT_CONN_Q_CONNECTING,
	NDT_CONN_Q_LIVE,
	NDT_CONN_Q_DISCONNECTING,
};

enum ndt_conn_recv_state {
	NDT_CONN_RECV_PDU,
	NDT_CONN_RECV_DATA,
	NDT_CONN_RECV_DDGST,
	NDT_CONN_RECV_ERR,
};

struct ndt_conn_queue {
	struct socket		*sock;
	struct ndt_conn_port	*port;//指向所属的端口？？
	struct work_struct	io_work;
	int io_cpu;//io_work及其负责的CPU
	int prio_class;
	// struct nvmet_cq		nvme_cq;
	// struct nvmet_sq		nvme_sq;
	struct sk_buff_head	receive_queue;//接收数据队列，一个sk_buffer list
	/* send state */ //这里的send state什么意思？？发送的时候不是使用的nd_conn_queue吗？？？？
	//以下部分似乎在发送时已经废弃不再使用
	// struct nvmet_tcp_cmd	*cmds;
	unsigned int		nr_cmds;
	struct list_head	free_list;
	struct llist_head	resp_list;
	struct list_head	resp_send_list;
	int			send_list_len;
	struct nd_conn_request	*snd_request;

	/* recv state */
	int			offset;//当前接收的偏移量
	int			left;//剩余数据量
	enum ndt_conn_recv_state rcv_state;//接收状态
	struct dst_entry *dst;//描述路由信息？？？
	// struct nvmet_tcp_cmd	*cmd;
	// union nvme_tcp_pdu	pdu;
	// struct vs_hdr vs_hdr;
	/* digest state */
	bool			hdr_digest;//是否启用头部数据校验
	bool			data_digest;//是否启用数据内容校验
	struct ahash_request	*snd_hash;
	struct ahash_request	*rcv_hash;//发送/接收数据时的hash请求，用于数据校验或者加密

	spinlock_t		state_lock;//队列状态相关
	enum ndt_conn_queue_state state;

	struct sockaddr_storage	sockaddr;//本地ip地址信息
	struct sockaddr_storage	sockaddr_peer;//对端地址信息
	struct work_struct	release_work;//用于异步资源释放

	int			idx;//队列索引
	struct list_head	queue_list;//维护了一个队列链表，而不是像发送端一样一个core一个queue

	/* handle the HOL timer */
	//用于处理队头阻塞相关
	struct hrtimer		hol_timer;
	int hol_timeout_us;
	struct sk_buff *hol_skb;//指向hol队列中的数据包
	spinlock_t		hol_lock;
	struct work_struct	delay_ack_work;//处理ack的异步任务

    // struct list_head        hol_list;
	// struct nvmet_tcp_cmd	connect;

	struct page_frag_cache	pf_cache;
	//以下的回调函数都是保存的旧有的回调函数，新设置的回调函数直接被保存在套接字sock中
	void (*data_ready)(struct sock *);//回调函数，有数据时触发
	void (*state_change)(struct sock *);
	void (*write_space)(struct sock *);//回调函数，写缓冲区可用时触发
};

struct ndt_channel_entry {//ndt_conn_queue的链表节点
    struct ndt_conn_queue* queue;
    struct list_head list_link;
};

inline bool ndt_conn_is_latency(struct ndt_conn_queue *queue);
inline int queue_cpu(struct ndt_conn_queue *queue);
void ndt_conn_remove_port(struct ndt_conn_port *port);
int ndt_conn_alloc_queue(struct ndt_conn_port *port,
		struct socket *newsock);
void ndt_conn_io_work(struct work_struct *w);
void ndt_conn_io_work_lock_less(struct work_struct *w);
int ndt_conn_set_queue_sock(struct ndt_conn_queue *queue);
void ndt_conn_state_change(struct sock *sk);
void ndt_conn_write_space(struct sock *sk);
void ndt_conn_data_ready(struct sock *sk);
int ndt_init_conn_port(struct ndt_conn_port *port);
void ndt_conn_listen_data_ready(struct sock *sk);
void ndt_conn_accept_work(struct work_struct *w);
void ndt_conn_schedule_release_queue(struct ndt_conn_queue *queue);
void ndt_conn_release_queue_work(struct work_struct *w);
void ndt_conn_restore_socket_callbacks(struct ndt_conn_queue *queue);
int __init ndt_conn_init(void);
void ndt_conn_exit(void);

#endif /* _ND_TARGET_H */
