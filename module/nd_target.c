#include "nd_target.h"
#include "nd_impl.h"
#include "net_nd.h"
static DEFINE_IDA(ndt_conn_queue_ida);
static LIST_HEAD(ndt_conn_queue_list);
static DEFINE_MUTEX(ndt_conn_queue_mutex);

struct workqueue_struct *ndt_conn_wq;
struct workqueue_struct *ndt_conn_wq_lat;

static struct ndt_conn_port * ndt_port;

#define NDT_CONN_RECV_BUDGET		8
#define NDT_CONN_SEND_BUDGET		8
#define NDT_CONN_IO_WORK_BUDGET	128


static int cur_io_cpu = 0;

inline int queue_cpu(struct ndt_conn_queue *queue)//返回需要处理这个队列的cpu编号
{
	return queue->io_cpu;
	// return 0;
	// return queue->sock->sk->sk_incoming_cpu;
}

static inline void ndt_sk_eat_skb(struct sock *sk, struct sk_buff *skb)//清理套接字接收队列中的一个skb，与等待data_copy时候nd_clean_dcopy_page有所不同
{
	__skb_unlink(skb, &sk->sk_receive_queue);//从receive queue中删除
	if(skb->destructor) 
		skb->destructor(skb);
	/* get from skb_clone */
	skb->next = skb->prev = NULL;//更改队列指针
	skb->sk = NULL;//断开与套接字的联系
	skb->destructor = NULL;
}

/* copied from tcp_read_sock; the only change is adding pass_to_vs_layer before sending tcp ack. */
int ndt_tcp_read_sock(struct ndt_conn_queue* queue, read_descriptor_t *desc, sk_read_actor_t recv_actor)
{//从套接字中读取 TCP 数据，并通过回调函数处理数据，支持接收的同时进行特定操作
	struct sock *sk = queue->sock->sk;
	struct sk_buff *skb;
	struct tcp_sock *tp = tcp_sk(sk);//转化为TCP结构来访问TCP特有的成员
	u32 seq = tp->copied_seq;
	u32 offset;
	int copied = 0;
	// int hol_len = tp->rcvq_space.hol_len, hol_len_diff;
	if (sk->sk_state == TCP_LISTEN)
		return -ENOTCONN;
	while ((skb = tcp_recv_skb(sk, seq, &offset)) != NULL) {//不断读取接收数据进行处理，
	//tcp_recv_skb指定套接字的接收队列中取出序列号为seq的数据包并返回对应序列的偏移量？？？
	//位于传输层TCP处理完之后，本身不处理数据，只是将数据包传递给上层
	//调用之前，有tcp_v4_recv，tcp_data_queue, tcp_ack等相关操作
		if (offset < skb->len) {
			int used;
			size_t len;

			len = skb->len - offset;//等待处理的数据大小
			/* Stop reading if we hit a patch of urgent data */
			if (tp->urg_data) {//如果存在紧急数据，需要特殊处理
				WARN_ON(true);
				u32 urg_offset = tp->urg_seq - seq;
				if (urg_offset < len)
					len = urg_offset;//仅仅处理到紧急数据之前
				if (!len)
					break;
			}
			used = recv_actor(desc, skb, offset, len);//调用回调函数交付上层处理
			//实际上是调用了ndt_recv_skbs(desc, skb, offset, len)
			if (used <= 0) {
				if (!copied)
					copied = used;
				break;
			} else if (used <= len) {//又处理了一些有效数据，但是当前skb没有处理完，更新相应的序列号和偏移量
				seq += used;
				copied += used;
				offset += used;
			}
		}
		// if (TCP_SKB_CB(skb)->tcp_flags & TCPHDR_FIN) {
		// 	ndt_sk_eat_skb(sk, skb);
		// 	++seq;
		// 	break;
		// }
		// ndt_sk_eat_skb(sk, skb);
		if (!desc->count)//读取预算已经耗尽，退出循环
			break;
		WRITE_ONCE(tp->copied_seq, seq);
	}
	WRITE_ONCE(tp->copied_seq, seq);
	/* parsing packet; not sure if it should includes in while loop when accounting budget */
	pass_to_vs_layer(queue, &queue->receive_queue);//交付VNS层处理层处理
	/* get hol alloc diff */
	// hol_len_diff = atomic_read(&tp->hol_len) - hol_len;

	tcp_rcv_space_adjust(sk);
	// tp->rcvq_space.hol_len += hol_len_diff;
	// copied -= hol_len_diff;
	/* Clean up data we have read: This will do ACK frames. */
	if (copied > 0) {
		tcp_recv_skb(sk, seq, &offset);//这里再次调用是为了移除已经处理完了的数据包吗？？？
		// if(raw_smp_processor_id() == 8)
		// 	printk("may send ack");
		if(atomic_read(&tp->hol_alloc) == 0) {//如果没有HOL数据，调用tcp_cleanup_rbuf清收缓冲区并发送ACK
			tcp_cleanup_rbuf(sk, copied);
			if(hrtimer_active(&queue->hol_timer)) {
				hrtimer_cancel(&queue->hol_timer);
			}
		} else {
			/* setup a hrtimer */
			if(!hrtimer_active(&queue->hol_timer)) {
				hrtimer_start(&queue->hol_timer, ns_to_ktime(queue->hol_timeout_us *
					NSEC_PER_USEC), HRTIMER_MODE_REL_PINNED_SOFT);
			}
		}
	}
	return 0;
}

void ndt_conn_schedule_release_queue(struct ndt_conn_queue *queue)//异步调度释放指定的连接队列 queue
{
	spin_lock(&queue->state_lock);
	if (queue->state != NDT_CONN_Q_DISCONNECTING) {
		queue->state = NDT_CONN_Q_DISCONNECTING;
		schedule_work(&queue->release_work);//默认选择一个CPU进行release_work，并没有指定具体的CPU
	}
	spin_unlock(&queue->state_lock);
}

inline bool ndt_conn_is_latency(struct ndt_conn_queue *queue)
{
	return queue->prio_class == 1;
}

void ndt_conn_accept_work(struct work_struct *w)//处理连接接收（accept逻辑），从监听套接字 port->sock 接受新的连接
{
	struct ndt_conn_port *port = container_of(w, struct ndt_conn_port, accept_work);
	struct socket *newsock;//存储新接收的连接套接字（用于标识一个新的套接字连接）
	int ret;

	while (true) {
		ret = kernel_accept(port->sock, &newsock, O_NONBLOCK);//从监听套接字中接受新的连接
		if (ret < 0) {
			if (ret != -EAGAIN)
				pr_warn("failed to accept err=%d\n", ret);
			return;
		}
		ret = ndt_conn_alloc_queue(port, newsock);//接收到新的连接时新分配一个队列并且进行初始化
		if (ret) {
			pr_err("failed to allocate queue\n");
			sock_release(newsock);
		}
	}
}

void ndt_conn_listen_data_ready(struct sock *sk)
{
	struct ndt_conn_port *port;

	read_lock_bh(&sk->sk_callback_lock);
	port = sk->sk_user_data;
	if (!port)
		goto out;

	if (sk->sk_state == TCP_LISTEN)
		schedule_work(&port->accept_work);
out:
	read_unlock_bh(&sk->sk_callback_lock);
}

/* assign */
int ndt_init_conn_port(struct ndt_conn_port *port)
{
	// struct ndt_conn_port *port;
	char* local_ip = port->local_ip;
	char* local_port = port->local_port;

	__kernel_sa_family_t af;
	int opt, ret;

	// port = kzalloc(sizeof(*port), GFP_KERNEL);
	if (!port)
		return -ENOMEM;

	// switch (nport->disc_addr.adrfam) {
	// case NVMF_ADDR_FAMILY_IP4:
		af = AF_INET;
	// 	break;
	// case NVMF_ADDR_FAMILY_IP6:
	// 	af = AF_INET6;
	// 	break;
	// default:
	// 	pr_err("address family %d not supported\n",
	// 			nport->disc_addr.adrfam);
	// 	ret = -EINVAL;
	// 	goto err_port;
	// }

	ret = inet_pton_with_scope(&init_net, af, local_ip,	local_port, &port->addr);//将IP地址和端口号解析为sockaddr_storage格式存储在port->addr中
	if (ret) {
		pr_err("malformed ip/port passed: %s:%s\n", local_ip, local_port);
		goto err_port;
	}

	// port->nport = nport;
	INIT_WORK(&port->accept_work, ndt_conn_accept_work);//初始化接收连接工作队列任务
	// if (port->nport->inline_data_size < 0)
	// 	port->nport->inline_data_size = NVMET_TCP_DEF_INLINE_DATA_SIZE;

	ret = sock_create(port->addr.ss_family, SOCK_STREAM, IPPROTO_TCP, &port->sock);
	if (ret) {
		pr_err("failed to create a socket\n");
		goto err_port;
	}

	port->sock->sk->sk_user_data = port;
	port->data_ready = port->sock->sk->sk_data_ready;
	port->sock->sk->sk_data_ready = ndt_conn_listen_data_ready;//设置回调函数，用于监听状态下的数据到达时间
	opt = 1;
	ret = kernel_setsockopt(port->sock, IPPROTO_TCP, TCP_NODELAY, (char *)&opt, sizeof(opt));//设置套接字选项，有报文立刻发送
	if (ret) {
		pr_err("failed to set TCP_NODELAY sock opt %d\n", ret);
		goto err_sock;
	}
	// tcp_sock_set_nodelay(port->sock->sk);
	ret = kernel_setsockopt(port->sock, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt));//设置套接字选项，允许地址重用，即允许一个本地地址和端口被多个套接字绑定
	if (ret) {
		pr_err("failed to set SO_REUSEADDR sock opt %d\n", ret);
		goto err_sock;
	}
	// sock_set_reuseaddr(port->sock->sk);
	// tcp_sock_set_nodelay(port->sock->sk);
	// if (so_priority > 0)
	// 	sock_set_priority(port->sock->sk, so_priority);

	ret = kernel_bind(port->sock, (struct sockaddr *)&port->addr, sizeof(port->addr));//将新创建的套接字绑定到本地IP地址和端口号
	if (ret) {
		pr_err("failed to bind port socket %d\n", ret);
		goto err_sock;
	}

	ret = kernel_listen(port->sock, 128);
	//进入监听状态，并设置连接队列请求最大长度为128，当有连接建立请求时，会调用sk_data_ready回调函数，也就是之前设置的ndt_conn_listen_data_ready
	if (ret) {
		pr_err("failed to listen %d on port sock\n", ret);
		goto err_sock;
	}

	// nport->priv = port;
	pr_info("enabling port %s (%pISpc)\n",
		local_port, &port->addr);

	return 0;

err_sock:
	sock_release(port->sock);
err_port:
	// kfree(port);
	return ret;
}

void ndt_conn_release_queue_work(struct work_struct *w)
{
	struct ndt_conn_queue *queue =
		container_of(w, struct ndt_conn_queue, release_work);

	mutex_lock(&ndt_conn_queue_mutex);
	list_del_init(&queue->queue_list);//从conn_queue_list中删除当前queue
	mutex_unlock(&ndt_conn_queue_mutex);

	ndt_conn_restore_socket_callbacks(queue);//恢复初始回调函数
	flush_work(&queue->io_work);//等待io_work执行完成

	// nvmet_tcp_uninit_data_in_cmds(queue);
	// nvmet_sq_destroy(&queue->nvme_sq);
	cancel_work_sync(&queue->io_work);//linux实际上要求queue->io_work只能被有效调度一次，会忽略之后的调度
	sock_release(queue->sock);//释放套接字
	// nvmet_tcp_free_cmds(queue);
	// if (queue->hdr_digest || queue->data_digest)
	// 	nvmet_tcp_free_crypto(queue);
	ida_simple_remove(&ndt_conn_queue_ida, queue->idx);//释放标识符

	kfree(queue);
}

void ndt_conn_restore_socket_callbacks(struct ndt_conn_queue *queue)
{
	struct socket *sock = queue->sock;

	write_lock_bh(&sock->sk->sk_callback_lock);
	sock->sk->sk_data_ready =  queue->data_ready;
	sock->sk->sk_state_change = queue->state_change;
	sock->sk->sk_write_space = queue->write_space;
	sock->sk->sk_user_data = NULL;
	write_unlock_bh(&sock->sk->sk_callback_lock);
}

void ndt_conn_data_ready(struct sock *sk)
{
	struct ndt_conn_queue *queue;

	read_lock_bh(&sk->sk_callback_lock);
	queue = sk->sk_user_data;
	// if(raw_smp_processor_id() != 28) {
	// 	pr_info("the real processing core:%d\n", raw_smp_processor_id());
	// 	pr_info("queue_cpu(queue):%d\n", queue_cpu(queue));
	// }
	if (likely(queue)) {
		// pr_info("conn data ready\n");
		if(ndt_conn_is_latency(queue)) {
			queue_work_on(queue_cpu(queue), ndt_conn_wq_lat, &queue->io_work);
		} else {
			queue_work_on(queue_cpu(queue), ndt_conn_wq, &queue->io_work);
		}
	}
	read_unlock_bh(&sk->sk_callback_lock);
}

void ndt_conn_write_space(struct sock *sk)
{
	struct ndt_conn_queue *queue;

	read_lock_bh(&sk->sk_callback_lock);//上锁并且取参数（此处即为触发套接字所属的队列）
	queue = sk->sk_user_data;
	if (unlikely(!queue))
		goto out;

	if (unlikely(queue->state == NDT_CONN_Q_CONNECTING)) {//如果队列状态为正在建立连接，调用原始回调函数，采用默认逻辑处理
		queue->write_space(sk);
		goto out;
	}

	if (sk_stream_is_writeable(sk)) {//检查缓冲区是否有可用空间
		clear_bit(SOCK_NOSPACE, &sk->sk_socket->flags);//如果有，清除相应标记，并调度写操作
		if(ndt_conn_is_latency(queue)) {
			queue_work_on(queue_cpu(queue), ndt_conn_wq_lat, &queue->io_work);
		} else {
			queue_work_on(queue_cpu(queue), ndt_conn_wq, &queue->io_work);
		}
	}
out:
	read_unlock_bh(&sk->sk_callback_lock);
}

void ndt_conn_state_change(struct sock *sk)
{
	struct ndt_conn_queue *queue;

	write_lock_bh(&sk->sk_callback_lock);
	queue = sk->sk_user_data;
	if (!queue)
		goto done;

	switch (sk->sk_state) {
	case TCP_FIN_WAIT1:
	case TCP_CLOSE_WAIT:
	case TCP_CLOSE://这三个状态都表示TCP连接已经进入关闭状态，资源需要被释放
		/* FALLTHRU */
		sk->sk_user_data = NULL;
		ndt_conn_schedule_release_queue(queue);
		break;
	default:
		pr_warn("queue %d unhandled state %d\n",
			queue->idx, sk->sk_state);
	}
done:
	write_unlock_bh(&sk->sk_callback_lock);
}

void ndt_prepare_receive_pkts(struct ndt_conn_queue *queue)
{
	queue->offset = 0;
	// this part needed to be modified
	// queue->left = sizeof(struct tcp_hdr);
	// queue->cmd = NULL;
	queue->rcv_state = NDT_CONN_RECV_PDU;
}


int ndt_conn_set_queue_sock(struct ndt_conn_queue *queue)//设置套接字的地址信息、选项、优先级以及回调函数
{
	struct socket *sock = queue->sock;
	struct inet_sock *inet = inet_sk(sock->sk);
	struct linger sol = { .l_onoff = 1, .l_linger = 0 };
	int ret;
	// int bufsize = 3145728;
	// int optlen = sizeof(bufsize);

	//获取本地和发送端远程地址并保存
	ret = kernel_getsockname(sock, (struct sockaddr *)&queue->sockaddr);
	if (ret < 0)
		return ret;

	ret = kernel_getpeername(sock, (struct sockaddr *)&queue->sockaddr_peer);
	if (ret < 0)
		return ret;

	/*
	 * Cleanup whatever is sitting in the TCP transmit queue on socket
	 * close. This is done to prevent stale data from being sent should
	 * the network connection be restored before TCP times out.
	 */
	ret = kernel_setsockopt(sock, SOL_SOCKET, SO_LINGER, (char *)&sol, sizeof(sol));//设置 SO_LINGER 选项，确保在关闭套接字时清除 TCP 传输队列中的任何数据
	if (ret)
		return ret;
	
	//存储队列中的路由缓存信息，提供快速路径，优化网络包的接收和转发流程
	//避免每次需要路由信息时都从头查找，提高性能
	WARN_ON( READ_ONCE(sock->sk->sk_rx_dst) == NULL);
	if(queue->dst == NULL && READ_ONCE(sock->sk->sk_rx_dst) != NULL) {
		queue->dst = READ_ONCE(sock->sk->sk_rx_dst);
		dst_hold(queue->dst);//增加路由缓存的引用计数，防止路由缓存在未使用完毕时被释放
	}
	// pr_info("sk dst is null or not:%d\n", READ_ONCE(sock->sk->sk_rx_dst) != NULL);

	// sock_no_linger(sock->sk);
	// if (so_priority > 0)
	// 	sock_set_priority(sock->sk, so_priority);

	/* set buff size */
	// ret = kernel_setsockopt(queue->sock, SOL_SOCKET, SO_SNDBUF,
	// 	(char *)&bufsize, sizeof(bufsize));
	// ret = kernel_setsockopt(queue->sock, SOL_SOCKET, SO_RCVBUF,
	// 		(char *)&bufsize, sizeof(bufsize));
	// ret = kernel_getsockopt(queue->sock, SOL_SOCKET, SO_RCVBUF,
	// 	(char *)&bufsize, &optlen);
	// pr_info("ret value:%d\n", ret);
	// pr_info("buffer size receiver:%d\n", bufsize);
	/* Set socket type of service */
	if (inet->rcv_tos > 0) {//设置socket的服务类型，这里inet->rcv_tos是内核根据接收到的数据包的IP头解析之后填充的，表明了服务类型
		int tos = inet->rcv_tos;

		ret = kernel_setsockopt(sock, SOL_IP, IP_TOS,
				(char *)&tos, sizeof(tos));
		if (ret)
			return ret;
	}
	// if (inet->rcv_tos > 0)
	// 	ip_sock_set_tos(sock->sk, inet->rcv_tos);

	write_lock_bh(&sock->sk->sk_callback_lock);
	sock->sk->sk_user_data = queue;
	queue->data_ready = sock->sk->sk_data_ready;
	sock->sk->sk_data_ready = ndt_conn_data_ready;
	queue->state_change = sock->sk->sk_state_change;
	sock->sk->sk_state_change = ndt_conn_state_change;
	queue->write_space = sock->sk->sk_write_space;
	sock->sk->sk_write_space = ndt_conn_write_space;
	write_unlock_bh(&sock->sk->sk_callback_lock);

	return 0;
}


// bool  manual_create = true;
// uint32_t max_pkts = 0;
static int ndt_recv_skbs(read_descriptor_t *desc, struct sk_buff *orig_skb, unsigned int orig_offset, size_t orig_len)
{//接受并处理orig_skb指向的数据包
	struct ndt_conn_queue  *queue = (struct ndt_conn_queue *)desc->arg.data;
	struct sk_buff *skb;

	// skb = skb_clone(orig_skb, GFP_KERNEL);
	ndt_sk_eat_skb(queue->sock->sk, orig_skb);//首先将orig_skb从套接字的receive_queue中删除
	skb = orig_skb;
	__skb_queue_tail(&queue->receive_queue, skb);//之后放入自定义队列的receive_queue中？？？这样的目的是什么？？？
	ND_SKB_CB(skb)->orig_offset = orig_offset;
	if(skb_has_frag_list(skb)) {//检查skb是否包含分片列表为超大分片的skb，主要逻辑是判断是否包含分片列表
		ND_SKB_CB(skb)->has_old_frag_list = 1;//标识frag_list中有附带的skb
	} else {
		ND_SKB_CB(skb)->has_old_frag_list = 0;
	}
	desc->count -= 1;//减去收包额度，更新接受预算
	return orig_len;
}


int ndt_conn_try_recv(struct ndt_conn_queue *queue,	int budget, int *recvs)
{
	int ret = 0;
	struct socket *sock = queue->sock;
	read_descriptor_t desc;
	WARN_ON(!sock);
	if (unlikely(!sock || !sock->ops || !sock->ops->read_sock))
		return -EBUSY;
	desc.arg.data = queue;//这里相当于是给自定义的函数进行传参？？？
	desc.error = 0;
	desc.count = budget; /* give more than one skb per call */
// recv:
	lock_sock(sock->sk);
	/* sk should be locked here, so okay to do read_sock */
	ret = ndt_tcp_read_sock(queue, &desc, ndt_recv_skbs);
	release_sock(sock->sk);

	(*recvs) += budget - desc.count;//更新计数器
// done:
	return ret;
}

// static void ndt_conn_process_resp_list(struct ndt_conn_queue *queue)
// {
// 	struct llist_node *node;
// 	struct nd_conn_request *cmd;
//
// 	for (node = llist_del_all(&queue->resp_list); node; node = node->next) {
// 		cmd = llist_entry(node, struct nd_conn_request, lentry);
// 		list_add(&cmd->entry, &queue->resp_send_list);
// 		queue->send_list_len++;
// 	}
// }
//
// static struct nd_conn_request *ndt_conn_fetch_req(struct ndt_conn_queue *queue)
// {
// 	queue->snd_request = list_first_entry_or_null(&queue->resp_send_list,
// 				struct nd_conn_request, entry);
// 	if (!queue->snd_request) {
// 		ndt_conn_process_resp_list(queue);
// 		queue->snd_request =
// 			list_first_entry_or_null(&queue->resp_send_list,
// 					struct ndt_conn_req, entry);
// 		if (unlikely(!queue->snd_request))
// 			return NULL;
// 	}
//
// 	list_del_init(&queue->snd_request->entry);
// 	queue->send_list_len--;
//
// 	// if (nvmet_tcp_need_data_out(queue->snd_cmd))
// 	// 	nvmet_setup_c2h_data_pdu(queue->snd_cmd);
// 	// else if (nvmet_tcp_need_data_in(queue->snd_cmd))
// 	// 	nvmet_setup_r2t_pdu(queue->snd_cmd);
// 	// else
// 	// 	nvmet_setup_response_pdu(queue->snd_cmd);
//
// 	return queue->snd_request;
// }
//
// static int nvmet_conn_try_send_one(struct nvmet_tcp_queue *queue,
// 		bool last_in_batch)
// {
// // 	struct nd_conn_request *req = queue->snd_request;
// // 	int ret = 0;
//
// // 	if (!cmd || queue->state == NDT_CONN_Q_DISCONNECTING) {
// // 		cmd = ndt_conn_fetch_request(queue);
// // 		if (unlikely(!cmd))
// // 			return 0;
// // 	}
//
// // 	if (cmd->state == NVMET_TCP_SEND_DATA_PDU) {
// // 		ret = nvmet_try_send_data_pdu(cmd);
// // 		if (ret <= 0)
// // 			goto done_send;
// // 	}
//
// // 	if (cmd->state == NVMET_TCP_SEND_DATA) {
// // 		ret = nvmet_try_send_data(cmd, last_in_batch);
// // 		if (ret <= 0)
// // 			goto done_send;
// // 	}
//
// // 	if (cmd->state == NVMET_TCP_SEND_DDGST) {
// // 		ret = nvmet_try_send_ddgst(cmd, last_in_batch);
// // 		if (ret <= 0)
// // 			goto done_send;
// // 	}
//
// // 	if (cmd->state == NVMET_TCP_SEND_R2T) {
// // 		ret = nvmet_try_send_r2t(cmd, last_in_batch);
// // 		if (ret <= 0)
// // 			goto done_send;
// // 	}
//
// // 	if (cmd->state == NVMET_TCP_SEND_RESPONSE)
// // 		ret = nvmet_try_send_response(cmd, last_in_batch);
//
// // done_send:
// // 	if (ret < 0) {
// // 		if (ret == -EAGAIN)
// // 			return 0;
// // 		return ret;
// // 	}
//
// // 	return 1;
// 	return 1;
// }
//
// static int ndt_conn_try_send(struct nvmet_tcp_queue *queue,
// 		int budget, int *sends)
// {
// 	int i, ret = 0;
//
// 	for (i = 0; i < budget; i++) {
// 		ret = ndt_conn_try_send_one(queue, i == budget - 1);
// 		// if (unlikely(ret < 0)) {
// 		// 	ndt_tcp_socket_error(queue, ret);
// 		// 	goto done;
// 		// } else if (ret == 0) {
// 		// 	break;
// 		// }
// 		(*sends)++;
// 	}
// done:
// 	return ret;
// }

void ndt_conn_io_work(struct work_struct *w)
{
	struct ndt_conn_queue *queue = container_of(w, struct ndt_conn_queue, io_work);
	bool pending, hol = false;
	int ret, ops = 0;

	int optlen, bufsize;
	sock_rps_record_flow(queue->sock->sk);
	/* To Do: check if pending skbs are in the queue; reinsert first, if fails, sleep and register hrtimer */
	// spin_lock_bh(&queue->hol_lock);
	// if(queue->hol_skb) {
	// 	WARN_ON(!hrtimer_active(&queue->hol_timer));
	// 	// local_bh_disable();
	// 	ret = nd_rcv(queue->hol_skb);
	// 	if(ret != -1) {
	// 		/* cancel hrtimer */
	// 		hrtimer_cancel(&queue->hol_timer);
	// 		queue->hol_skb = NULL;
	// 	} else {
	// 		hol = true;
	// 	}
	// 	// local_bh_enable();
	// }
	// spin_unlock_bh(&queue->hol_lock);
	if(hol) {
		// ret = kernel_getsockopt(queue->sock, SOL_SOCKET, SO_RCVBUF,
		// (char *)&bufsize, &optlen);
		// pr_info("buffer size receiver:%d\n", bufsize);
		// printk("hol return :%d \n", raw_smp_processor_id());
		return;//有队头阻塞时直接返回不执行，等待之后的定时器处理或者下一次调度到时再看看是否还有队头阻塞现象
	}
	do {
		pending = false;
		ret = ndt_conn_try_recv(queue, NDT_CONN_IO_WORK_BUDGET - ops, &ops);
		if (ret > 0) {
			pending = true;
		} 
		else if (ret < 0) {
			// pr_info("ret < 0 \n");
			return;
		}
		/* parsing packet; not sure if it should includes in while loop when accounting budget */
		// ret = pass_to_vs_layer(queue, &queue->receive_queue);
		// if(ret < 0)
		// 	return;
		// pr_info("ops:%d\n", ops);
		// ret = ndt_conn_try_send(queue, NDT_CON_SEND_BUDGET, &ops);
		// if (ret > 0)
		// 	pending = true;
		// else if (ret < 0)
			// return;

	} while (pending && ops < NDT_CONN_IO_WORK_BUDGET);//不断尝试收包，直到收包预算用完或者没有包可收
	// ret = kernel_getsockopt(queue->sock, SOL_SOCKET, SO_RCVBUF,
	// 	(char *)&bufsize, &optlen);
	// pr_info("ret value:%d\n", ret);
	// pr_info("buffer size receiver:%d\n", bufsize);
	// /*
	//  * We exahusted our budget, requeue our selves
	//  */
	if (pending) {//如果有没有完成的任务，重新调度工作项
		// pr_info("pending is true\n");
		if(ndt_conn_is_latency(queue)) {
			queue_work_on(queue_cpu(queue), ndt_conn_wq_lat, &queue->io_work);
		} else {
			queue_work_on(queue_cpu(queue), ndt_conn_wq, &queue->io_work);
		}
	}
}

void ndt_delay_ack_work(struct work_struct *w) {
	struct ndt_conn_queue *queue =	container_of(w, struct ndt_conn_queue, delay_ack_work);
	struct socket *sock = queue->sock;
	WARN_ON(!sock);
	if (unlikely(!sock))
		return;
	/* try to send delay*/
	lock_sock(sock->sk);

	// if(raw_smp_processor_id() == 8)
//	pr_info("send delay ack; hol alloc:%d\n", atomic_read(&tcp_sk(sock->sk)->hol_alloc));
	__tcp_send_ack(sock->sk, tcp_sk(sock->sk)->rcv_nxt);
	release_sock(sock->sk);
	if(atomic_read(&tcp_sk(sock->sk)->hol_alloc) != 0) {//如果有HOL数据，重新启动定时器
		// if(!hrtimer_active(&queue->hol_timer))
			hrtimer_start(&queue->hol_timer, ns_to_ktime(queue->hol_timeout_us *
					NSEC_PER_USEC), HRTIMER_MODE_REL_PINNED_SOFT);
		return;
	}
}

enum hrtimer_restart ndt_hol_timer_handler(struct hrtimer *timer)
{
	struct ndt_conn_queue *queue =
		container_of(timer, struct ndt_conn_queue,
			hol_timer);
// 	struct ndt_channel_entry* entry;
// 	int ret = 0;
// 	spin_lock_bh(&queue->hol_lock);
//     WARN_ON(!queue->hol_skb);
// 	nd_handle_hol_data_pkt(queue->hol_skb);
// 	/* clean hol_skb state */
// 	queue->hol_skb = NULL;
// 	spin_unlock_bh(&queue->hol_lock);
// 	// printk("timer handler: set hol skb to be null:%d\n", raw_smp_processor_id());
// resume_channel:

 	/* send the delay ack */
	if(ndt_conn_is_latency(queue)) {
		queue_work_on(queue_cpu(queue), ndt_conn_wq_lat, &queue->delay_ack_work);
	} else {
		queue_work_on(queue_cpu(queue), ndt_conn_wq, &queue->delay_ack_work);
	}
	return HRTIMER_NORESTART;
}


int ndt_conn_alloc_queue(struct ndt_conn_port *port, struct socket *newsock)//分配连接队列
{
	struct ndt_conn_queue *queue;
	int ret;

	queue = kzalloc(sizeof(*queue), GFP_KERNEL);
	if (!queue)
		return -ENOMEM;

	INIT_WORK(&queue->release_work, ndt_conn_release_queue_work);
	INIT_WORK(&queue->io_work, ndt_conn_io_work);
	queue->sock = newsock;
	/* initialize the recvspace */
	tcp_sk(queue->sock->sk)->rcvq_space.hol_len = 0;//初始化head of line数据长度为0
	queue->port = port;
	queue->snd_request = NULL;
	/* initialize the hrtimer for HOL */
	hrtimer_init(&queue->hol_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL_PINNED_SOFT);
	queue->hol_timer.function = &ndt_hol_timer_handler;//设置HOL数据超时处理函数
	queue->hol_skb = NULL;
	queue->hol_timeout_us = 1000;
	INIT_WORK(&queue->delay_ack_work, ndt_delay_ack_work);//绑定HOL时异步ACK发送函数
	// INIT_LIST_HEAD(&queue->hol_list);
	// queue->nr_cmds = 0;
	spin_lock_init(&queue->state_lock);
	spin_lock_init(&queue->hol_lock);
	queue->state = NDT_CONN_Q_CONNECTING;//队列状态设置为正在进行连接
	INIT_LIST_HEAD(&queue->free_list);
	init_llist_head(&queue->resp_list);
	INIT_LIST_HEAD(&queue->resp_send_list);
	skb_queue_head_init(&queue->receive_queue);//初始化接收队列，其为带锁链表
	queue->idx = ida_simple_get(&ndt_conn_queue_ida, 0, 0, GFP_KERNEL);//分配一个唯一的ID用于标识，但是之后这个ID又用于区分队列的类型是taillatency还是普通的？？？
	if (queue->idx < 0) {
		ret = queue->idx;
		goto out_free_queue;
	}
	if (queue->idx >= nd_params.total_channels / 2) {
		/* latency-sensitive channel */
		queue->prio_class = 1;
	} else
		/* throughput-bound i10-lanes */
		queue->prio_class = 0;

	// ret = nvmet_tcp_alloc_cmd(queue, &queue->connect);
	// if (ret)
	// 	goto out_ida_remove;
	//
	// ret = nvmet_sq_init(&queue->nvme_sq);
	// if (ret)
	// 	goto out_free_connect;

	ndt_prepare_receive_pkts(queue);//为接收数据包初始化必要的资源

	mutex_lock(&ndt_conn_queue_mutex);
	list_add_tail(&queue->queue_list, &ndt_conn_queue_list);
	mutex_unlock(&ndt_conn_queue_mutex);

	ret = ndt_conn_set_queue_sock(queue);//初始化套接字相关设置
	if (ret)
		goto out_destroy_sq;
	
	// hard code for now
	queue->io_cpu = (cur_io_cpu * nd_params.nr_nodes) % nd_params.nr_cpus;//采用round_robin为当前队列分配一个处理CPU，直接使用所有能用的CPU
	cur_io_cpu += 1;
	if(ndt_conn_is_latency(queue)) {
		queue_work_on(queue_cpu(queue), ndt_conn_wq_lat, &queue->io_work);//这里第二个参数的作用是决定了调度的上下文，在创建时决定了这个是一个高优先级的队列
	} else {
		queue_work_on(queue_cpu(queue), ndt_conn_wq, &queue->io_work);
	}

	return 0;
out_destroy_sq://分配时出了问题，进行相关资源的回收
	mutex_lock(&ndt_conn_queue_mutex);
	list_del_init(&queue->queue_list);
	mutex_unlock(&ndt_conn_queue_mutex);
	// nvmet_sq_destroy(&queue->nvme_sq);
// out_free_connect:
	// nvmet_tcp_free_cmd(&queue->connect);
// out_ida_remove:
	ida_simple_remove(&ndt_conn_queue_ida, queue->idx);//移除计数器
out_free_queue:
	kfree(queue);
	return ret;
}

void ndt_conn_remove_port(struct ndt_conn_port *port)
{
	// struct nvmet_tcp_port *port = nport->priv;
	write_lock_bh(&port->sock->sk->sk_callback_lock);
	port->sock->sk->sk_data_ready = port->data_ready;
	port->sock->sk->sk_user_data = NULL;
	write_unlock_bh(&port->sock->sk->sk_callback_lock);
	cancel_work_sync(&port->accept_work);//取消监听工作项

	sock_release(port->sock);
	kfree(port);
}

int __init ndt_conn_init(void)
{
	int ret;

	ndt_conn_wq = alloc_workqueue("ndt_conn_wq", 0, 0);
	if (!ndt_conn_wq)
		return -ENOMEM;
	ndt_conn_wq_lat =  alloc_workqueue("ndt_conn_wq_lat", WQ_HIGHPRI, 0);//标识为高优先级
	if(!ndt_conn_wq_lat)
		return -ENOMEM;
	ndt_port = kzalloc(sizeof(*ndt_port), GFP_KERNEL);
	ndt_port->local_ip = nd_params.local_ip;//初始化端口的本地IP和端口号，端口号为9000与发送端一致
	//也就是说在发送端底层的多个Channel的TCP套接字都会连接到这个端口上，从而创建多个队列
	ndt_port->local_port = "9000";
	ret = ndt_init_conn_port(ndt_port);
	// ret = nvmet_register_transport(&nvmet_tcp_ops);
	if (ret)
	 	goto err;

	return 0;
err:
	destroy_workqueue(ndt_conn_wq);//这里为什么仅仅摧毁conn_wq而没有摧毁conn_wq_lat？？？
	ndt_conn_remove_port(ndt_port);
	return ret;
}

void ndt_conn_exit(void)
{
	struct ndt_conn_queue *queue;

	// nvmet_unregister_transport(&nvmet_tcp_ops);

	flush_scheduled_work();//等待所有调度的工作项完成
	mutex_lock(&ndt_conn_queue_mutex);
	list_for_each_entry(queue, &ndt_conn_queue_list, queue_list) {//遍历连接队列
		kernel_sock_shutdown(queue->sock, SHUT_RDWR);//关闭套接字
		dst_release(queue->dst);//释放目标缓存路由表的引用计数
		queue->dst = NULL;
	}
	mutex_unlock(&ndt_conn_queue_mutex);
	flush_scheduled_work();

	destroy_workqueue(ndt_conn_wq);//销毁工作队列，这里为什么仅仅销毁了ndt_conn_wq而没有销毁ndt_conn_wq_lat？？？？
	ndt_conn_remove_port(ndt_port);//清理监听端口相关的资源
}
