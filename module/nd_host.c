#include "nd_host.h"
#include "nd_impl.h"
// static LIST_HEAD(nd_conn_ctrl_list);
static DEFINE_MUTEX(nd_conn_ctrl_mutex);
static struct workqueue_struct *nd_conn_wq;
static struct workqueue_struct *nd_conn_wq_lat;
static struct workqueue_struct *sock_wait_wq;//与套接字等待相关？？？

// struct nd_conn_ctrl* nd_ctrl;
// static struct blk_mq_ops nvme_tcp_mq_ops;
// static struct blk_mq_ops nvme_tcp_admin_mq_ops;

/*  conn_table is read-only for now so that we don't need lock in the hot path; 
TO DO: add the lock once the dynamic adding/removing logic has been added.
This also requires the change of ctrl->io_queue logic. 
*/
/* conn_table has 2^8 slots */
DECLARE_HASHTABLE(nd_conn_table, 8);

static inline bool nd_conn_has_inline_data(struct nd_conn_request *req) {//报文是否包含了实际的数据字段
	struct ndhdr* hdr = req->hdr;
	return hdr->type == DATA;
}

static inline int nd_conn_queue_id(struct nd_conn_queue *queue)//要求conn_queue被组织成一个数组吗？
{
	return queue - queue->ctrl->queues;
}

static inline bool nd_conn_queue_is_lat(struct nd_conn_queue *queue)
{
	return queue->prio_class == 1;
}

static inline void nd_conn_done_send_req(struct nd_conn_queue *queue)//发送结束之后释放相关的资源，如skb等
{
	struct ndhdr* hdr = queue->request->hdr;
	if(hdr->type == DATA) //释放实际的数据字段的skb
		kfree_skb(queue->request->skb);
	/* pdu doesn't have to be freed */
	// kfree(queue->request->pdu);
	// put_page(queue->request->hdr);
	page_frag_free(queue->request->hdr);
	kfree(queue->request);
	queue->request = NULL;
	
}

static inline bool nd_conn_queue_more(struct nd_conn_queue *queue)//是否还有请求要处理
{
	return !list_empty(&queue->send_list) ||
		!llist_empty(&queue->req_list) || queue->more_requests;
}

void nd_conn_restore_sock_calls(struct nd_conn_queue *queue)//恢复套接字回调函数（设置套接字回调函数），以便在（数据到达、状态变化）等网络事件发生的时候正确执行并相应
{
	struct socket *sock = queue->sock;

	write_lock_bh(&sock->sk->sk_callback_lock);
	sock->sk->sk_user_data  = NULL;
	sock->sk->sk_data_ready = queue->data_ready;
	sock->sk->sk_state_change = queue->state_change;
	sock->sk->sk_write_space  = queue->write_space;
	write_unlock_bh(&sock->sk->sk_callback_lock);
}

void __nd_conn_stop_queue(struct nd_conn_queue *queue)
{
	kernel_sock_shutdown(queue->sock, SHUT_RDWR);
	nd_conn_restore_sock_calls(queue);//避免停止之后，套接字触发不必要的事件或者回调，同时在发送和接收时可能采用自定义的回调函数，队列停止后恢复回调函数
	cancel_work_sync(&queue->io_work);//停止IO任务
}

void nd_conn_stop_queue(struct nd_conn_ctrl *ctrl, int qid)
{
	struct nd_conn_queue *queue = &ctrl->queues[qid];

	if (!test_and_clear_bit(ND_CONN_Q_LIVE, &queue->flags))//如果之前该位上已经是0（表示不活跃），则直接返回，否则需要进一步停止该队列
		return;
	__nd_conn_stop_queue(queue);
}

void nd_conn_free_queue(struct nd_conn_ctrl *ctrl, int qid)
{
	// struct nvme_tcp_ctrl *ctrl = to_tcp_ctrl(nctrl);
	struct nd_conn_queue *queue = &ctrl->queues[qid];

	if (!test_and_clear_bit(ND_CONN_Q_ALLOCATED, &queue->flags))
		return;

	// if (queue->hdr_digest || queue->data_digest)
	// 	nvme_tcp_free_crypto(queue);

	sock_release(queue->sock);//关闭并且释放套接字？？？
	if(queue->request)//存在未完成的请求，额外释放资源？？？
		nd_conn_done_send_req(queue);
	// kfree(queue->pdu);
}

void nd_conn_free_io_queues(struct nd_conn_ctrl *ctrl)//释放该控制配置下的所有队列？？？
{
	int i;

	for (i = 0; i < ctrl->queue_count; i++)
		nd_conn_free_queue(ctrl, i);
}

int nd_conn_start_queue(struct nd_conn_ctrl *ctrl, int idx)
{
	// struct nvme_tcp_ctrl *ctrl = to_tcp_ctrl(nctrl);
	int ret = 0;

	// if (idx)
	// 	ret = nvmf_connect_io_queue(nctrl, idx, false);
	// else
	// 	ret = nvmf_connect_admin_queue(nctrl);

	// if (!ret) {
		set_bit(ND_CONN_Q_LIVE, &ctrl->queues[idx].flags);//置位来启动队列

	// } else {
	// 	if (test_bit(NVME_TCP_Q_ALLOCATED, &ctrl->queues[idx].flags))
	// 		__nvme_tcp_stop_queue(&ctrl->queues[idx]);
	// 	dev_err(nctrl->device,
	// 		"failed to connect queue: %d ret=%d\n", idx, ret);
	// }
	return ret;
}

void nd_conn_stop_io_queues(struct nd_conn_ctrl *ctrl)
{
	int i;

	for (i = 0; i < ctrl->queue_count; i++)
		nd_conn_stop_queue(ctrl, i);
}

void nd_conn_data_ready(struct sock *sk)//data_ready的回调函数，这里并没有显示调用套接字的回调函数，为什么要上读锁？？？
{//这里上读锁是因为sk_user_data中存了回调函数，防止其被更改？？？
	struct nd_conn_queue *queue;

	read_lock_bh(&sk->sk_callback_lock);//获取套接字的回调锁，禁止在此时修改套接字的回调函数
	queue = sk->sk_user_data;
	if (likely(queue && queue->rd_enabled) &&
	    !test_bit(ND_CONN_Q_POLLING, &queue->flags)) {//如果队列存在，且队列可读，且队列不是轮询队列，将放入到相应的conn_queue中
			if(nd_conn_queue_is_lat(queue)) {
				queue_work_on(queue->io_cpu, nd_conn_wq_lat, &queue->io_work);
			}else {
				queue_work_on(queue->io_cpu, nd_conn_wq, &queue->io_work);
			}
		}
	read_unlock_bh(&sk->sk_callback_lock);
}

void nd_conn_write_space(struct sock *sk)
{
	struct nd_conn_queue *queue;

	read_lock_bh(&sk->sk_callback_lock);
	queue = sk->sk_user_data;
	if (likely(queue && sk_stream_is_writeable(sk))) {//写缓冲区是否有足够的空间来接收
		// printk("write space invoke\n");
		clear_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
			if(nd_conn_queue_is_lat(queue)) {
				queue_work_on(queue->io_cpu, nd_conn_wq_lat, &queue->io_work);
			}else {
				queue_work_on(queue->io_cpu, nd_conn_wq, &queue->io_work);
			}
	}
	read_unlock_bh(&sk->sk_callback_lock);
}

void nd_conn_state_change(struct sock *sk)
{
	struct nd_conn_queue *queue;

	read_lock(&sk->sk_callback_lock);
	queue = sk->sk_user_data;
	if (!queue)
		goto done;

	switch (sk->sk_state) {
	case TCP_CLOSE:
	case TCP_CLOSE_WAIT:
	case TCP_LAST_ACK:
	case TCP_FIN_WAIT1:
	case TCP_FIN_WAIT2:
        // this part might have issue
        pr_info("TCP state change:%d\n", sk->sk_state);
		// nd_conn_error_recovery(&ctrl);
		break;
	default:
		pr_info("queue %d socket state %d\n",
			nd_conn_queue_id(queue), sk->sk_state);
	}

	queue->state_change(sk);//调用相关回调函数进行处理
done:
	read_unlock(&sk->sk_callback_lock);
}

/* round-robin; will not select the previous one except if there is only one channel. */
int nd_conn_sche_rr(struct nd_conn_queue* queues, int last_q, int cur_count, int prio_class, bool avoid_check) {//？？？？？到底是什么意思？？？？？
	//avoid_check表示是否允许跳过队列检查？？？
	struct nd_conn_queue *queue;
	/* cur_count tracks how many skbs has been sent for the current queue before going to the next queue */
	// static u32;
	int i = 0, qid = last_q;
	int lower_bound = 0;
	int num_queue = 0;
	if(prio_class) {//根据不同的类型来获取上一次选择的Channel的编号以及Channel数量
		lower_bound = nd_params.lat_channel_idx;
		num_queue = nd_params.num_lat_channels;
	} else {
		lower_bound = nd_params.thpt_channel_idx;
		num_queue =  nd_params.num_thpt_channels;
	}
	// if(nd_params.nd_num_queue == 1)
	// 	i = 0;
	/* advance to the next queue */
	if(cur_count >= queues[last_q].compact_low_thre) {
		//如果当前的队列大于了low_thre，那么切换到下一个队列，也即是尽量往一个队列里放，放大于阈值了才放到下一个里
		//？？？
		last_q = (last_q + 1) % num_queue + lower_bound;
		// cur_count = 0;
	}
	for (; i < num_queue; i++) {
		/* select queue */
		qid = (last_q + i) % num_queue + lower_bound;
		queue =  &queues[qid];
		// WARN_ON(cur_count >= queue->compact_low_thre);

		if(atomic_read(&queue->cur_queue_size) 
			>= queue->queue_size) {//该队列的容量已经满了，换下一个
			/* update the count */
			// cur_count = 0;
			continue;
		} else {
			// cur_count++;
		}
		// atomic_add(1, &queue->cur_queue_size);
		last_q = qid;
		return qid;//选中了应该直接返回，但是下面还有内容也就是没有选中
	}
	if(avoid_check) {//找了一圈没有找到，如果允许跳过队列检查，直接选择下一个队列，否则返回没有可用队列
		qid = (1 + last_q) % num_queue + lower_bound;
		queue =  &queues[qid];
		// atomic_add(1, &queue->cur_queue_size);
		last_q = qid;
		return last_q;
	}
	return -1;//找了一圈没有找到合适的队列，返回-1
}

/* round-robin; will not select the previous one except if there is only one channel. */
int nd_conn_sche_low_lat(void) {
	return  raw_smp_processor_id() / nd_params.nr_nodes + nd_params.lat_channel_idx;
}

/* round-robin; will not select the previous one except if there is only one channel. */
int nd_conn_sche_src_port(struct nd_conn_queue *queues, int src_port, bool avoid_check, int pri_class) {//根据源端口号进行hash
        struct nd_conn_queue *queue;
        int qid;
        if(pri_class)
            qid = src_port % nd_params.num_lat_channels + nd_params.lat_channel_idx;
        else
            qid = src_port % nd_params.num_thpt_channels + nd_params.thpt_channel_idx;
        queue = &queues[qid];
        if(atomic_read(&queue->cur_queue_size)
                >= queue->queue_size && !avoid_check) {//当前不可用并且不允许跳过检查，返回-1表示没有可用队列
                /* update the count */
                // cur_count = 0;
                return -1;
        } else {
                return qid;
                // cur_count++;
        }
        return -1;
}

/* stick on one queue if the queue size is below than threshold; */
// int nd_conn_sche_compact(bool avoid_check) {
// 	struct nd_conn_queue *queue;
// 	static u32 last_q = 0;
// 	int i = 1, qid;
// 	/* try low threshold first */
// 	for (i = 0; i < nd_params.nd_num_queue; i++) {

// 		qid = (i) % (nd_params.nd_num_queue);
// 		queue =  &nd_ctrl->queues[qid];
// 		if(atomic_fetch_add_unless(&queue->cur_queue_size, 1, queue->compact_low_thre) 
// 			== queue->compact_low_thre) {
// 			continue;
// 		}
// 		WARN_ON(atomic_read(&queue->cur_queue_size) > queue->compact_low_thre);
// 		// if(qid == 1){
// 		// 	printk("qid 1 is being used\n");
// 		// }
// 		last_q = qid;
// 		return last_q;
// 	}
// 	/* then try high threshold*/
// 	// for (i = 0; i < nd_params.nd_num_queue; i++) {

// 	// 	qid = (i) % (nd_params.nd_num_queue);
// 	// 	queue =  &nd_ctrl->queues[qid];
// 	// 	if(atomic_fetch_add_unless(&queue->cur_queue_size, 1, queue->compact_high_thre) 
// 	// 		== queue->compact_high_thre) {
// 	// 		continue;
// 	// 	}
// 	// 	last_q = qid;
// 	// 	return last_q;
// 	// }
// 	/* when all queues become full and avoid check is true */
// 	/* do rr */
// 	if(avoid_check) {
// 		qid = (1 + last_q) % (nd_params.nd_num_queue);
// 		queue =  &nd_ctrl->queues[qid];
// 		atomic_add(1, &queue->cur_queue_size);
// 		last_q = qid;
// 		return last_q;
// 	}
// 	return -1;
// }

/* find nd_ctrl based on dest ip address */
void* nd_conn_find_nd_ctrl(__be32 dst_addr) {//根据目标IP地址从hash表中找到对应的nd_ctrl
	struct nd_conn_ctrl *nd_ctrl;
	/*find the nd ctrl */
	hash_for_each_possible(nd_conn_table, nd_ctrl, hlist, dst_addr) {
		return nd_ctrl;
		break;
	} 
	return NULL;
}

bool nd_conn_queue_request(struct nd_conn_request *req, struct nd_sock *nsk, bool sync, bool avoid_check, bool last)
{	//last指示是否为最后一个请求
    struct inet_sock *inet = inet_sk((struct sock*)nsk);
	struct nd_conn_queue *queue = req->queue, *last_q;
	struct nd_conn_ctrl *nd_ctrl = nsk->nd_ctrl;
	// static u32 queue_id = 0;
	bool empty;
	// bool push = false;
	int ret;
	int qid = 0;
	WARN_ON(nsk == NULL);
	if(queue == NULL) { //如果queue为空，说明是第一次请求，需要选择一个合适的队列
		/* hard code for now */
		// queue_id = (smp_processor_id() - 16) / 4;
		// if(req->prio_class)
		// 	qid = nd_conn_sche_low_lat();
		// else
	//		qid = nd_conn_sche_rr(nsk->sender.con_queue_id, nsk->sender.con_accumu_count, req->prio_class, avoid_check);
		if(nsk->sche_policy == SCHE_SRC_PORT)
			qid = nd_conn_sche_src_port(nd_ctrl->queues, ntohs(inet->inet_sport), avoid_check, req->prio_class);
		else if(nsk->sche_policy == SCHE_RR)
			qid = nd_conn_sche_rr(nd_ctrl->queues, nsk->sender.con_queue_id, nsk->sender.con_accumu_count, req->prio_class, avoid_check);
		if(qid < 0) {//没有选择成功，唤醒先前的队列来继续处理？？？
			/* wake up previous queue */
			if(nsk->sender.con_queue_id != - 1) {
				last_q =  &nd_ctrl->queues[nsk->sender.con_queue_id];
				if(nd_conn_queue_is_lat(last_q)) {
					queue_work_on(last_q->io_cpu, nd_conn_wq_lat, &last_q->io_work);
				}else {
					queue_work_on(last_q->io_cpu, nd_conn_wq, &last_q->io_work);
				}					
			}
			return false;
		}
		req->queue = &nd_ctrl->queues[qid];
		// req->queue =  &nd_ctrl->queues[6];
		queue = req->queue;
		atomic_add(1, &queue->cur_queue_size);
		/* update nsk state */
		if(nsk->sche_policy == SCHE_RR) {
			if(qid == nsk->sender.con_queue_id)//正在使用之前的队列，增加计数器
				nsk->sender.con_accumu_count += 1;
			else {
				/* wake up previous queue */
				// printk("wake up previous channel:%d\n", nsk->sender.con_queue_id);
				if(nsk->sender.con_queue_id != - 1) {//换了新的队列，同样唤醒之前的队列？？？
					last_q =  &nd_ctrl->queues[nsk->sender.con_queue_id];
					if(nd_conn_queue_is_lat(last_q)) {
						queue_work_on(last_q->io_cpu, nd_conn_wq_lat, &last_q->io_work);
					}else {
						queue_work_on(last_q->io_cpu, nd_conn_wq, &last_q->io_work);
					}					
				}
				/* reinitalize the sk state */
				nsk->sender.con_accumu_count = 1;
			}
		}
		nsk->sender.con_queue_id = qid;
		// queue_id += 1;
	} else {
		atomic_add(1, &queue->cur_queue_size);
	}
	// bytes_sent[qid] += 1;
	WARN_ON(req->queue == NULL);
	// if(!avoid_check){
	// 	if(atomic_fetch_add_unless(&queue->cur_queue_size, 1, queue->queue_size) 
	// 	== queue->queue_size)
	// 		return false;
	// }
	empty = llist_add(&req->lentry, &queue->req_list) &&
		list_empty(&queue->send_list) && !queue->request;//send_list为空，没有可以发送的数据包？？？，并且没有数据正在处理

	/*
	 * if we're the first on the send_list and we can try to send
	 * directly, otherwise queue io_work. Also, only do that if we
	 * are on the same cpu, so we don't introduce contention.
	 */
	if (queue->io_cpu == smp_processor_id() &&
	    sync && empty && mutex_trylock(&queue->send_mutex)) {
		// queue->more_requests = !last;
		ret = nd_conn_try_send(queue);//尝试直接发送数据
		// if(ret == -EAGAIN)
		// 	queue->more_requests = false;
		mutex_unlock(&queue->send_mutex);
	} else if(last){//last为最后一个数据包？？？
		//放入队列中等待处理
		/* data packets always go here */
		// printk("wake up last channel:%d\n", nsk->sender.con_queue_id);
		if(nd_conn_queue_is_lat(queue)) {
			queue_work_on(queue->io_cpu, nd_conn_wq_lat, &queue->io_work);
		}else {
			queue_work_on(queue->io_cpu, nd_conn_wq, &queue->io_work);
		}
	}
	return true;
}

void nd_conn_teardown_ctrl(struct nd_conn_ctrl *ctrl, bool shutdown)
{
	nd_conn_teardown_io_queues(ctrl, shutdown);
}

void nd_conn_delete_ctrl(struct nd_conn_ctrl *ctrl)
{
	nd_conn_teardown_ctrl(ctrl, true);
	hash_del(&ctrl->hlist);//将控制器从hash表中删除
	// flush_workqueue(ctrl->sock_wait_wq);
	// destroy_workqueue(ctrl->sock_wait_wq);
    /* free option here */
	kfree(ctrl->queues);
    kfree(ctrl->opts);
	kfree(ctrl);
}

void nd_conn_teardown_io_queues(struct nd_conn_ctrl *ctrl, bool remove)
{
	mutex_lock(&ctrl->teardown_lock);
    // might need to change later
	// if (ctrl->queue_count <= 1)
	// 	goto out;
	nd_conn_stop_io_queues(ctrl);
	nd_conn_destroy_io_queues(ctrl, remove);
	mutex_unlock(&ctrl->teardown_lock);
}

unsigned int nd_conn_nr_io_queues(struct nd_conn_ctrl *ctrl)//计算需要分配的io_queue的数量
{
	unsigned int nr_io_queues;

	nr_io_queues = min(ctrl->opts->nr_io_queues, num_online_cpus());
	// nr_io_queues += min(ctrl->opts->nr_write_queues, num_online_cpus());
	// nr_io_queues += min(ctrl->opts->nr_poll_queues, num_online_cpus());

	return nr_io_queues;
}

int nd_conn_alloc_io_queues(struct nd_conn_ctrl *ctrl)//首先根据ctrl配置信息计算需要分配的io_queue的数量，然后进行分配
{
	unsigned int nr_io_queues;
	// int ret;
	nr_io_queues = nd_conn_nr_io_queues(ctrl);
	ctrl->queue_count = nr_io_queues;
	return __nd_conn_alloc_io_queues(ctrl);
}

int __nd_conn_alloc_io_queues(struct nd_conn_ctrl *ctrl)
{
	int i, ret;

	for (i = 0; i < ctrl->queue_count; i++) {
		ret = nd_conn_alloc_queue(ctrl, i);//分配队列并且设置相关的信息，并且在nr_numanodes=2的情况下，分配队列占用的ioCPU编号分别为2，4，6，8，...
		if (ret)//套接字创建时出现了问题，释放之前的队列
			goto out_free_queues;
	}

	return 0;

out_free_queues:
	for (i--; i >= 0; i--)
		nd_conn_free_queue(ctrl, i);

	return ret;
}

void nd_conn_destroy_io_queues(struct nd_conn_ctrl *ctrl, bool remove)//停止io_queue并且释放空间
{
	nd_conn_stop_io_queues(ctrl);//为什么在这里又调用了一次？？？
	nd_conn_free_io_queues(ctrl);
}

int nd_conn_configure_io_queues(struct nd_conn_ctrl *ctrl, bool new)//根据ctrl配置信息进行io_queue的创建
{//一个queues指针指向的是一个数组吗？？？
	int ret;

	ret = nd_conn_alloc_io_queues(ctrl);
	if (ret)
		return ret;
	return 0;
}

void nd_conn_process_req_list(struct nd_conn_queue *queue) {//在send_list为空时处理，将req_list中的内容全部放入到send_list中
	struct nd_conn_request *req;
	struct llist_node *node;

	for (node = llist_del_all(&queue->req_list); node; node = node->next) {
		req = llist_entry(node, struct nd_conn_request, lentry);
		list_add(&req->entry, &queue->send_list);
	}
}

static inline struct nd_conn_request *nd_conn_fetch_request(struct nd_conn_queue *queue) {
	//从queue的sendlist中取出一个request，如果sendlist为空，则将reqlist中的内容全部放入到sendlist中并重新取出
	struct nd_conn_request *req;

	req = list_first_entry_or_null(&queue->send_list, struct nd_conn_request, entry);
	if (!req) {
		nd_conn_process_req_list(queue);
		req = list_first_entry_or_null(&queue->send_list, struct nd_conn_request, entry);
		if (unlikely(!req))
			return NULL;
	}

	list_del(&req->entry);
	return req;
}

int nd_conn_try_send_cmd_pdu(struct nd_conn_request *req)//通过kernel_sendpage进行发送？？？
{
	struct nd_conn_queue *queue = req->queue;
	struct ndhdr *hdr = req->hdr;
	bool inline_data = nd_conn_has_inline_data(req);
	/* it should be non-block */
	int flags = MSG_DONTWAIT | (inline_data ? MSG_MORE : MSG_EOR);//设置非阻塞模式，并且如果有数据则设置MSG_MORE，否则设置MSG_EOR
	int len = sizeof(*hdr) - req->offset;//通过*hdr解引用再sizeof来获得ndhdr的大小
	int ret;

	// printk("nd_conn_try_send_cmd_pdu: type:%d\n", hdr->type);
	ret = kernel_sendpage(queue->sock, virt_to_page(hdr),
			offset_in_page(hdr) + req->offset, len,  flags);//发送指定内存页面到目标套接字上？？？
	//具体的发送是什么机制？？？？？
	
	// pr_info("inline_data:%d\n", inline_data);
	// pr_info("send ack grant seq:%u\n", htonl(hdr->grant_seq));
	// pr_info("ret:%d\n", ret);
	// printk("pdu->source:%d\n", ntohs(hdr->source));
	// printk("pdu->dest:%d\n", ntohs(hdr->dest));
	// printk("ret :%d\n", ret);

	if (unlikely(ret <= 0)) {
		return ret;
	}
	len -= ret;
	if (!len) {
		if(inline_data) {
			req->state = ND_CONN_SEND_DATA;//如果还有数据要进行发送，就进入SEND_DATA状态
			/* initialize the sending state */
		} else {
			req->state = ND_CONN_PDU_DONE;
			// nd_conn_done_send_req(queue);
		}
		return 1;
	}
	req->offset += ret;//更新offset
	return -EAGAIN;
}
extern ktime_t start_time;
int nd_conn_try_send_data_pdu(struct nd_conn_request *req)
{
	struct nd_conn_queue *queue = req->queue;
	struct sk_buff *skb = req->skb;
	// unsigned int sent = req->sent;
	int ret = 0;
 	skb_frag_t *frag;
	// printk("skb_shinfo(skb)->nr_frags:%d\n", skb_shinfo(skb)->nr_frags);
	while(true) {//不断循环发送
		int flags = MSG_DONTWAIT;
		unsigned short frag_offset = req->frag_offset, 
			fragidx = req->fragidx;
		frag = &skb_shinfo(skb)->frags[fragidx];//skb通过shinfo模块额外附带了大量的内容
		/* this part should be handled in the future */
		while (WARN_ON(!skb_frag_size(frag))) {//如果当前的分片的大小数据为0，则报告WARN并且迭代寻找下一个frag
			fragidx += 1;
			if (fragidx == skb_shinfo(skb)->nr_frags) {
				req->state = ND_CONN_PDU_DONE;
				return 1;
			}
			frag = &skb_shinfo(skb)->frags[fragidx];
		}
		if(fragidx == skb_shinfo(skb)->nr_frags - 1 && atomic_read(&queue->cur_queue_size) == 1) {
			flags |= MSG_EOR;
		} else {
			flags |= MSG_MORE;
		}//当前为最后一个分片且队列中cur_queue_size为1时，flag设置为MSG_EOR
		// if(queue->qid == 0)
		// 	printk("time diff: %lld\n", ktime_to_us(ktime_sub(ktime_get(), start_time)));

		ret = kernel_sendpage(queue->sock,
						skb_frag_page(frag),
						skb_frag_off(frag) + frag_offset,
						skb_frag_size(frag) - frag_offset,
						flags);
		if(ret <= 0) {
			return ret;
		}
		// printk("send data bytes:%d\n", ret);
		frag_offset += ret;
		if(frag_offset == skb_frag_size(frag)) {//当前frag发送完成
			if(fragidx == skb_shinfo(skb)->nr_frags - 1) {//当前恰好为最后一个frag，整个frag全部发送完成，更新状态
				/* sending is done */
				// printk("ND_CONN_PDU_DONE\n");
				req->state = ND_CONN_PDU_DONE;
				return 1;
			} else {// 当前数据包不是最后一个数据包，重新更新offset和idx
				/* move to the next frag */
				// printk("move to the next frag\n");
				req->frag_offset = 0;
				req->fragidx += 1;
			}
		} else {
			/* increment the offset */
			req->frag_offset = frag_offset;//一个数据包没有拷贝完
		}
	}
	return -EAGAIN;
}

int nd_conn_try_send(struct nd_conn_queue *queue)
{
	struct nd_conn_request *req;
	int ret = 1;

	if (!queue->request) {//当前没有正在处理的request
		queue->request = nd_conn_fetch_request(queue);
		if (!queue->request)
			return 0;
	}
	req = queue->request;
	if (req->state == ND_CONN_SEND_CMD_PDU) {
		ret = nd_conn_try_send_cmd_pdu(req);
		if (ret <= 0)
			goto done;
		if (req->state == ND_CONN_PDU_DONE)
			goto clean;
	}
	//以上在try_send_cmd_pdu中如果检测到还有数据要发送，则进入SEND_DATA
	
	if (req->state == ND_CONN_SEND_DATA) {
		// printk("send data pdu\n");
		ret = nd_conn_try_send_data_pdu(req);
		// if(max_queue_length < atomic_read(&queue->cur_queue_size))
		// 	max_queue_length = atomic_read(&queue->cur_queue_size);
		if (ret <= 0)
			goto done;
		// if (ret == 1) {
		// 	atomic_dec(&queue->cur_queue_size);
		// }
	}

	// if (req->state == NVME_TCP_SEND_DATA) {
	// 	ret = nvme_tcp_try_send_data(req);
	// 	if (ret <= 0)
	// 		goto done;
	// }
clean:	//正常完成，回收相关资源
	// printk("queue cpu:%d  size %d\n", queue->io_cpu, atomic_read(&queue->cur_queue_size));
	atomic_dec(&queue->cur_queue_size);
	nd_conn_done_send_req(queue);
	// if (req->state == NVME_TCP_SEND_DDGST)
	// 	ret = nvme_tcp_try_send_ddgst(req);
done:	//错误处理
	if (ret == -EAGAIN) {
		ret = 0;
	} else if (ret < 0) {
		pr_err("failed to send request %d\n", ret);
		// if (ret != -EPIPE && ret != -ECONNRESET)
		// 	nvme_tcp_fail_request(queue->request);
		nd_conn_done_send_req(queue);
	}
	return ret;
}
uint32_t total_time = 0;

void nd_conn_io_work(struct work_struct *w)
{
	struct nd_conn_queue *queue = container_of(w, struct nd_conn_queue, io_work);//找到绑定该work_struct的nd_conn_queue
	unsigned long deadline = jiffies + msecs_to_jiffies(1);//计算截至时间，设置能够执行1ms
	bool pending;
	// int bufsize;
	// int optlen = sizeof(bufsize);
	// pr_info("queue size:%u\n", atomic_read(&queue->cur_queue_size));
	total_time += 1;
	do {
		int result;
		pending = false;
		mutex_lock(&queue->send_mutex);//上锁，并且尝试发送
		result = nd_conn_try_send(queue);
		mutex_unlock(&queue->send_mutex);
		if (result > 0)//返回1表示队列中的内容彻底完成了？？？
			pending = true;
		else if (unlikely(result < 0))
			break;
		

		// result = nvme_tcp_try_recv(queue);
		// if (result > 0)
		// 	pending = true;
		// else if (unlikely(result < 0))
		// 	return;
		if (!pending)//如果没有等待处理的数据，则跳出循环
			break;
	} while (!time_after(jiffies, deadline)); /* quota is exhausted */
	// ret = kernel_getsockopt(queue->sock, SOL_SOCKET, SO_SNDBUF,
	// 	(char *)&bufsize, &optlen);
	// pr_info("ret value:%d\n", ret);
	// pr_info("buffer size receive:%d\n", bufsize);
	if(pending) {//pending=1表示queue中的任务已经完成了，为什么要重新queue_work_on？？？
		if(nd_conn_queue_is_lat(queue)) {
			queue_work_on(queue->io_cpu, nd_conn_wq_lat, &queue->io_work);
		}else {
			queue_work_on(queue->io_cpu, nd_conn_wq, &queue->io_work);
		}
	}
	// ret = queue_work_on(queue->io_cpu, nd_conn_wq, &queue->io_work);
	/* To Do: only wake up all socks if there is available space */
	//如果队列中有空间了，则唤醒所有的套接字
	if(atomic_read(&queue->cur_queue_size) < queue->queue_size)	nd_conn_wake_up_all_socks(queue);
}

/* assume hold socket lock */
void nd_conn_add_sleep_sock(struct nd_conn_ctrl *ctrl, struct nd_sock *nsk) {//将一个sock的请求放入到conn_queue的wait_queue中
	uint32_t qid = 0;
	struct sock *sk = (struct sock*)(nsk);
	struct inet_sock *inet = inet_sk(sk);
	bool pri_class = sk->sk_priority == 0? 0 : 1;
	struct nd_conn_queue *queue;
	int src_port = ntohs(inet->inet_sport);
	if(nsk->sche_policy == SCHE_SRC_PORT) {
		if(pri_class)
			qid = src_port % nd_params.num_lat_channels + nd_params.lat_channel_idx;
		else
			qid = src_port % nd_params.num_thpt_channels + nd_params.thpt_channel_idx;
	} else if(nsk->sche_policy == SCHE_RR){
		/* for now pick the current sending queue */
		qid = nsk->sender.con_queue_id;
	}
	queue = &ctrl->queues[qid];//根据qid得到对应的queue
	//将套接字放入到当前的queue的等待队列中
	spin_lock_bh(&queue->sock_wait_lock);
	if(nsk->sender.wait_on_nd_conns) {
		spin_unlock_bh(&queue->sock_wait_lock);
		goto queue_work;
	}//已经在等待队列中，跳过不添加
	nsk->sender.wait_cpu = raw_smp_processor_id();
	nsk->sender.wait_on_nd_conns = true;
	/* might have to add ref count later */
	nsk->sender.wait_queue = queue;
	list_add_tail(&nsk->tx_wait_list, &queue->sock_wait_list);
	spin_unlock_bh(&queue->sock_wait_lock);
	/* wake up corresponding queue */
queue_work:
	if(nd_conn_queue_is_lat(queue)) {//放入了之后开启一个queue_work_on任务通知队列去取东西？？？
		queue_work_on(queue->io_cpu, nd_conn_wq_lat, &queue->io_work);
	}else {
		queue_work_on(queue->io_cpu, nd_conn_wq, &queue->io_work);
	}
}

// void nd_conn_add_sleep_sock(struct nd_conn_ctrl *ctrl, struct nd_sock* nsk) {
// 	uint32_t i, index;
// 	spin_lock_bh(&ctrl->sock_wait_lock);
// 	// printk("add sleep sock\n");
// 	if(nsk->sender.wait_on_nd_conns)
// 		goto queue_work;
// 	nsk->sender.wait_cpu = raw_smp_processor_id();
// 	nsk->sender.wait_on_nd_conns = true;
// 	list_add_tail(&nsk->tx_wait_list, &ctrl->sock_wait_list);
// queue_work:
// 	spin_unlock_bh(&ctrl->sock_wait_lock);
// 	for(i = 0; i < nd_params.num_thpt_channels; i++) {
// 		index = i + nd_params.thpt_channel_idx;
// 		if(nd_conn_queue_is_lat(&ctrl->queues[index])) {
// 			queue_work_on(ctrl->queues[index].io_cpu, nd_conn_wq_lat, &ctrl->queues[index].io_work);
// 		}else {
// 			queue_work_on(ctrl->queues[index].io_cpu, nd_conn_wq, &ctrl->queues[index].io_work);
// 		}
// 		// queue_work_on(ctrl->queues[i].io_cpu, nd_conn_wq, &ctrl->queues[i].io_work);
// 	}
// }

void nd_conn_remove_sleep_sock(struct nd_conn_queue *queue, struct nd_sock *nsk) {
	if(nsk->sender.wait_on_nd_conns) {
		spin_lock_bh(&queue->sock_wait_lock);
		list_del_init(&nsk->tx_wait_list);//所以为什么用了list而不用llist（无锁队列）？？？
		nsk->sender.wait_on_nd_conns = false;
		nsk->sender.wait_queue = NULL;
		spin_unlock_bh(&queue->sock_wait_lock);
	}
}

void nd_conn_wake_up_all_socks(struct nd_conn_queue *queue) {//唤醒并处理网络连接队列（nd_conn_queue）中所有等待的套接字
	struct nd_sock *nsk; 
	spin_lock_bh(&queue->sock_wait_lock);
	list_for_each_entry(nsk, &queue->sock_wait_list, tx_wait_list) {//遍历等待套接字链表
		WARN_ON(!nsk->sender.wait_on_nd_conns);
		queue_work_on(nsk->sender.wait_cpu, sock_wait_wq, &nsk->tx_work);//开始调度执行？？？
		nsk->sender.wait_on_nd_conns = false;
		nsk->sender.wait_queue = NULL;
	}
	INIT_LIST_HEAD(&queue->sock_wait_list);//清空等待队列
	spin_unlock_bh(&queue->sock_wait_lock);
}

int nd_conn_alloc_queue(struct nd_conn_ctrl *ctrl, int qid)
{
	// struct nvme_tcp_ctrl *ctrl = to_tcp_ctrl(nctrl);
	struct nd_conn_queue *queue = &ctrl->queues[qid];//通过指针直接获得
	struct linger sol = { .l_onoff = 1, .l_linger = 0 };
	int ret, opt, n;
	// int bufsize = 1000000;
	// int optlen = sizeof(bufsize);
	queue->ctrl = ctrl;
    init_llist_head(&queue->req_list);
	INIT_LIST_HEAD(&queue->send_list);
	/* init socket wait list */
	INIT_LIST_HEAD(&queue->sock_wait_list);
	spin_lock_init(&queue->sock_wait_lock);

	// spin_lock_init(&queue->lock);
    mutex_init(&queue->send_mutex);//初始化锁与队列
	INIT_WORK(&queue->io_work, nd_conn_io_work);//从队列中取出元素并尝试通过kernel_sendpage进行发送
	queue->queue_size = ctrl->opts->queue_size;//设置容量上限
	queue->compact_low_thre = ctrl->opts->compact_low_thre;
	queue->compact_high_thre = ctrl->opts->compact_high_thre;
	atomic_set(&queue->cur_queue_size, 0);//初始化计数器


	if (qid >= ctrl->queue_count / 2) {//设置队列的类型，前一半用作throughput，后一半用作latency
		/* latency-sensitive channel */
		queue->prio_class = 1;
	} else
		/* throughput-bound channel */
		queue->prio_class = 0;
	// if (qid > 0)
	// 	queue->cmnd_capsule_len = nctrl->ioccsz * 16;
	// else
	// 	queue->cmnd_capsule_len = sizeof(struct nvme_command) +
	// 					NVME_TCP_ADMIN_CCSZ;

	ret = sock_create(ctrl->addr.ss_family, SOCK_STREAM, IPPROTO_TCP, &queue->sock);//为queue->sock创建了一个TCP套接字？？？
	//这一个TCP协议的发送难道没有处理瓶颈吗？？？如果是小流的话，仍然还有TCP协议栈的处理开销啊？？？
	//并且在高负载下，还是会有TCP协议栈的争抢？？？
	if (ret) {
		pr_err("failed to create socket: %d\n", ret);
		return ret;
	}

	/* Single syn retry */
	opt = 1;
	ret = kernel_setsockopt(queue->sock, IPPROTO_TCP, TCP_SYNCNT, (char *)&opt, sizeof(opt));
	if (ret) {
		pr_err("failed to set TCP_SYNCNT sock opt %d\n", ret);
		goto err_sock;
	}//设置建立连接时如果没有收到ACK仅仅重试一次
	// tcp_sock_set_syncnt(queue->sock->sk, 1);
	/* Set TCP no delay */
	opt = 1;
	ret = kernel_setsockopt(queue->sock, IPPROTO_TCP, TCP_NODELAY, (char *)&opt, sizeof(opt));
	if (ret) {
		pr_err("failed to set TCP_NODELAY sock opt %d\n", ret);
		goto err_sock;
	}//每一次调用send时会立刻发送来减少时间延迟
	// tcp_sock_set_nodelay(queue->sock->sk);
	/*
	 * Cleanup whatever is sitting in the TCP transmit queue on socket
	 * close. This is done to prevent stale data from being sent should
	 * the network connection be restored before TCP times out.
	 */
	ret = kernel_setsockopt(queue->sock, SOL_SOCKET, SO_LINGER,	(char *)&sol, sizeof(sol));
	if (ret) {
		pr_err("failed to set SO_LINGER sock opt %d\n", ret);
		goto err_sock;
	}//确保套接字关闭时，发送队列中的数据能够得到正确处理
	// sock_no_linger(queue->sock->sk);
	/* Set socket type of service */
	// if (ctrl->opts->tos >= 0) {
	// 	opt = ctrl->opts->tos;
	// 	ret = kernel_setsockopt(queue->sock, SOL_IP, IP_TOS,
	// 			(char *)&opt, sizeof(opt));
	// 	if (ret) {
	// 		pr_err("failed to set IP_TOS sock opt %d\n", ret);
	// 		goto err_sock;
	// 	}
	// }
	// if (so_priority > 0)
	// 	sock_set_priority(queue->sock->sk, so_priority);
	// if (ctrl->opts->tos >= 0)
	// 	ip_sock_set_tos(queue->sock->sk, ctrl->opts->tos);
    // io cpu might be need to be changed later
	// ret = kernel_getsockopt(queue->sock, SOL_SOCKET, SO_SNDBUF,
	// 	(char *)&bufsize, &optlen);
	// pr_info("ret value:%d\n", ret);
	// pr_info("buffer size sender:%d\n", bufsize);
	// bufsize = 4000000;
	// ret = kernel_setsockopt(queue->sock, SOL_SOCKET, SO_SNDBUF,
	// 		(char *)&bufsize, sizeof(bufsize));
	queue->sock->sk->sk_allocation = GFP_ATOMIC;//？？？
	if (!qid)
		n = 0;
	else
		n = (qid - 1) % num_online_cpus();
	// queue->io_cpu = cpumask_next_wrap(n - 1, cpu_online_mask, -1, false);
	queue->io_cpu = (nd_params.nr_nodes * qid) % nd_params.nr_cpus;//计算队列的处理CPU
	// queue->io_cpu = 0;
	queue->qid = qid;
	// printk("queue id:%d\n", queue->io_cpu);
	queue->request = NULL;
	// queue->data_remaining = 0;
	// queue->ddgst_remaining = 0;
	// queue->pdu_remaining = 0;
	// queue->pdu_offset = 0;
	sk_set_memalloc(queue->sock->sk);//设置内存分配标志，优先进行内存分配

	// if (nctrl->opts->mask & NVMF_OPT_HOST_TRADDR) {
		ret = kernel_bind(queue->sock, (struct sockaddr *)&ctrl->src_addr, sizeof(ctrl->src_addr));//该套接字绑定到本地地址
		//但是一个本地地址会支持绑定多个套接字吗？？？？还是说这个地址在VNS层没有被绑定？？？？
		if (ret) {
			pr_err("failed to bind queue %d socket %d\n",qid, ret);
			goto err_sock;
		}
	// }

	// queue->hdr_digest = nctrl->opts->hdr_digest;
	// queue->data_digest = nctrl->opts->data_digest;
	// if (queue->hdr_digest || queue->data_digest) {
	// 	ret = nvme_tcp_alloc_crypto(queue);
	// 	if (ret) {
	// 		dev_err(nctrl->device,
	// 			"failed to allocate queue %d crypto\n", qid);
	// 		goto err_sock;
	// 	}
	// }

	// rcv_pdu_size = sizeof(struct nvme_tcp_rsp_pdu) +
	// 		nvme_tcp_hdgst_len(queue);
	// queue->pdu = kmalloc(rcv_pdu_size, GFP_KERNEL);
	// if (!queue->pdu) {
	// 	ret = -ENOMEM;
	// 	goto err_crypto;
	// }

	// dev_dbg(nctrl->device, "connecting queue %d\n",
	// 		nvme_tcp_queue_id(queue));

	ret = kernel_connect(queue->sock, (struct sockaddr *)&ctrl->addr, sizeof(ctrl->addr), 0);//建立套接字连接
	if (ret) {
		pr_err("failed to connect socket: %d\n", ret);
		goto err_rcv_pdu;
	}
    // this part needed to be handled later
	// ret = nvme_tcp_init_connection(queue);
	if (ret)
		goto err_init_connect;

	queue->rd_enabled = true;//启用数据读取
	set_bit(ND_CONN_Q_ALLOCATED, &queue->flags);//设置队列已经分配状态
	// nvme_tcp_init_recv_ctx(queue);

	write_lock_bh(&queue->sock->sk->sk_callback_lock);//上锁，设置回调函数
	queue->sock->sk->sk_user_data = queue;//允许将自定义数据绑定到套接字上，在回调函数中通过sk_user_data来进行访问
	queue->state_change = queue->sock->sk->sk_state_change;
	queue->data_ready = queue->sock->sk->sk_data_ready;
	queue->write_space = queue->sock->sk->sk_write_space;
	queue->sock->sk->sk_data_ready = nd_conn_data_ready;
	queue->sock->sk->sk_state_change = nd_conn_state_change;
	queue->sock->sk->sk_write_space = nd_conn_write_space;//设置回调函数
#ifdef CONFIG_NET_RX_BUSY_POLL	//如果启用了网络轮询，设置相应的标识
	queue->sock->sk->sk_ll_usec = 1;
#endif
	write_unlock_bh(&queue->sock->sk->sk_callback_lock);

	return 0;

err_init_connect://连接失败，暂停套接字
	kernel_sock_shutdown(queue->sock, SHUT_RDWR);
err_rcv_pdu:
	// kfree(queue->pdu);
// err_crypto:
// 	if (queue->hdr_digest || queue->data_digest)
// 		nvme_tcp_free_crypto(queue);
err_sock://套接字绑定失败，释放套接字
	sock_release(queue->sock);
	queue->sock = NULL;
	return ret;
}

// int nd_conn_alloc_admin_queue(struct nd_conn_ctrl *ctrl)
// {
// 	int ret;

// 	ret = nd_conn_alloc_queue(ctrl, 0);
// 	if (ret)
// 		return ret;

// 	// ret = nvme_tcp_alloc_async_req(to_tcp_ctrl(ctrl));
// 	if (ret)
// 		goto out_free_queue;

// 	return 0;

// out_free_queue:
// 	nd_conn_free_queue(ctrl, 0);
// 	return ret;
// }

int nd_conn_setup_ctrl(struct nd_conn_ctrl *ctrl, bool new)//根据conn_ctrl相关的信息创建io_queue
{
	int ret;
	ret = nd_conn_configure_io_queues(ctrl, new);
	if (ret)
		goto destroy_admin;
	return 0;
destroy_admin:
	nd_conn_stop_queue(ctrl, 0);
	return ret;
}


struct nd_conn_ctrl *nd_conn_create_ctrl(struct nd_conn_ctrl_options *opts)//根据传入的conn_ctrl_options创建一个conn_ctrl
{	//一个conn_ctrl_options对应一个conn_ctrl
	struct nd_conn_ctrl *ctrl;
	struct sockaddr_in *target_addr;
	int ret;

	ctrl = kzalloc(sizeof(*ctrl), GFP_KERNEL);//分配内存并清零
	if (!ctrl) {
		kfree(opts);
		return ERR_PTR(-ENOMEM);
	}

	// INIT_LIST_HEAD(&ctrl->list);
	ctrl->opts = opts;
	ctrl->queue_count = opts->nr_io_queues + opts->nr_write_queues + opts->nr_poll_queues;
	// ctrl->sqsize = opts->queue_size - 1;
	// ctrl->ctrl.kato = opts->kato;
    // pr_info("queue count: %u\n", ctrl->queue_count);
	// INIT_DELAYED_WORK(&ctrl->connect_work,
	// 		nvme_tcp_reconnect_ctrl_work);
	// INIT_WORK(&ctrl->err_work, nd_conn_error_recovery_work);
	// INIT_WORK(&ctrl->ctrl.reset_work, nvme_reset_ctrl_work);
    mutex_init(&ctrl->teardown_lock);

	// if (!(opts->mask & NVMF_OPT_TRSVCID)) {
	// 	opts->trsvcid =
	// 		kstrdup(__stringify(NVME_TCP_DISC_PORT), GFP_KERNEL);
	// 	if (!opts->trsvcid) {
	// 		ret = -ENOMEM;
	// 		goto out_free_ctrl;
	// 	}
	// 	opts->mask |= NVMF_OPT_TRSVCID;
	// }

	ret = inet_pton_with_scope(&init_net, AF_UNSPEC, opts->traddr, opts->trsvcid, &ctrl->addr);
	//解析传入地址taddr和trsvcid，并且将其填充到ctrl->addr中
	//将传入的地址字符串（traddr）和服务标识符（trsvcid）解析为网络地址，并存储在通用的 sockaddr_storage 结构中。
	//init_net对应网络命名空间的上下文
	if (ret) {
		pr_err("malformed address passed: %s:%s\n",	opts->traddr, opts->trsvcid);
		goto out_free_ctrl;
	}
	target_addr = (struct sockaddr_in *)(&ctrl->addr);

	ret = inet_pton_with_scope(&init_net, AF_UNSPEC, opts->host_traddr, NULL, &ctrl->src_addr);//源地址通常不绑定端口号？？？？
	if (ret) {
		pr_err("malformed src address passed: %s\n", opts->host_traddr);
		goto out_free_ctrl;
	}
	ctrl->queues = kcalloc(ctrl->queue_count, sizeof(*ctrl->queues), GFP_KERNEL);//分配指针数组指向的空间
	if (!ctrl->queues) {
		ret = -ENOMEM;
		goto out_free_ctrl;
	}
	ret = nd_conn_setup_ctrl(ctrl, true);//进行实际queues的空间分配
	if (ret)
		goto out_uninit_ctrl;
    pr_info("create ctrl sucessfully\n");
	mutex_lock(&nd_conn_ctrl_mutex);
	// list_add_tail(&ctrl->list, &nd_conn_ctrl_list);
	hash_add(nd_conn_table, &ctrl->hlist, target_addr->sin_addr.s_addr);//将控制器实例插入hash表，方便之后快速寻找
	mutex_unlock(&nd_conn_ctrl_mutex);

	return ctrl;

out_uninit_ctrl://出了故障之后进行回收空间
	/* To Do: handle it corrrectly */
	WARN_ON(true);
	// nvme_uninit_ctrl(&ctrl->ctrl);
	// nvme_put_ctrl(&ctrl->ctrl);
	if (ret > 0)
		ret = -EIO;
	// return ERR_PTR(ret);
// out_kfree_queues:
	kfree(ctrl->opts);
	kfree(ctrl->queues);
out_free_ctrl:
	kfree(ctrl);
	return ERR_PTR(ret);
}

int nd_conn_init_module(void)
{
	struct nd_conn_ctrl_options* opts;
	int i;
	nd_conn_wq = alloc_workqueue("nd_conn_wq", WQ_MEM_RECLAIM, 0);//一个work_queue是全局的，可以在多个CPU上调度执行
	if (!nd_conn_wq)
		return -ENOMEM;
	nd_conn_wq_lat = alloc_workqueue("nd_conn_wq_lat", WQ_MEM_RECLAIM | WQ_HIGHPRI, 0);
	if(!nd_conn_wq_lat)
		return -ENOMEM;
	sock_wait_wq = alloc_workqueue("sock_wait_wq", WQ_MEM_RECLAIM, 0);
	if(!sock_wait_wq)
		return -ENOMEM;		
    // pr_info("HCTX_MAX_TYPES: %d\n", HCTX_MAX_TYPES);
	/* hash table init */
	hash_init(nd_conn_table);
	
	for (i = 0; i < nd_params.num_remote_hosts; i++) {//为每一个远程host创建控制器
	    /* initialiize the option */
		opts = kmalloc(sizeof(*opts), GFP_KERNEL);
		opts->nr_io_queues = nd_params.total_channels;
		opts->nr_write_queues = 0;
		opts->nr_poll_queues = 0;
		/* target address */
		opts->traddr = nd_params.remote_ips[i];//解析得到目标的地址
		opts->trsvcid = "9000";//用的是和目的一样的IP地址，但是目的端口号不同，这里是9000，正常发送时候是4000
		/* src address */
		opts->host_traddr = nd_params.local_ip;
		// opts->host_port = "10000";

		opts->queue_size = 32;//设置队列大小上限
		opts->compact_high_thre = 256;
		opts->compact_low_thre = 6;
		opts->tos = 0;
		pr_info("create the ctrl \n");
		nd_conn_create_ctrl(opts);//根据opts创建一个conn_ctrl
	}

	// nvmf_register_transport(&nvme_tcp_transport);
	return 0;
}

void nd_conn_cleanup_module(void)
{
	struct nd_conn_ctrl *ctrl;
	struct hlist_node *tmp;
	int i;
	// nvmf_unregister_transport(&nvme_tcp_transport);

	mutex_lock(&nd_conn_ctrl_mutex);
	hash_for_each_safe(nd_conn_table, i, tmp, ctrl, hlist)
		nd_conn_delete_ctrl(ctrl);//删除hash表中的所有连接控制器
	mutex_unlock(&nd_conn_ctrl_mutex);
	// flush_workqueue(nvme_delete_wq);

	destroy_workqueue(sock_wait_wq);
	destroy_workqueue(nd_conn_wq);
	destroy_workqueue(nd_conn_wq_lat);//移除work_queue
}
