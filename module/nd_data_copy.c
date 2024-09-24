#include "nd_data_copy.h"
#include "nd_impl.h"

static struct workqueue_struct *nd_dcopy_wq;

static struct nd_dcopy_queue nd_dcopy_q[NR_CPUS];
//NR_CPUS为linux系统中能够支持的CPU数量的最大值，此处为8192

static inline void nd_dcopy_free_request(struct nd_dcopy_request *req) {
    if(req->clean_skb && req->skb){
		// pr_info("reach here:%d\n", __LINE__);
        kfree_skb(req->skb);//释放网络缓冲区的内存，kfree和kmalloc分配的是内核中的地址，所以实现较为高效
		//同时由于涉及到内核内存，所以在创建work_struct、分配work queue的时候需要传入WQ_MEM_RECLAIM宏
	}

	if(req->bv_arr) {//释放指向的内存片段
		// nd_release_pages(req->bv_arr, true, req->max_segs);
		kfree(req->bv_arr);
		req->bv_arr = NULL;
	}
	// pr_info("reach here:%d\n", __LINE__);
    // kfree(req->iter.bvec);
	// pr_info("reach here:%d\n", __LINE__);
    kfree(req);
}

// static inline void nd_dcopy_clean_req(struct nd_dcopy_request *req)
// {

// 	/* pdu doesn't have to be freed */
// 	// kfree(queue->request->pdu);
// 	// put_page(queue->request->hdr);
// 	// page_frag_free(queue->request->hdr);
// 	// kfree(queue->request);
//     nd_dcopy_free_request(request);	
// }

static void nd_dcopy_process_req_list(struct nd_dcopy_queue *queue)//遍历req_list链表中的所有元素，将内容从request list放到copy list中
{
	struct nd_dcopy_request *req;
	struct llist_node *node;

	for (node = llist_del_all(&queue->req_list); node; node = node->next) {
		//一次性遍历req_list链表中的所有元素，将内容从request list放到copy list中？？？？
		//这里由于不能够做细粒度的拆分，只能一次性通过llist_del_all将所有的元素都取出来都放进去？？？
		//是对应了论文中为了防止holblocking首先将data从channel取到resp队列中，再从resp队列中取出来到rx buffer中的过程吗？？？
		req = llist_entry(node, struct nd_dcopy_request, lentry);
		list_add(&req->entry, &queue->copy_list);
	}
}

static inline struct nd_dcopy_request *
nd_dcopy_fetch_request(struct nd_dcopy_queue *queue)//返回一个copy_list中的copy请求，如果copy_list为空，则将req_list中的所有元素都放到copy_list中再重新返回
{
	struct nd_dcopy_request *req;

	req = list_first_entry_or_null(&queue->copy_list,
			struct nd_dcopy_request, entry);//从copy_list中取出第一个元素（nd_dcopy_request）
	if (!req) {
		nd_dcopy_process_req_list(queue);//如果req为空，即copy_list为空，则将req_list中的所有元素都放到copy_list中
		req = list_first_entry_or_null(&queue->copy_list,
				struct nd_dcopy_request, entry);//再次尝试取出元素
		if (unlikely(!req))//unlikely是一个宏表示该现象很少发生，用于编译器优化，如果req仍然为空，返回NULL
			return NULL;
	}

	list_del(&req->entry);//将被取出来的entry从链表中删除？？？但是是从哪一个链表中删除？？？
	return req;
}

/* round-robin */
int nd_dcopy_sche_rr(int last_qid) {
	//last_qid表示上一个处理请求的CPU的编号，用于作为轮询的起点
	struct nd_dcopy_queue *queue;
	int last_q =  (last_qid - nd_params.data_cpy_core) / nd_params.nr_nodes;
	int i = 0, qid;
	bool find = false;
	
 	for (i = 1; i <= nd_params.nd_num_dc_thread; i++) {//遍历所有的data_copy_thread？？？？

		qid = (i + last_q) % (nd_params.nd_num_dc_thread);//取模保证仍然落在范围内
		queue =  &nd_dcopy_q[qid * nd_params.nr_nodes + nd_params.data_cpy_core];
		if(qid * nd_params.nr_nodes + nd_params.data_cpy_core == raw_smp_processor_id())//跳过当前的CPU
			continue;
		if(atomic_read(&queue->queue_size) >= queue->queue_threshold)//跳过队列中的请求已经超过了阈值的CPU
			continue;
		find = true;
		last_q = qid;
		break;
		// return qid * 4 + nd_params.data_cpy_core;
	}
	if(!find) {
		return -1;
		// qid = (1 + last_q) % (nd_params.nd_num_dc_thread);
		// last_q = qid;
	}
	return last_q * nd_params.nr_nodes + nd_params.data_cpy_core;//返回最终的CPU编号
	// }
	// return -1;
}

/* compact */
int nd_dcopy_sche_compact(void) {
	//紧凑调度策略，首先尝试选择负载较轻的队列，若所有队列都已经满载，则返回-1
	struct nd_dcopy_queue *queue;
	static u32 last_q = 0;
	int i = 0, qid;
	bool find = false;
	for (i = 0; i < nd_params.nd_num_dc_thread; i++) {

		qid = (i) % (nd_params.nd_num_dc_thread);
		queue =  &nd_dcopy_q[qid * nd_params.nr_nodes + nd_params.data_cpy_core];
		// if(nd_params.nd_debug)
		// 	pr_info("qid:%d queue size:%d \n",qid, atomic_read(&queue->queue_size));
		if(atomic_read(&queue->queue_size) >= queue->queue_threshold) {
			// pr_info(" queue size is larger than limit:%d %d\n", i, atomic_read(&queue->queue_size));
			continue;
		}
		find = true;
		last_q = qid;
		break;
		// return qid * 4 + nd_params.data_cpy_core;
	}
	/* if all queue is full; do round-robin */
	if(!find) {
		return -1;
		// qid = (1 + last_q) % (nd_params.nd_num_dc_thread);
		// last_q = qid;
	}
	return last_q * nd_params.nr_nodes + nd_params.data_cpy_core;
	// }
	// return -1;
}

int nd_dcopy_queue_request(struct nd_dcopy_request *req) {//将一个datacopy请求加入队列中
	int qid;
    struct nd_dcopy_queue* queue;  
    bool empty = false;
	if(req->io_cpu < 0) {// 检查 req->io_cpu 是否有效，若无效则产生一个警告
		WARN_ON(true);
	}
	//根据分配的io_cpu字段，将其分配到相应的CPU的dcopy_queue中
	qid = req->io_cpu;
	queue = &nd_dcopy_q[req->io_cpu];
	atomic_add(req->remain_len, &queue->queue_size);
	req->queue = queue;
    empty = llist_add(&req->lentry, &queue->req_list) &&
		list_empty(&queue->copy_list) && !queue->request;
		
	queue_work_on(queue->io_cpu, nd_dcopy_wq, &queue->io_work);//异步执行的函数，绑定了nd_dcopy_io_work
    return qid;
}

void nd_try_dcopy_receive(struct nd_dcopy_request *req) {
    struct nd_sock *nsk;
 	int err, req_len;

	nsk = nd_sk(req->sk);//将sock类型转化为nd_sock类型
	err = skb_copy_datagram_iter(req->skb, req->offset, &req->iter, req->remain_len);//将数据从 sk_buff 拷贝到用户空间的缓冲区中
	//offset是数据包开始的拷贝地址，sk_buff 中的数据可能包含不同协议的头部和负载数据，使用offset可以跳过这些头部
	//iter是一个迭代器，用于指向用户空间的缓冲区，从而支持复杂的分页和分段拷贝；remain_len是剩余的数据长度
    if (err) {//放弃处理，报告异常
    /* Exception. Bailout! */
	    skb_dump(KERN_WARNING, req->skb, false);//将sk_buff的内容打印到内核日志中
		//false：只输出 sk_buff 的基本信息，如头部信息，不包括全部数据内容
        // pr_info("msg->mssg_iter.type:%ld\n", req->iter.type &4);
		// pr_info("msg->mssg_iter.count:%ld\n", req->iter.count);
		// pr_info("msg->mssg_iter.iov_offset:%ld\n", req->iter.iov_offset);
		// pr_info("msg->mssg_iter.iov_offset:%p\n", req->iter.iov);
		// pr_info("msg->mssg_iter.nr_segs:%ld\n", req->iter.nr_segs);
		// pr_info("msg->mssg_iter.iov_base:%p\n", req->iter.iov->iov_base);
		// pr_info("msg->mssg_iter.iov_len:%ld\n", req->iter.iov->iov_len);
        WARN_ON(true);//输出一条警告信息并生成堆栈回溯
    }
    // pr_info("err:%d\n", err);
	req_len = req->remain_len;
// clean:
    // nd_dcopy_free_request(req);
	req->state = ND_DCOPY_DONE;//拷贝完成，更改相应的状态
	/* release the page before reducing the count */
	if(req->bv_arr || req->clean_skb) {
		struct nd_dcopy_page* resp = kmalloc(sizeof(struct nd_dcopy_page), GFP_KERNEL);//统一管理传输之后的内存空间吗？
		if(req->bv_arr) {//将原来指向的内存空间使用新的指针指向，原来的指针置空
			resp->max_segs = req->max_segs;
			resp->bv_arr = req->bv_arr;
			req->bv_arr = NULL;
		} else {
			resp->bv_arr = NULL;
		}
		if(req->clean_skb) {
			resp->skb = req->skb;
			req->skb = NULL;
		} else {
			resp->skb = NULL;
		}
		llist_add(&resp->lentry, &nsk->receiver.clean_page_list);//统一放到clean_page_list中等待之后批量处理
		// nd_release_pages(req->bv_arr, true, req->max_segs);
	} 
    atomic_sub_return(req_len, &nsk->receiver.in_flight_copy_bytes);//更新相应的in_flight信息
	atomic_sub(req_len, &req->queue->queue_size);
// done:
// 	return ret;
}

void nd_try_dcopy_send(struct nd_dcopy_request *req) {
    struct nd_sock *nsk;
 	int err, req_len, i;
	size_t copy;
	struct page_frag *pfrag = &current->task_frag;//获得当前线程的页面碎片缓冲区指针
	struct sk_buff *skb;
	struct nd_dcopy_response *resp;
	req_len = req->remain_len; 
	nsk = nd_sk(req->sk);
	WARN_ON(req_len == 0);//如果条件为真，在内核日志中发出警告
	while(req_len > 0) {
		bool merge = true;
		if (!skb_page_frag_refill(32U, pfrag, req->sk->sk_allocation)) {//从内存碎片中分配32B的空间
		//从内存碎片中分配用于优化内存管理同时减少时延，但是为什么仅仅分配32B的空间？是为了仅仅处理报文头吗？
			goto wait_for_memory;
		}
		skb = req->skb;
		if(!skb) //若skb为空创建新的skb
			goto create_new_skb;
		if(skb->len == ND_MAX_SKB_LEN)//skb数据包的长度达到了最大值，无法继续添加数据
			goto push_skb;
		i = skb_shinfo(skb)->nr_frags;//获取大包的fragments数量（当一个包的大小过大时，无法直接放入到data和tail的指针中间，所以通过fragments数组来描述）
		if (!skb_can_coalesce(skb, i, pfrag->page, pfrag->offset)) {
			//此处为什么不是i-1而是i？看了源代码，是利用的索引编号（从1开始）而不是下标（从0开始），即在内部实现中进行访问时使用的是i-1作为下标
			//查看新分配的内存碎片pfrag能否与sk_buffer中尾部的frags碎片合并
			//此时不能合并
			if (i == MAX_SKB_FRAGS) {
				goto push_skb;
			}
			merge = false;
		}
		copy = min_t(int, ND_MAX_SKB_LEN - skb->len, req_len);//取可以赋值的空间与剩余搬运数据里的最小值
		copy = min_t(int, copy, pfrag->size - pfrag->offset);//取当前内存碎片中剩余的空间与上面的最小值
		err = nd_copy_to_page_nocache(req->sk, &req->iter, skb,
					       pfrag->page,
					       pfrag->offset,
					       copy);//最终数据被拷贝到了pfrag->page中，还没有串联到skb中
		/* ToDo: handle the err */
		if(err)
			WARN_ON(true);
		/* Update the skb. */
		if (merge) {
			skb_frag_size_add(&skb_shinfo(skb)->frags[i - 1], copy);//可以合并，直接增加skb最后一个frag的大小
		} else {//无法与现有片段合并，将page附到skb的fragments数组之后
			skb_fill_page_desc(skb, i, pfrag->page,
					   pfrag->offset, copy);
			get_page(pfrag->page);//增加page的引用计数
		}
		//更新相应的数据
		pfrag->offset += copy;
		req_len -= copy;
		/* last request */
		if(req_len == 0)
			goto push_skb;
		continue;

	create_new_skb://由于发送的数据包过大了，可能一次并没有发送完，而上次发送成功之后，skb指针就指向NULL了，此处需要创建新的数据包，并再次进入循环进行发送
		skb = alloc_skb(0, req->sk->sk_allocation);//分配一个用于存储网络数据包的缓冲区，用于后续协议栈的处理如发送、接收
		WARN_ON(req->skb != NULL);
		req->skb = skb;
		// printk("create new skb\n");
		if(!skb)//新的skb分配失败，进入等待内存碎片状态
			goto wait_for_memory;

		// __skb_queue_tail(&sk->sk_write_queue, skb);
		continue;

	push_skb://这段代码的目的是什么？？？？
	//是否表示当前的套接字能够顺带的frags数量达到了上限，无法处理更多的数据包，所以需要将当前的skb放入到发送队列中，同时为req创建一个新的skb
		/* push the new skb */
		ND_SKB_CB(skb)->seq = req->seq;//针对不同的协议，套接字中有一个cb结构体用于存储一些额外的信息，这里将seq信息存储到cb中
		resp = kmalloc(sizeof(struct nd_dcopy_response), GFP_KERNEL);
		resp->skb = req->skb;
		llist_add(&resp->lentry, &nsk->sender.response_list);//将创建的response结构体放入套接字相关的response_list中
		req->seq += skb->len;
		req->skb = NULL;//将req中的skb指针置空，为下一次发送做准备
		resp = NULL;//？？？？
		continue;

	wait_for_memory://内存碎片不够用，报告错误信息并返回
		WARN_ON(true);
		break;
	}
	if(req_len == 0) {//数据拷贝完成，更新相应的状态
		req->state = ND_DCOPY_DONE;
		nd_release_pages(req->bv_arr, true, req->max_segs);
	}  
	atomic_sub_return(req->remain_len - req_len, &nsk->sender.in_flight_copy_bytes);
	atomic_sub(req->remain_len - req_len, &req->queue->queue_size);
	req->remain_len = req_len;//由于以上有可能没有空余的内存碎片而失败，所以需要再次进行更新
// done:
// 	return ret;
}

int nd_try_dcopy(struct nd_dcopy_queue *queue)
{
	struct nd_dcopy_request *req;
    // struct nd_sock *nsk;
	int ret = 1;
    // u32 offset;

	if (!queue->request) {//如果当前的一个request为空，则从copy_list中取出一个request
		queue->request = nd_dcopy_fetch_request(queue);
		if (!queue->request) return 0;//如果仍然为空，则返回0
	} else {
		WARN_ON(true);//WARN_ON检查给定的条件是否为 true。如果条件为 true，会在内核日志中输出警告信息（包括文件名、行号、函数名和出错的条件），同时显示堆栈回溯。
	}
    req = queue->request;

	if(req->state == ND_DCOPY_RECV) {//状态为接收
		nd_try_dcopy_receive(req);

	} 
	if(req->state == ND_DCOPY_SEND) {//状态为发送
		nd_try_dcopy_send(req);
	}
	if(req->state == ND_DCOPY_DONE) {//以上处理完了之后数据被处理完毕，该请求被释放，同时更新相应的状态
		// atomic_dec(&queue->queue_size);
		nd_dcopy_free_request(req);//但是在receive时候涉及的内存信息似乎并没有被直接释放
		queue->request = NULL;
	}
    /*perform data copy */
    // lock_sock(req->sk);
    // pr_info("doing data copy\n");
	// pr_info("req addr:%p\n", req);
	// pr_info("req iter:%p\n", req->iter);
	// pr_info("req iter bvec:%p\n", req->iter.bvec);

    // err = skb_copy_datagram_iter(req->skb, req->offset, &req->iter, req->len);
    // release_sock(req->sk);

	return ret;
}

void nd_dcopy_io_work(struct work_struct *w)
{
	struct nd_dcopy_queue *queue = container_of(w, struct nd_dcopy_queue, io_work);//通过container_of获得该work_struct对应的nd_dcopy_queue
	unsigned long deadline = jiffies + msecs_to_jiffies(1);//设置事件限制1ms
	//jiffies表示了系统从启动之后的时钟中断的数量，与主频HZ有关，通常用于延迟函数和定时器机制
	int ret;
	bool pending;
	do {
		int result;
		pending = false;
		mutex_lock(&queue->copy_mutex);//上拷贝锁，因为涉及对于copy_list的操作，但是此处为什么不采用更加细粒度的锁划分呢？
		//即仅仅在更新相应的数据结构时上锁，而不是整个函数都上锁（尤其是耗时的拷贝部分不要上锁）
		//是为了防止被更改吗？？？
		//按照道理来说一个request被fetch了之后就从queue中删去了，但是为什么还是要继续上锁呢？？？
		result = nd_try_dcopy(queue);
		//没有request的时候会返回0，否则将会返回1
		mutex_unlock(&queue->copy_mutex);
		if (result > 0)
			pending = true;//以上函数明明都是同步的，执行到这里的时候拷贝应该已经完成了，为什么需要pending？？？
		else if (unlikely(result < 0))
			break;
		// printk("queue size:%d \n",atomic_read(&queue->queue_size));

		// result = nvme_tcp_try_recv(queue);
		// if (result > 0)
		// 	pending = true;
		// else if (unlikely(result < 0))
		// 	return;
		if (!pending)
			break;

	} while (!time_after(jiffies, deadline)); /* quota is exhausted */
	//循环直到quota用完，即时间超过了deadline？？？
	//每次搬运1ms的数据？？？？
	if(pending)
		ret = queue_work_on(queue->io_cpu, nd_dcopy_wq, &queue->io_work);//？？？？？
		//如果在时间配额内还有未完成的任务（pending 为 true），则调用 queue_work_on 重新将任务排入工作队列，指定在 queue->io_cpu CPU异步上执行
		//异步执行任务还是执行当前函数？？？？
}

void nd_dcopy_flush_req_list(struct nd_dcopy_queue *queue) {//从copy_list中将req逐个取出之后进行处理，并将copy_list重新初始化
    struct nd_dcopy_request *req, *temp;
    list_for_each_entry_safe(req, temp, &queue->copy_list, entry) {
        nd_dcopy_free_request(req);
    }
	INIT_LIST_HEAD(&queue->copy_list);
}

void nd_dcopy_free_queue(struct nd_dcopy_queue *queue)
//将一个队列清空，将其中的请求处理掉，首先将请求从req_list放入到copy_list中，
//之后再上锁之后处理copy_list的内容
{
	// struct nd_conn_queue *queue = &ctrl->queues[qid];

	// if (!test_and_clear_bit(ND_CONN_Q_LIVE, &queue->flags))
	// 	return;
	cancel_work_sync(&queue->io_work);//取消工作队列中的某一个任务
    /* flush all pending request and clean the occupied memory of each req */
    nd_dcopy_process_req_list(queue);
    mutex_lock(&queue->copy_mutex);
    nd_dcopy_flush_req_list(queue);
    mutex_unlock(&queue->copy_mutex);

}

int nd_dcopy_alloc_queue(struct nd_dcopy_queue *queue, int io_cpu)//初始化和某一个CPU绑定的相应队列
{
    init_llist_head(&queue->req_list);
	INIT_LIST_HEAD(&queue->copy_list);
	// spin_lock_init(&queue->lock);
    mutex_init(&queue->copy_mutex);
	INIT_WORK(&queue->io_work, nd_dcopy_io_work);//为work_struct绑定相应的处理函数
    queue->io_cpu = io_cpu;
	queue->queue_threshold = 10 * 65536;//队列中所有包的大小的上限，超过该上限将不再将request放入该队列中
	// queue->queue_size = queue_size;
	atomic_set(&queue->queue_size, 0);//queue_size表示了所有request的长度之和
	return 0;//此处总是return 0，那么之后的出错时的情况还会触发吗？？？？
}

int nd_dcopy_alloc_queues(struct nd_dcopy_queue *queues)//初始化所有的dcopy_queue
{
	int i, ret;

	for (i = 0; i < NR_CPUS; i++) {
		ret = nd_dcopy_alloc_queue(&queues[i], i);
		if (ret)
			goto out_free_queues;//通过goto来先释放资源再终止进程，同java的try-with-resources
	}

	return 0;

out_free_queues:
	for (i--; i >= 0; i--)
		nd_dcopy_free_queue(&queues[i]);

	return ret;
}

int nd_dcopy_init(void)
{
	int ret;

	nd_dcopy_wq = alloc_workqueue("nd_dcopy_wq", WQ_MEM_RECLAIM, 0);
	//创建工作队列名称为nd_dcopy_wq
	//当内核检测到某个带有 WQ_MEM_RECLAIM 标志的工作队列中的任务不能被及时处理时，它会启动救援线程
	//救援线程以高优先级执行这些任务，以帮助系统释放内存或处理其他关键任务
	//如果工作队列中的任务可能会在内存回收路径中被调用，则必须设置该flag，即该任务会在内存回收时候被执行
	//@max_active 的最大限制是 512，当指定为 0 时，默认值为 256，即每一个CPU上可以执行最多256个执行该工作队列的工作项
	//通常建议为0，最大值为512
	//返回指向workqueue_struct的指针

	if (!nd_dcopy_wq) return -ENOMEM;//工作队列分配失败，返回-ENOMEM错误码
	ret= nd_dcopy_alloc_queues(nd_dcopy_q);
	// ndt_port = kzalloc(sizeof(*ndt_port), GFP_KERNEL);

	// ret = nvmet_register_transport(&nvmet_tcp_ops);


	if (ret)
	 	goto err;

	return 0;
err:
	destroy_workqueue(nd_dcopy_wq);//出问题时摧毁工作队列（首先检查工作队列是否仍有未完成的工作。如果有，它会等待这些工作完成。
								   //在所有工作项处理完毕后，工作队列结构会被释放）
	return ret;
}

void nd_dcopy_exit(void)
{
	// struct ndt_conn_queue *queue;

	// nvmet_unregister_transport(&nvmet_tcp_ops);
    int i;
    pr_info("exit data copy \n");
	flush_scheduled_work();
	for (i = 0; i >= 0; i--)
		nd_dcopy_free_queue(&nd_dcopy_q[i]);//清空完队列中的req请求之后摧毁工作队列
	// mutex_lock(&ndt_conn_queue_mutex);
	// list_for_each_entry(queue, &ndt_conn_queue_list, queue_list)
	// 	kernel_sock_shutdown(queue->sock, SHUT_RDWR);
	// mutex_unlock(&ndt_conn_queue_mutex);
	// flush_scheduled_work();

	destroy_workqueue(nd_dcopy_wq);
}
