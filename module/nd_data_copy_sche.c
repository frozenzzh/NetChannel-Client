#include "nd_data_copy_sche.h"

int pre_pid=0;//保证只能有一条接收端的大象流，通过下一个APP和上一个APP的pid不相同来进行更新，在极端条件下可能有pid被回收导致没有更新的情况
int send_call_times=0;//表示调用次数，当为1的时候，直接采用原来的方案；当为2的时候，更新并采用新的方案；>=3的时候直接采用新的方案
bool is_1update=false;
bool is_2update=false;
//这里必须要在try_send的时候更新，只有当一轮全部发送出去之后才能够获得有用的利用率信息
static struct Available_cores cores;
static struct Forbidden_cores forbidden;
static struct Cpu_Info_List cpuInfo;
extern struct nd_dcopy_queue nd_dcopy_q[NR_CPUS];


void forbidden_cores_add(int cpuid) {
    int tail=forbidden.num;
    forbidden.forbidden_cores[tail]=cpuid;
    forbidden.num++;
}

bool check_in_forbidden(int cpuid) {//检查是或否在forbidden_list中
    int i;
    for (i=0;i<forbidden.num;i++)
        if (forbidden.forbidden_cores[i]==cpuid) return true;
    return false;
}

static void available_cores_add(int cpuid, int overhead) {
    int tail=cores.num;
    cores.cores[tail].id=cpuid;
    cores.cores[tail].util=overhead;
    cores.num++;
}

static void overhead_info_add(int cpu_id,  int user, int nice, int system, int idle, int iowait, int irq, int softirq) {
//要求必须按照顺序加入，即当前的cpu_id应该等于cpuInfo.num-1，并且每一个信息只会被加入一次
    // Initialize cpuInfo
    cpuInfo.cpu_info[cpu_id].user = user;
    cpuInfo.cpu_info[cpu_id].nice = nice;
    cpuInfo.cpu_info[cpu_id].system = system;
    cpuInfo.cpu_info[cpu_id].idle = idle;
    cpuInfo.cpu_info[cpu_id].iowait = iowait;
    cpuInfo.cpu_info[cpu_id].irq = irq;
    cpuInfo.cpu_info[cpu_id].softirq = softirq;
    cpuInfo.cpu_num++;
    if (cpuInfo.cpu_num!=cpu_id+1) {
        pr_err("Error: CPU info is not added in order\n");
    }
}

static void get_cpu_overhead_info(void) {
    int online_cpu_num=num_online_cpus();

    struct file *f;
    mm_segment_t fs;
    loff_t pos;
    int ret;

    fs = get_fs();
    set_fs(KERNEL_DS);

    f = filp_open("/proc/stat", O_RDONLY, 0);
    if (IS_ERR(f)) {
        pr_err("Error opening /proc/stat\n");
        set_fs(fs);  // 恢复原来的文件系统状态
        return PTR_ERR(f);
    }

    char *buf=kmalloc(1024 * 30, GFP_KERNEL);//一次性分配30KB的内存
    pos = 0;
    ret = kernel_read(f, buf, 1024*30, &pos);
    if (ret < 0) {
        pr_err("Error reading /proc/stat\n");
        filp_close(f, NULL);
        kfree(buf);
        set_fs(fs);
        return;
    }
    pr_info("Get: %s\n", buf);
    buf[ret] = '\0';
    filp_close(f, NULL);
    set_fs(fs);

    // Parse the buffer to extract CPU overhead information
    char *line;
    char *ptr = buf;
    int cpu_id = 0;

    while ((line = strsep(&ptr, "\n")) != NULL) {
        pr_info("line: %s\n", line);
        if (strncmp(line, "cpu", 3) == 0 && isdigit(line[3])) {
            int user, nice, system, idle, iowait, irq, softirq;
            sscanf(line, "cpu%d %d %d %d %d %d %d %d", &cpu_id, &user, &nice, &system, &idle, &iowait, &irq, &softirq);
            overhead_info_add(cpu_id, user, nice, system, idle, iowait, irq, softirq);
            if (cpu_id==online_cpu_num-1) break;
        }
    }

    kfree(buf);
}

static void init(void) {//对于本地的相关结构体进行初始化，即简单的将其num参数设置为0
    cores.num=0;
    forbidden.num=0;
    cpuInfo.cpu_num=0;
}

static bool check_busy(int cpuid, int *overhead) {//检查是否繁忙，如果繁忙则返回true，否则返回false，并且将利用率放到overhead中
    //如果利用率比较低，并且没有负责si，则返回false，但是对于发送端有一点小问题，因为发送端在第一次选择时不知道是用哪一个核来处理irq的
    long long user, nice, system, idle, iowait, irq, softirq;
    user = cpuInfo.cpu_info[cpuid].user;
    nice = cpuInfo.cpu_info[cpuid].nice;
    system = cpuInfo.cpu_info[cpuid].system;
    idle = cpuInfo.cpu_info[cpuid].idle;
    iowait = cpuInfo.cpu_info[cpuid].iowait;
    irq = cpuInfo.cpu_info[cpuid].irq;
    softirq = cpuInfo.cpu_info[cpuid].softirq;

    long long total = user + nice + system + idle + iowait + irq + softirq+1;
    long long busy = total - idle - iowait;
    int busy_rate = busy * 100 / total;
    *overhead=busy_rate;
    if ((busy_rate>OVERHEAD_THRESHOLD)||(irq+softirq>TOTAL_IRQ_THRESHOLD_ABSOLUTE)) return true;
    return false;
}

static void print_available_cores(void) {
    int i;
    pr_info("Available cores:\n");
    for (i=0;i<cores.num;i++) {
        pr_info("CPU %d, overhead %d\n", cores.cores[i].id, cores.cores[i].util);
    }
}

void update(void) {//构建cores结构体
    init();
    
    int now_cpuid=raw_smp_processor_id();
    int current_node = cpu_to_node(now_cpuid);  // 获取当前 CPU 所在的 NUMA 节点
    get_cpu_overhead_info();//重新获得了所有CPU的负载信息
    
    struct cpumask mask;
    int cpu;
    cpumask_and(&mask, cpumask_of_node(current_node), cpu_online_mask); // 获取与当前 CPU 所在同一 NUMA 节点上的 CPU
    pr_info("CPUs on NUMA node %d (including CPU %d):\n", current_node, now_cpuid);

    for_each_cpu(cpu, &mask) {
        if (cpu!=now_cpuid) {
            pr_info("CPU %d\n", cpu);
            int overhead;
            if (!check_busy(cpu,&overhead)) available_cores_add(cpu, overhead);
        }
    }
    //最终由于dcopy_thread的限制，还需要裁剪掉一部分，这里为了简单起见，直接选取前面的几个
    //但是在条大象流的情况下，这样会导致在编号较低的CPU上扎堆，有待进一步优化
    cores.num=min(cores.num,nd_params.nd_num_dc_thread);
    print_available_cores();
}

static int get_idx_in_available_cores(int cpuid) {//如果在的话，直接返回idx，否则返回num
    int i;
    for (i=0;i<cores.num;i++) {
        if (cores.cores[i].id==cpuid) return i;
    }
    return cores.num;
}

int nd_dcopy_sche_smart_rr(int last_qid) {//表示上一次使用的CPU编号，但是有可能没有初始化，并且也有可能不在round_robin的范围内吗？
    //如果last_qid不在available cores中，则直接从头部开始round_robin
    //否则返回下一个可用的CPU编号
	struct nd_dcopy_queue *queue;
    int start_idx=get_idx_in_available_cores(last_qid);
    if (start_idx==cores.num) start_idx=0;
    else start_idx=(start_idx+1)%cores.num;
    int i = 0, qid,qid_idx;
	bool find = false;
	
 	for (i = 0; i < nd_params.nd_num_dc_thread; i++) {
        qid_idx=(start_idx+i)%cores.num;
		qid = cores.cores[qid_idx].id;
		queue =  &nd_dcopy_q[qid];
		if(qid == raw_smp_processor_id()) continue;
		if(atomic_read(&queue->queue_size) >= queue->queue_threshold) continue;
		find = true;
		break;
	}
	if(!find) return -1;
	return qid;
}

int decide_update_choose_strategy(int last_qid) {
    if (send_call_times==1) {//第一次时直接生成NUMA节点作为拷贝线程，而不考虑irq的处理，即采用的是残缺版的update
        if (!is_1update) {
            is_1update=true;
            init();
            int now_cpuid=raw_smp_processor_id();
            int current_node = cpu_to_node(now_cpuid);  // 获取当前 CPU 所在的 NUMA 节点

            struct cpumask mask;
            int cpu;
            cpumask_and(&mask, cpumask_of_node(current_node), cpu_online_mask); // 获取与当前 CPU 所在同一 NUMA 节点上的 CPU
            pr_info("CPUs on NUMA node %d (including CPU %d):\n", current_node, now_cpuid);

            for_each_cpu(cpu, &mask) {
                if (cpu!=now_cpuid) {
                    pr_info("CPU %d\n", cpu);
                    available_cores_add(cpu, 50);
                }
            }
            //最终由于dcopy_thread的限制，还需要裁剪掉一部分，这里为了简单起见，直接选取前面的几个
            //但是在条大象流的情况下，这样会导致在编号较低的CPU上扎堆，有待进一步优化
            cores.num=min(cores.num,nd_params.nd_num_dc_thread);
            print_available_cores();
        }
    }
    else if (send_call_times==2) {
        if (!is_2update) {
            is_2update=true;
            update();
        }
    }
    return nd_dcopy_sche_smart_rr(last_qid);
}