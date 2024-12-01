#include <linux/types.h>
#include <linux/sched.h>
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
#include <linux/numa.h>
#include <linux/cpumask.h>
#include <linux/topology.h>
#include <linux/fs.h>
#include <linux/ctype.h>
#include <linux/types.h>
#include "nd_impl.h"
#include "nd_data_copy.h"

#define MAX_CPU_NUM 256
#define OVERHEAD_THRESHOLD 50
#define TOTAL_IRQ_THRESHOLD_ABSOLUTE 2000//表示如果有超过这个数值的jiffies，就认为这个核心是专门用于data_copy的

struct available_core{
    int id;
    int util;//取值为1-100表示其利用率
};

struct Available_cores{
    int num;
    struct available_core cores[MAX_CPU_NUM];
};

struct Forbidden_cores{
    int num;
    int forbidden_cores[MAX_CPU_NUM];
};

struct Cpu_Overhead_Info {
    long long user;//normal processes executing in user mode
    long long nice;//niced processes executing in user mode 
    long long system;//processes executing in kernel mode
    long long idle;//twiddling thumbs
    long long iowait;//waiting for I/O to complete
    long long irq;//servicing interrupts
    long long softirq;//servicing softirqs
};

struct Cpu_Info_List {
    int cpu_num;
    struct Cpu_Overhead_Info cpu_info[MAX_CPU_NUM];
};


int decide_update_choose_strategy(int last_qid);