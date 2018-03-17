#include<linux/init.h>
#include<linux/kernel.h>
#include<linux/module.h>
#include<linux/netfilter.h>
#include<linux/netfilter_ipv4.h>
#include<linux/ip.h>
#include<linux/inet.h>
#include<linux/skbuff.h>
#include<linux/tcp.h>
#include<linux/udp.h>
#include<linux/time.h>
#include <linux/timer.h>
#include <linux/timex.h>
#include <linux/rtc.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include<linux/string.h>
#include <linux/completion.h>

#include "log.h"
#include "netFilter.h"
#include "netLink.h"

MODULE_LICENSE("GPL");

//char MSG_BUF[10000];

/**
 * 内核完成量，供netfilter和netlink进行同步
 */
struct completion msgCompletion;

/**
 * 插入模块时调用的函数
 */
static int __init init(void) {
    // 插入模块时
    INFO("insert netFilter module to kernel!\n");

    // 初始化完成量
    init_completion(&msgCompletion);

    // 先初始化netLink模块，优先保证与用户态通信
    if (createNetLink() != 0) {
        ERROR("create netLink failed!\n");
        return 1;
    }
    else {
        INFO("create netLink success!\n");
    }

    // 初始化netFilter
    initNetFilter();

    return 0;
}

/**
 * 移除模块时调用的函数
 */
static void __exit fini(void) {
    INFO("remove netfilter module from kernel!\n");
    // 先释放netFilter钩子
    releaseNetFilter();
    // 释放netLink
    deleteNetLink();
}

// 模块入口，插入模块后调用绑定函数
module_init(init);
// 模块出口，插入模块后调用绑定函数
module_exit(fini);