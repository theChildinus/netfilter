/**
 * netFilter运行在内核中，通过往网络挂载点挂载钩子函数实现网络流量的捕获
 */

#ifndef NET_FILTER_NET_FILTER_H
#define NET_FILTER_NET_FILTER_H

#include<linux/netfilter.h>

/**
 * 初始化netFilter
 * @return 初始化成功:0,初始化失败:1
 */
int initNetFilter(void);

/**
 * 释放netFilter钩子
 */
void releaseNetFilter(void);

/**
 * 钩子函数声明
 * @param hooknum
 * @param skb
 * @param in
 * @param out
 * @param okfn
 * @return
 */

unsigned int hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in,
                       const struct net_device *out, int (*okfn)(struct sk_buff *));
#endif //NET_FILTER_NET_FILTER_H