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
#include <linux/string.h>
#include <linux/netfilter_bridge.h>
#include <linux/version.h>

#include "conf.h"
#include "log.h"
#include "netFilter.h"
#include "dealConf.h"
#include "netLink.h"

extern UserCmd userCmd; // netLink中的全局变量，表示用户指令

extern UserInfo userInfo;   // netlink中的全局变量，表示用户PID信息

extern TimeoutStruct timeoutStruct; // 对内核完成量超时次数的计数

#ifdef LOG_TIME
struct timeval startTime, endTime;
unsigned long timeSec;
unsigned long timeUSec;

struct timex txc;
struct rtc_time tm;
#endif

/**
 * 完成量，内核态发数据后阻塞等netlink收消息唤醒
 */
//DECLARE_COMPLETION(msgCompletion);
extern struct completion msgCompletion;

/**
 * netFilter钩子
 */
static struct nf_hook_ops nfho_single;

int initNetFilter(void){
    // 绑定钩子函数
    DEBUG("bind netFilter hook func\n");
    nfho_single.hook = (nf_hookfn *) hook_func;

    // 根据桥接和NAT选择不同的挂载方式
    if (BRIDGE == 0) {
        // 数据流入网桥前触发
        INFO("trigger before data into the bridge\n");
        nfho_single.hooknum = NF_BR_PRE_ROUTING;
        nfho_single.pf = PF_BRIDGE;
        nfho_single.priority = NF_BR_PRI_FIRST;
//        nfho_single.priority = NF_BR_PRI_BRNF;
    }
    else if (BRIDGE == 1) {
        // 数据流入网络层前触发
        INFO("triggr before data into network layer\n");
        nfho_single.hooknum = NF_INET_PRE_ROUTING;
        nfho_single.pf = PF_INET;
        nfho_single.priority = NF_IP_PRI_FILTER;
    }
    else {
        WARNING("illegal parameter BRIDGE = %d\n", BRIDGE);
        return 1;
    }

    //注册一个netFilter钩子
    INFO("register netFilter hook!\n");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
    nf_register_net_hook(&init_net, &nfho_single);
#else
    nf_register_hook(&nfho_single);
#endif

    return 0;
}

void releaseNetFilter(void){
    INFO("unRegister netFilter hook!");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
    nf_unregister_net_hook(&init_net, &nfho_single);
#else
    nf_unregister_hook(&nfho_single);   // 卸载钩子
#endif
}

unsigned int hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in,
                       const struct net_device *out, int (*okfn)(struct sk_buff *)) {
    struct ethhdr *eth; // 以太网帧首部指针
    struct iphdr *iph;  // ip数据报首部指针

    struct udphdr *udp_head; // udp报文首部长度
    int udp_head_len;   // 首部长度

    char *data; // data是数据指针游标，从UDP body开始
    int data_len;

    // 事件范围
    char *tag_head;
    char *tag_tail;
    unsigned long tag_len;

    // 关键事件标志
    char *important_flag_pos;

    // 线性化SKB
    skb_linearize(skb);

    // 1. 判断是否已经有客户端连接
    read_lock_bh(&userInfo.lock);
    if (userInfo.pid == 0) {
        read_unlock_bh(&userInfo.lock);
        return NF_ACCEPT;
    }
    read_unlock_bh(&userInfo.lock);

    // 2. 判断是否为无效或者空数据包
    eth = eth_hdr(skb); // 获得以太网帧首部指针
    if(!skb || !eth) {
        return NF_ACCEPT;
    }

    // 3. 过滤掉发往本地主机的数据、以太网广播报文、以太网多播报文、本地主机环回报文，只留下发往其他主机的报文
    if(skb->pkt_type != PACKET_OTHERHOST) {
        return NF_ACCEPT;
    }


    // IP head和body长度
    iph = ip_hdr(skb);  // 获得ip数据报首部指针，或者iph = (struct iphdr *) data;

    // 4. 按源IP和目的IP过滤IP数据报
    if (iph->saddr != in_aton(SOURCE_IP)
        || iph->daddr != in_aton(TARGET_IP)) {
        // 比较配置中ip与获取ip的16进制形式
        return NF_ACCEPT;
    }

    DEBUG("trigger netfilter hook func");


    // 5. 过滤掉非UDP协议
    if (iph->protocol != IPPROTO_UDP) {
        return NF_ACCEPT;
    }

    // UDP head和body长度
    skb_set_transport_header(skb, sizeof(struct iphdr));
    udp_head = udp_hdr(skb);
    udp_head_len = sizeof(struct udphdr);

    // data指向UDP报文body
    data = (char*)udp_head + udp_head_len;
    data_len = ntohs(udp_head->len) - sizeof(struct udphdr);
    DEBUG("udp data len is %d", data_len);

    // 获取SKB的len和data_len;
    unsigned int skb_len = skb->len;
    unsigned int skb_data_len = skb->data_len;
    DEBUG("skb_len = %u", skb_len);
    DEBUG("skb_data_len = %u", skb_data_len);

    // 数据切片指针
    struct skb_shared_info *shinfo = skb_shinfo(skb);
    if (shinfo == NULL) {
        DEBUG("shinfo is null");
        return NF_ACCEPT;
    }
    // 数据切片数量
    unsigned int nr_frags = 0;
    nr_frags = shinfo->nr_frags;
    DEBUG("nr_frags = %u", nr_frags);

    // 访问frags[0]
    struct skb_frag_struct frags0 = shinfo->frags[0];
    // 获取frags[0].size
    unsigned int frags0Size = (unsigned int)frags0.size;
    DEBUG("frags0Size = %u", frags0Size);
    // 获取page_offset
    unsigned int frags0PageOffset = (unsigned int)frags0.page_offset;
    DEBUG("frags0PageOffset = %u", frags0PageOffset);

    DEBUG("sizeof(struct page) = %u", sizeof(struct page));

    struct page *frags0Page = frags0.page.p;
    if (frags0Page == NULL) {
        DEBUG("frags0Page is NULL");
        return NF_ACCEPT;
    }
    else {
        DEBUG("frags0Page is not NULL");
    }

//    // 访问page的slab
//    struct kmem_cache *slab = frags0Page->slab_cache;
//    if (slab == NULL) {
//        DEBUG("slab is NULL");
//        return NF_ACCEPT;
//    }
//    else {
//        DEBUG("slab is not NULL");
//    }


//    frags0Page->flags;
//    frags0Page->mapping;
//    frags0Page->s_mem;
//    frags0Page->compound_mapcount;
//    frags0Page->index;
//    frags0Page->freelist;
//    frags0Page->counters;
//    frags0Page->_mapcount;
//    frags0Page->inuse;
//    frags0Page->objects;
//    frags0Page->frozen;
//    frags0Page->units;
//    frags0Page->_refcount;
//    frags0Page->lru;
//    frags0Page->pgmap;
//    frags0Page->next;
//    frags0Page->pages;
//    frags0Page->pobjects;
//    frags0Page->rcu_head;
//    frags0Page->compound_head;
//    frags0Page->compound_dtor;
//    frags0Page->compound_order;
//    frags0Page->__pad;
//    frags0Page->pmd_huge_pte;
//    frags0Page->private;
//    frags0Page->ptl;
//    frags0Page->slab_cache;
//    frags0Page->mem_cgroup;



//    // 获取frags[0].page
//    char *frags0Page = frags0.page;
//    if (frags0Page == NULL) {
//        DEBUG("frags0Page is null");
//    }
//    else {
//        DEBUG("frags0Page is not null");
//    }

//    // 访问frag_list
//    struct sk_buff *frag_list = shinfo->frag_list;
//    if (frag_list == NULL) {
//        DEBUG("frag_list is null");
//        return NF_ACCEPT;
//    }
//    else {
//        DEBUG("frag_list is null");
//    }
//
//    // 访问first_len
//    int first_len = skb_pagelen(skb);
//    DEBUG("first_len = %d", first_len);

//    DEBUG_LEN(data, frags0Size);
//    DEBUG("data:%s", data);
//    DEBUG("data+500:%s", data + 500);
//    DEBUG("data+1000:%s", data + 1000);
//    DEBUG("data+1500:%s", data + 1500);
//    DEBUG("data+2000:%s", data + 2000);
    unsigned int data_size = 0;
    for (; data_size < data_len; data_size += 500) {
        DEBUG("data + %u:%s", data_size, data + data_size);
    }


    DEBUG("NF_ACCEPT");


//    if (data_len > 200) {
//        shinfo = skb_shinfo(skb);
//        skb = shinfo->frag_list;
//        data_len = ntohs(udp_hdr(skb)->len) - sizeof(struct udphdr);
//        DEBUG("udp data len is %d", data_len);
//    }

    // 6. 在data中搜索匹配head
    tag_head = searchStr(data, data_len, TAG_HEAD, sizeof(TAG_HEAD) - 1);
    if (tag_head == NULL) {
        DEBUG("search head failed!");
        return NF_ACCEPT;
    }
    else {
        DEBUG("search head success!");
    }

    // 在data中继续搜索匹配tail
    tag_tail = searchStr(tag_head + (sizeof(TAG_HEAD) - 1), data_len - (tag_head - data) - (sizeof(TAG_HEAD) - 1), TAG_TAIL, sizeof(TAG_TAIL) - 1);
    if (tag_tail == NULL) {
        DEBUG("search tail failed!");
        return NF_ACCEPT;
    }
    else {
        DEBUG("search tail success!");
    }

    // 确定事件长度
    tag_len = tag_tail - tag_head + (sizeof(TAG_TAIL) - 1);

    // 判断事件是不是关键事件
    important_flag_pos = isImportantEvent(tag_head, tag_len);

    // 7. 发送消息
    sendMsgNetLink(tag_head, tag_len);

    // 8. 消息发出后对关键事件使用完成量进行超时阻塞，非关键事件直接通过
    if (important_flag_pos != NULL) {
        INFO("important event:%.*s", (int)tag_len, tag_head);
        sendMsgNetLink(tag_head, tag_len);

#ifdef LOG_TIME
        do_gettimeofday(&startTime);
        do_gettimeofday(&(txc.time));
        rtc_time_to_tm(txc.time.tv_sec, &tm);
        DEBUG("UTC time:%d-%d-%d %d:%d:%d", tm.tm_year+1900, tm.tm_mon, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
#endif
        if (wait_for_completion_timeout(&msgCompletion, KERNEL_WAIT_MILISEC) == 0) {
#ifdef LOG_TIME
            do_gettimeofday(&endTime);
            DEBUG("start sec is %d", startTime.tv_sec);
            DEBUG("end sec is %d", endTime.tv_sec);

            timeUSec = (endTime.tv_sec - startTime.tv_sec) * 1000000 + endTime.tv_usec - startTime.tv_usec;
            timeSec = timeUSec / 1000000;
            timeUSec -= timeSec * 1000000;
            DEBUG("wait %ld s, %ld us, timeout", timeSec, timeUSec);
#endif

            write_lock_bh(&timeoutStruct.lock);
            ++timeoutStruct.timeoutTimes;
            write_unlock_bh(&timeoutStruct.lock);
            WARNING("event %.*s wait response timeout", (int)tag_len, tag_head);
            return NF_ACCEPT;
        }
        else {
#ifdef LOG_TIME
            do_gettimeofday(&endTime);
            DEBUG("start sec is %d", startTime.tv_sec);
            DEBUG("end sec is %d", endTime.tv_sec);

            timeUSec = (endTime.tv_sec - startTime.tv_sec) * 1000000 + endTime.tv_usec - startTime.tv_usec;
            timeSec = timeUSec / 1000000;
            timeUSec -= timeSec * 1000000;
#endif
            WARNING("recvd response");
#ifdef LOG_TIME
            DEBUG("wait %ld s, %ld us", timeSec, timeUSec);
#endif
        }

        // 直接读userCmd
        read_lock_bh(&userCmd.lock);
        if (userCmd.userCmdEnum == DISCARD) {
            INFO("drop event %.*s", (int)tag_len, tag_head);
            read_unlock_bh(&userCmd.lock);
            return NF_DROP;
        }
        else {
            INFO("accept event %.*s", (int)tag_len, tag_head);
            read_unlock_bh(&userCmd.lock);
            return NF_ACCEPT;
        }
    }
    else {
        DEBUG("unimportant event:%.*s", (int)tag_len, tag_head);
//        sendMsgNetLink(tag_head, tag_len);
        return NF_ACCEPT;
    }
}
