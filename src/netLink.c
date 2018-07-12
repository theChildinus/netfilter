#include <linux/init.h>  
#include <linux/module.h>  
#include <linux/timer.h>  
#include <linux/time.h>  
#include <linux/types.h>  
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/version.h>

#include "log.h"
#include "netLink.h"

/**
 * netLink创建的与客户端通信的内核套接字
 */
static struct sock *nl_sk;
/**
 * 表示客户端的连接pid
 */
UserInfo userInfo;
/**
 * 表示用户对该数据包返回的操作指令
 */
UserCmd userCmd;
/**
 * 对内核完成量超时次数的计数
 */
TimeoutStruct timeoutStruct;

extern struct completion msgCompletion;

/**
 * KERNEL版本>=3.10时，需要一个netLink内核配置参数
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
static struct netlink_kernel_cfg cfg;
#endif

/**
 * 内核态netLink收到用户态发来的消息时触发此回调函数
 * 函数获取用户指令并置userCmd相应标识位
 * @param skb
 */
static void recvMsgNetLink(struct sk_buff *skb) {
    struct nlmsghdr *nlh;   // 指向netLink消息首部的指针

//    DEBUG("recvMsgNetLink is triggered");

    if (skb->len >= NLMSG_SPACE(0)) {
        nlh = nlmsg_hdr(skb);   // 获取netLink消息首部指针
//        DEBUG("nlh->nlmsg_len = %d, sizeof(struct nlmsghdr)=%lu, skb->len=%d, nlh->nlmsg_len=%d", nlh->nlmsg_len, sizeof(struct nlmsghdr), skb->len, nlh->nlmsg_len);
        if ((nlh->nlmsg_len >= sizeof(struct nlmsghdr)) && (skb->len >= nlh->nlmsg_len)){
            // 如果首部完整
            if (nlh->nlmsg_type == NET_LINK_CONNECT){
                // 如果消息类型为请求连接
                INFO("netLink client connect msg");
                INFO("netLink client pid is %d", nlh->nlmsg_pid);

                write_lock_bh(&userInfo.lock);
                userInfo.pid = nlh->nlmsg_pid;
                write_unlock_bh(&userInfo.lock);

                // 初始化时将CompletionTimeout次数计0
                write_lock_bh(&timeoutStruct.lock);
                timeoutStruct.timeoutTimes = 0;
                write_unlock_bh(&timeoutStruct.lock);

                //sendMsgNetLink("you have connected to the kernel!", strlen("you have connected to the kernel!"));  // 向客户端发送回复消息
            }
            else if (nlh->nlmsg_type == NET_LINK_DISCONNECT){
                // 如果消息类型为释放连接
                INFO("netLink client disconnect");

                write_lock_bh(&userInfo.lock);
                if (nlh->nlmsg_pid == userInfo.pid) {
                    userInfo.pid = 0;
                }
                else {
                    ERROR("user pid is changed!");
                }
                write_unlock_bh(&userInfo.lock);

//                // 对可能还在等待的内核唤醒
//                write_lock_bh(&userCmd.lock);
//                userCmd.userCmdEnum = ACCEPT;
//                write_unlock_bh(&userCmd.lock);
//
//                complete(&msgCompletion);

                // 让还在等待的内核超时
                mdelay(KERNEL_WAIT_MILISEC);

                // 清空超时次数
                write_lock_bh(&timeoutStruct.lock);
                timeoutStruct.timeoutTimes = 0;
                write_unlock_bh(&timeoutStruct.lock);
            }
            else if (nlh->nlmsg_type == NET_LINK_ACCEPT || nlh->nlmsg_type == NET_LINK_DISCARD) {
                write_lock_bh(&timeoutStruct.lock);
                if (timeoutStruct.timeoutTimes > 0) {
                    INFO("recvd timeout command");
                    --timeoutStruct.timeoutTimes;
                    write_unlock_bh(&timeoutStruct.lock);
                    return;
                }
                write_unlock_bh(&timeoutStruct.lock);

                write_lock_bh(&userCmd.lock);
                if (nlh->nlmsg_type == NET_LINK_ACCEPT) {
                    INFO("netLink accept");
                    userCmd.userCmdEnum = ACCEPT;
                }
                else {
                    INFO("netLink discard");
                    userCmd.userCmdEnum = DISCARD;
                }
                write_unlock_bh(&userCmd.lock);

                // 唤醒阻塞的内核线程
                complete(&msgCompletion);
            }
            else {
                // 如果消息类型为其他指令,有待操作
                WARNING("unkown user cmd %d", nlh->nlmsg_type);
            }
        }
        else{
            INFO("netLink message too short");
        }
//        memcpy(str, NLMSG_DATA(nlh), sizeof(str));  // 获取netLink消息主体
//        INFO("netLink message received:%s\n", str);
    }
}

int createNetLink(void) {
    // 对不同版本的内核调用不同的函数
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
    cfg.groups = 0; // 0表示单播，1表示多播
    cfg.flags = 0;
    cfg.input = recvMsgNetLink;    // 回调函数，当收到消息时触发
    cfg.cb_mutex = NULL;

    // 创建服务，init_net表示网络设备命名空间指针，NET_LINK_TEST表示协议类型，cfg指向netLink的配置结构体
    nl_sk = netlink_kernel_create(&init_net, NET_LINK_PROTOCOL, &cfg);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 18)
    nl_sk = netlink_kernel_create(&init_net, NET_LINK_PROTOCOL, 0, recvMsgNetlink, NULL, THIS_MODULE);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 16)
    nl_sk = netlink_kernel_create(NET_LINK_PROTOCOL, 0, recvMsgNetlink, NULL, THIS_MODULE);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 10)
    nl_sk = netlink_kernel_create(NET_LINK_PROTOCOL, 0, recvMsgNetlink, THIS_MODULE);
#else
    // 其他更低版本
    nl_sk = netlink_kernel_create(NET_LINK_PROTOCOL, recvMsgNetlink);
#endif

    if (!nl_sk) {
        // netLink创建失败
        return 1;
    }

    // 初始时将客户端pid置0
    DEBUG("set client pid to 0\n");
    write_lock_bh(&userInfo.lock);
    userInfo.pid = 0;
    write_unlock_bh(&userInfo.lock);
    return 0;
}

void deleteNetLink(void) {
    if (nl_sk) {
        DEBUG("release netLink socket!\n");
        netlink_kernel_release(nl_sk);
    }
}

int sendMsgNetLink(char *message, int len) {
    // 向进程号为pid的用户态进程发送消息message
    struct sk_buff *skb;    // 定义套接字缓冲区
    int totalSize;   // 表示netLink消息首部加载荷对齐后的长度
    struct nlmsghdr *nlh;   // netLink首部
    sk_buff_data_t old_tail;    // 记录填充消息前skb的尾部，sk_buff_data_t类型表示偏移量或者指针
    int ret;    // 单播消息发送的返回值

    if (!message || !nl_sk) {
        // 异常情况，直接返回
        return 1;
    }

    // 实际发送的消息要带上终止符
    totalSize = NLMSG_SPACE(len + 1);    // 获取总长度，NLMSG_SPACE宏会计算消息加上首部再对齐后的长度

    skb = alloc_skb(totalSize, GFP_ATOMIC); //申请一个skb,长度为total_size,优先级为GFP_ATOMIC
    if (!skb) {
        ERROR("my_net_link:alloc_skb error");
        return 1;
    }
    old_tail = skb->tail;   // 记录填充消息前skb的尾部偏移量或指针

    // 先获取skb中消息的首部地址，根据内核版本变动
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 16)
    // 参数分别为套接字缓冲区，请求的端口id，消息序列号，消息类型，消息载荷长度，消息标志
    nlh = nlmsg_put(skb, 0, 0, NET_LINK_REPLY, totalSize - sizeof(struct nlmsghdr), 0);
#else
    nlh = NLMSG_PUT(skb, 0, 0, NET_LINK_TEST_REPLY, totalSize - sizeof(struct nlmsghdr));
#endif

    // 填充nlh的载荷部分，NLMSG_DATA宏用于取得nlh载荷部分首地址
    strncpy(NLMSG_DATA(nlh), message, len);
    strncpy(NLMSG_DATA(nlh) + len, "", 1);
//    DEBUG("my_net_link:send message '%s'.\n", (char *) NLMSG_DATA(nlh));

    //nlh->nlmsg_len = skb->tail - old_tail;  // 获取当前skb中填充消息的长度
    // 为python客户端尝试另一种填充长度的方法
    nlh->nlmsg_len = len + 1 + sizeof(struct nlmsghdr);

    // 设置控制字段
    //NETLINK_CB(skb).pid = 0;  // 消息发送者为内核，所以pid为0
    //NETLINK_CB(skb).dst_pid = pid;  // 消息接收者的pid
    NETLINK_CB(skb).dst_group = 0;    // 目标为进程时，设置为0

    // 向客户端发消息
    read_lock_bh(&userInfo.lock);
    if (userInfo.pid == 0){
//        read_unlock_bh(&userInfo.lock);
        return -1; // 如果客户端断开了连接，直接返回
    }
    // 发送单播消息，参数分别为nl_sk(内核套接字), skb(套接字缓冲区), pid(目的进程), MSG_DONTWAIT(不阻塞)
    ret = netlink_unicast(nl_sk, skb, userInfo.pid, MSG_DONTWAIT); // 发送单播消息
    read_unlock_bh(&userInfo.lock);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 16)
    // 如果内核版本过小，需要做一个出错时跳转标签
    nlmsg_failure:
#endif

    if (ret < 0) {
        ERROR("send msg failed!");
        return 1;
    }
    else return 0;
}




