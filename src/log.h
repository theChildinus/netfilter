//
// Created by yingzi on 2017/9/12.
//

/**
 * log主要用来提供日志宏定义，便于统一修改日志等级
 */

#ifndef NET_FILTER_LOG_H
#define NET_FILTER_LOG_H

#include "conf.h"
//static char MSG_BUF[10000];

#define DEBUG(...) printk(KERN_DEBUG "DEBUG:" __VA_ARGS__)
#define INFO(...) printk(KERN_INFO "INFO :" __VA_ARGS__)
#define WARNING(...) printk(KERN_WARNING "WARN :" __VA_ARGS__)
#define ERROR(...) printk(KERN_ERR "ERROR:" __VA_ARGS__)

//#define DEBUG_LEN(str, len) strncpy(MSG_BUF, str, len);MSG_BUF[len] = '\0';DEBUG("%s", MSG_BUF);

//#define LOG_TIME

#endif //NET_FILTER_LOG_H