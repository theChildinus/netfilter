/**
 * dealConf主要用来提供配置读取、数据包合法检查与提取、ip格式转换等功能
 */

#ifndef NET_FILTER_DEAL_CONF_H
#define NET_FILTER_DEAL_CONF_H


/**
 * 将保存在整数in中的16进制格式ip地址转成点分10进制的字符串保存在sip中并返回该地址
 * @param sip 预先分配的保存结果的字符串指针
 * @param in 16进制格式ip地址字符串
 * @return 10进制ip字符串
 */
char *in_ntoa(char *sip, __u32 in);

/**
 * 判断事件是不是关键事件
 * @param event 事件的起始位置
 * @param eventLen 事件的长度
 * @return 是关键事件返回name的起始位置，不是返回 NULL
 */
char *isImportantEvent(char *event, int eventLen);

/**
 * 在字符串范围内搜索另一字符串
 * @param originStr 源串的起始位置
 * @param originStrLen 源串的长度
 * @param patternStr 模式串
 * @param patternStrLen 模式串长度
 * @return 匹配成功返回首个模式串的起始位置，否则返回NULL
 */
char *searchStr(char *originStr, int originStrLen, const char *patternStr, int patternStrLen);

#endif //NET_FILTER_DEAL_CONF_H