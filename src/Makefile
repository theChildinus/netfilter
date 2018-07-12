# 模块名称为netfilter
MODULE_NAME := netfilter
# 指定入口函数所在模块
RESMAN_CORE_OBJS := main.o
# 指定其他被调用模块
RESMAN_GLUE_OBJS := netFilter.o dealConf.o netLink.o
# 指定工程由哪些模块构成
$(MODULE_NAME)-objs := $(RESMAN_CORE_OBJS) $(RESMAN_GLUE_OBJS)
# 指定最终生成的模块的名称为netfilter.o
obj-m := netfilter.o

# 获取当前路径
PWD := $(shell pwd)
# 获取当前系统版本号
KVER ?= $(shell uname -r)
# 获取编译目标目录
KDIR := /lib/modules/$(KVER)/build
# KDIR := /usr/src/linux-headers-$(KVER)

defalut:
    # 将各文件编译成.o的模块
	$(MAKE) -C $(KDIR) M=$(PWD) modules
	# 将除netfilter.o外全部删除
	cp netfilter.ko netfilter.tmp
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	mv netfilter.tmp netfilter.ko
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
