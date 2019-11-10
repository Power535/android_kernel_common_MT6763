zram-y	:=	zcomp.o zram_drv.o

obj-$(CONFIG_ZRAM)	+=	zram.o

# zram accelerator implementation
obj-$(CONFIG_HWZRAM_IMPL)      += hwzram_impl.o

# vendors for zram accelerator
obj-$(CONFIG_HWZRAM_IMPL)      += vendor/

# hw zram driver
obj-$(CONFIG_HWZRAM_DRV)       += hwzram_drv.o
