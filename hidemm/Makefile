#ifndef TARGET_COMPILE
#    $(error TARGET_COMPILE not set)
#endif

ANDROID=1

ifndef KP_DIR
    KP_DIR = $(HOME)/kpm/KernelPatch
endif


CC = $(TARGET_COMPILE)gcc
LD = $(TARGET_COMPILE)ld

INCLUDE_DIRS := . include patch/include linux/include linux/arch/arm64/include linux/tools/arch/arm64/include

INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir))

CFLAGS += -fno-unwind-tables -fno-asynchronous-unwind-tables -fno-pic

objs := hidemm.o

all: hidemm.kpm

hidemm.kpm: ${objs}
	${CC} -r -o $@ $^

%.o: %.c
	${CC} $(CFLAGS) $(INCLUDE_FLAGS) -c -O2 -o $@ $<

.PHONY: clean
clean:
	rm -rf *.kpm
	find . -name "*.o" | xargs rm -f


load: hidemm.kpm
	@kp ${KPSKEY} kpm info hidemm >/dev/null && kp ${KPSKEY} kpm unload hidemm || true
	@kp ${KPSKEY} kpm load hidemm.kpm function_pointer_hook
	@kp ${KPSKEY} kpm info hidemm && echo ""


unload:
	@kp ${KPSKEY} kpm unload hidemm
	@echo "[-] unloaded"

