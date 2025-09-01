BPF_CLANG ?= clang
BPF_CFLAGS = -O2 -g -target bpf -D__TARGET_ARCH_x86 -I. -I/usr/include -I/usr/include/bpf

all: openssl_handshake.bpf.o vmlinux.h

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

openssl_handshake.bpf.o: openssl_handshake.bpf.c vmlinux.h
	$(BPF_CLANG) $(BPF_CFLAGS) -c openssl_handshake.bpf.c -o openssl_handshake.bpf.o

clean:
	rm -f *.o vmlinux.h
