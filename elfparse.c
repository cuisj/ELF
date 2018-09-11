#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <elf.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

int main(int argc, char **argv)
{
	int fd, i;
	uint8_t *mem;
	struct stat st = {0};

	Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdr;
	Elf64_Shdr *shdr;

	Elf64_Shdr *shstrhdr;	/* 节头字符串表节头 */
	char *shstrtab;		/* 节头字符串表 */
	char *interp;

	if (argc < 2) {
		printf("Usage: %s <executable>\n", argv[0]);
		exit(0);
	}

	if ((fd = open(argv[1], O_RDONLY)) < 0) {
		perror("open");
		exit(-1);
	}

	if (fstat(fd, &st) < 0) {
		perror("fstat");
		exit(-1);
	}

	/* 映射可执行文件到内存 */
	mem = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (mem == MAP_FAILED) {
		perror("mmap");
		exit(-1);
	}

	/* 初始化ELF头、程序头，节头表 */
	ehdr = (Elf64_Ehdr *)mem;
	phdr = (Elf64_Phdr *)(mem + ehdr->e_phoff);
	shdr = (Elf64_Shdr *)(mem + ehdr->e_shoff);

	/* 检查是不是ELF文件 */
	if (mem[EI_MAG0] != ELFMAG0 && strncmp(&mem[EI_MAG1], "ELF", 3) != 0) {
		fprintf(stderr, "%s is not an ELF file\n", argv[1]);
		exit(-1);
	}

	/* 检查是不是可执行文件 */
	if (ehdr->e_type != ET_EXEC) {
		fprintf(stderr, "%s is not an executable\n", argv[1]);
		exit(-1);
	}

	printf("Programm Entry point: 0x%x\n", ehdr->e_entry);

	/* 打印出每个节的名字和地址 */

	shstrhdr = shdr + ehdr->e_shstrndx;
	shstrtab = mem + shstrhdr->sh_offset;

	printf("Section header list: \n");
	for (i = 0; i < ehdr->e_shnum; i++)
		printf("%20s\t0x%x\n", shstrtab + shdr[i].sh_name, shdr[i].sh_addr);

	/* 打印出段的名字和地址 */
	for (i = 0; i < ehdr->e_phnum; i++) {
		switch (phdr[i].p_type) {
		case PT_LOAD:
			if (phdr[i].p_offset == 0)
				printf("Text segment: 0x%x\n", phdr[i].p_vaddr);
			else
				printf("Data segment: 0x%x\n", phdr[i].p_vaddr);
			break;

		case PT_INTERP:
			interp = strdup((char *)&mem[phdr[i].p_offset]);
			printf("Interpreter: %s\n", interp);
			break;

		case PT_NOTE:
			printf("Note segment: 0x%x\n", phdr[i].p_vaddr);
			break;

		case PT_DYNAMIC:
			printf("Dynamic segment: 0x%x\n", phdr[i].p_vaddr);
			break;

		case PT_PHDR:
			printf("Phdr segment: 0x%x\n", phdr[i].p_vaddr);
			break;
		}
	}

	exit(0);
}
