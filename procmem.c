#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/prctl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>

#define N 10

static long buf_size, mem_size;

static int read_buf(int fd, void *buf, long buf_size, void *addr)
{
	long off = 0;

	while (off < buf_size) {
		long ret = pread(fd, buf + off, buf_size - off, (long) addr);
		if (ret == -1)
			return -1;
		if (ret == 0)
			break;
		off += ret;
	}
	return off;
}

static int process_read_buf(pid_t pid, int fd, void *buf, long buf_size, void *addr)
{
	struct iovec riov, liov;
	long off = 0;

	while (off < buf_size) {
		long ret;

		liov.iov_base = buf + off;
		liov.iov_len = buf_size - off;
		riov.iov_len = buf_size - off;
		riov.iov_base = addr + off;

		ret = process_vm_readv(pid, &liov, 1, &riov, 1, 0);
		if (ret == -1)
			return -1;
		if (ret == 0)
			break;
		off += ret;
	}
	return off;
}

static int write_buf(int fd, void *buf, long buf_size)
{
	long off = 0;

	while (off < buf_size) {
		long ret = write(fd, buf + off, buf_size - off);
		if (ret <= -1)
			return -1;
		off += ret;
	}
	return off;
}

static int child(char *addr, int *sync_pipe, int *p) {
	long off, i;

	prctl(PR_SET_PDEATHSIG, 9, 0, 0, 0);
	close(p[0]);
	close(sync_pipe[0]);

	struct iovec iov = {.iov_base = addr, .iov_len = mem_size};
	for (off = 0; off < mem_size; off += 4096) {
		*(long *)(addr + off) = off;
	}
	close(sync_pipe[1]);

	for (i = 0; i < N; i++) {
		off = 0;
		while (off < mem_size) {
			long ret;

			iov.iov_base = addr + off;
			iov.iov_len = mem_size - off;
			ret = vmsplice(p[1], &iov, 1, SPLICE_F_GIFT);
			if (ret == -1)
				return 1;
			off += ret;
		}
	}

	return 0;
}

static int iter(char *cmd, pid_t pid, char *addr, int devmem, int dump_file, int *p)
{
	long ret = 0, off = 0;

	while (off < mem_size) {
		switch (cmd[0]) {
		case 's':
			ret = splice(p[0], 0, dump_file, 0, mem_size - off, 0);
			if (ret == -1)
				return -1;
			break;
		case 'm':
			ret = read_buf(devmem, addr, buf_size, addr + off);
			if (ret < 0)
				return -1;
			if (write_buf(dump_file, addr, buf_size) < 0)
				return -1;
			break;
		case 'p':
			ret = process_read_buf(pid, devmem, addr, buf_size, addr + off);
			if (ret < 0)
				return -1;
			if (write_buf(dump_file, addr, buf_size) < 0)
				return -1;
			break;
		default:
			return -1;
		}
		if (ret == 0)
			break;
		off += ret;
	}

	return 0;
}

int main(int argc, char **argv)
{
	int p[2], sync_pipe[2];
	int devmem, dump_file, i;
	char fname[4096];
	char *addr;
	pid_t pid;

	mem_size = atol(argv[4]);
	if (mem_size <= 0)
		return 1;
	buf_size = atol(argv[3]);
	if (buf_size <= 0 || buf_size > mem_size)
		return 1;
	addr = mmap(0, mem_size, PROT_READ | PROT_WRITE,
			MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
	if (addr == MAP_FAILED)
		return 1;

	if (pipe(p) == -1)
		return 1;
	if (pipe(sync_pipe) == -1)
		return 1;
	fcntl(p[1], F_SETPIPE_SZ, buf_size);
	pid = fork();
	if (pid < 0)
		return 1;
	if (pid == 0)
		return child(addr, sync_pipe, p);

	close(sync_pipe[1]);
	close(p[1]);
	// Wait while the child is filling memory.
	if (read(sync_pipe[0], addr, 1) != 0)
		return 1;
	close(sync_pipe[0]);

	snprintf(fname, sizeof(fname), "/proc/%d/mem", pid);
	devmem = open(fname, O_RDONLY);
	if (devmem == -1)
		return 1;

	dump_file = open(argv[2], O_CREAT | O_WRONLY, 0666);
	if (dump_file == -1)
		return 1;

	for (i = 0; i < N; i++) {
		struct timespec start, end;
		long ret;

		clock_gettime(CLOCK_MONOTONIC, &start);

		if (lseek(dump_file, 0, SEEK_SET) == -1)
			return 1;

		ret = iter(argv[1], pid, addr, devmem, dump_file, p);
		if (ret < 0)
			return 1;

		clock_gettime(CLOCK_MONOTONIC, &end);
		fprintf(stderr, "ok %ld MB/sec\n", mem_size / 1024 / (
				(end.tv_sec - start.tv_sec) * 1000 +
				(end.tv_nsec - start.tv_nsec)/1000000));
	}

	return 0;
}
