// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
// Copyright(c) 2016-18 Intel Corporation.

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include "defines.h"
#include "sgx_call.h"

#define PAGE_SIZE  4096

#define SGX_REG_PAGE_FLAGS \
	(SGX_SECINFO_REG | SGX_SECINFO_R | SGX_SECINFO_W | SGX_SECINFO_X)

#define IMAGE		"encl.bin"
#define SIGSTRUCT	"encl.ss"
#define TOKEN		"encl.token"

static struct sgx_secs secs;
static bool initialized = false;

static bool encl_create(int dev_fd, unsigned long bin_size,
			struct sgx_secs *secs)
{
	struct sgx_enclave_create ioc;
	void *area;
	int rc;

	memset(secs, 0, sizeof(*secs));
	secs->ssa_frame_size = 1;
	secs->attributes = SGX_ATTR_MODE64BIT | SGX_ATTR_DEBUG;
	secs->xfrm = 7;

	for (secs->size = PAGE_SIZE; secs->size < bin_size; )
		secs->size <<= 1;

	area = mmap(NULL, secs->size * 2, PROT_NONE, MAP_SHARED, dev_fd, 0);
	if (area == MAP_FAILED) {
		perror("mmap");
		return false;
	}

	secs->base = ((uint64_t)area + secs->size - 1) & ~(secs->size - 1);
	munmap(area, secs->base - (uint64_t)area);
	munmap((void *)(secs->base + secs->size),
	       (uint64_t)area + secs->size - secs->base);

	if (mprotect((void *)secs->base, secs->size, PROT_READ | PROT_WRITE | PROT_EXEC)) {
		perror("mprotect");
		munmap((void *)secs->base, secs->size);
		return false;
	}

	ioc.src = (unsigned long)secs;
	rc = ioctl(dev_fd, SGX_IOC_ENCLAVE_CREATE, &ioc);
	if (rc) {
		fprintf(stderr, "ECREATE failed rc=%d, err=%d.\n", rc, errno);
		munmap((void *)secs->base, secs->size);
		return false;
	}

	return true;
}

static bool encl_add_pages(int dev_fd, uint64_t addr, void *data,
			   unsigned long length, uint64_t flags)
{
	struct sgx_enclave_add_page ioc;
	struct sgx_secinfo secinfo;
	int rc;

	memset(&secinfo, 0, sizeof(secinfo));
	secinfo.flags = flags;

	ioc.src = (uint64_t)data;
	ioc.addr = addr;
	ioc.secinfo = (unsigned long)&secinfo;
	ioc.mrmask = (__u16)-1;

	uint64_t added_size = 0;
	while (added_size < length) {
		rc = ioctl(dev_fd, SGX_IOC_ENCLAVE_ADD_PAGE, &ioc);
		if (rc) {
			fprintf(stderr, "EADD failed rc=%d.\n", rc);
			return false;
		}

		ioc.addr += PAGE_SIZE;
		ioc.src += PAGE_SIZE;
		added_size += PAGE_SIZE;
	}

	return true;
}

static bool encl_build(struct sgx_secs *secs, void *bin, unsigned long bin_size, 
		       struct sgx_sigstruct *sigstruct,
		       struct sgx_einittoken *token)
{
	struct sgx_enclave_init ioc;
	int dev_fd;
	int rc;

	dev_fd = open("/dev/isgx", O_RDWR);
	if (dev_fd < 0) {
		fprintf(stderr, "Unable to open /dev/sgx\n");
		return false;
	}

	if (!encl_create(dev_fd, bin_size, secs))
		goto out_dev_fd;

	if (!encl_add_pages(dev_fd, secs->base + 0, bin, PAGE_SIZE, SGX_SECINFO_TCS))
		goto out_map;

	if (!encl_add_pages(dev_fd, secs->base + PAGE_SIZE, bin + PAGE_SIZE,
			    bin_size - PAGE_SIZE, SGX_REG_PAGE_FLAGS))
		goto out_map;

	ioc.addr = secs->base;
	ioc.sigstruct = (uint64_t)sigstruct;
	ioc.einittoken = (uint64_t)token;
	rc = ioctl(dev_fd, SGX_IOC_ENCLAVE_INIT, &ioc);
	if (rc) {
		printf("EINIT failed rc=%d\n", rc);
		goto out_map;
	}

	close(dev_fd);
	return true;
out_map:
	munmap((void *)secs->base, secs->size);
out_dev_fd:
	close(dev_fd);
	return false;
}

static bool get_file_size(const char *path, off_t *bin_size)
{
	struct stat sb;
	int ret;

	ret = stat(path, &sb);
	if (ret) {
		perror("stat");
		return false;
	}

	if (!sb.st_size || sb.st_size & 0xfff) {
		fprintf(stderr, "Invalid blob size %lu\n", sb.st_size);
		return false;
	}

	*bin_size = sb.st_size;
	return true;
}

static bool encl_data_map(const char *path, void **bin, off_t *bin_size)
{
	int fd;

	fd = open(path, O_RDONLY);
	if (fd == -1)  {
		fprintf(stderr, "open() %s failed, errno=%d.\n", path, errno);
		return false;
	}

	if (!get_file_size(path, bin_size))
		goto err_out;

	*bin = mmap(NULL, *bin_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (*bin == MAP_FAILED) {
		fprintf(stderr, "mmap() %s failed, errno=%d.\n", path, errno);
		goto err_out;
	}

	close(fd);
	return true;

err_out:
	close(fd);
	return false;
}

static bool load_sigstruct(const char *path, void *sigstruct)
{
	int fd;

	fd = open(path, O_RDONLY);
	if (fd == -1)  {
		fprintf(stderr, "open() %s failed, errno=%d.\n", path, errno);
		return false;
	}

	if (read(fd, sigstruct, sizeof(struct sgx_sigstruct)) !=
	    sizeof(struct sgx_sigstruct)) {
		fprintf(stderr, "read() %s failed, errno=%d.\n", path, errno);
		close(fd);
		return false;
	}

	close(fd);
	return true;
}

static bool load_token(const char *path, void *token)
{
	int fd;

	fd = open(path, O_RDONLY);
	if (fd == -1)  {
		fprintf(stderr, "open() %s failed, errno=%d.\n", path, errno);
		return false;
	}

	if (read(fd, token, sizeof(struct sgx_einittoken)) !=
		sizeof(struct sgx_einittoken)) {
		fprintf(stderr, "read() %s failed, errno=%d.\n", path, errno);
		close(fd);
		return false;
	}

	close(fd);
	return true;
}

int pal_get_version(void)
{
	return 1;
}

int pal_init(const char *args, const char *log_level)
{
	struct sgx_sigstruct sigstruct;
	struct sgx_einittoken token;
	off_t bin_size;
	void *bin;

	if (!encl_data_map(IMAGE, &bin, &bin_size))
		return -ENOENT;

	if (!load_sigstruct(SIGSTRUCT, &sigstruct))
		return -ENOENT;

	if (!load_token(TOKEN, &token))
		return -ENOENT;

	if (!encl_build(&secs, bin, bin_size, &sigstruct, &token))
		return -EINVAL;

	initialized = true;	

	return 0;
}

int pal_exec(char *path, char *argv[], const char *envp[],
	     int *exit_code, int stdin, int stdout, int stderr)
{
        FILE *fp = fdopen(stderr, "w");
        if (!fp)
                return -1;

	if (!initialized) {
	        fprintf(fp, "enclave runtime skeleton uninitialized yet!\n");
		fclose(fp);
	        return -1;
	}

	uint64_t result = 0;
	int ret = SGX_ENTER_1_ARG(ECALL_MAGIC, (void *)secs.base, &result);
	if (ret) {
		fprintf(fp, "failed to initialize enclave\n");
		fclose(fp);
		return ret;
	}
	if (result != INIT_MAGIC) {
		fprintf(fp, "Unexpected result: 0x%lx != 0x%lx\n", result, INIT_MAGIC);
		fclose(fp);
		return -1;
	}

	fprintf(fp, "Enclave runtime skeleton initialization succeeded\n");
	fclose(fp);

	*exit_code = 0;

	return 0;
}

int pal_destroy(void)
{
	if (!initialized) {
		fprintf(stderr, "Enclave runtime skeleton uninitialized yet!\n");
		return -1;
	}
	return 0;
}
