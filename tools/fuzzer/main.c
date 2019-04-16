/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of the Intel Corporation nor the
 *     names of its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Author: Liam Girdwood <liam.r.girdwood@linux.intel.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <sys/time.h>
#include <pthread.h>
#include <string.h>
#include "fuzzer.h"
#include <uapi/ipc/topology.h>
#include "qemu-bridge.h"
#include <uapi/ipc/trace.h>

pthread_cond_t ipc_cond = PTHREAD_COND_INITIALIZER;
pthread_mutex_t ipc_mutex = PTHREAD_MUTEX_INITIALIZER;

/* list of supported target platforms */
static struct fuzz_platform *platform[] =
{
		&byt_platform,
		&cht_platform,
};

static void usage(char *name)
{
	int i;

	fprintf(stdout, "Usage 	%s -p platform <option(s)>\n", name);
	fprintf(stdout, "		-t topology file\n");
	fprintf(stdout, "		-p platform name\n");

	fprintf(stdout, "		supported platforms: ");
	for (i = 0; i < ARRAY_SIZE(platform); i++) {
		fprintf(stdout, "%s ", platform[i]->name);
	}
	fprintf(stdout, "\n");

	exit(0);
}

static void ipc_dump(struct fuzz *fuzzer, struct ipc_msg *msg)
{
	/* TODO: dump data here too */
	fprintf(stdout, "ipc: header 0x%x size %d reply %d\n",
			msg->header, msg->msg_size, msg->reply_size);
}

static void ipc_dump_err(struct fuzz *fuzzer, struct ipc_msg *msg)
{
	/* TODO: dump data here too */
	fprintf(stderr, "ipc: header 0x%x size %d reply %d\n",
		msg->header, msg->msg_size, msg->reply_size);
}

void *fuzzer_create_io_region(struct fuzz *fuzzer, int id, int idx)
{
	struct fuzz_platform *plat = fuzzer->platform;
	struct fuzzer_reg_space *space;
	char shm_name[32];
	int err;
	void *ptr = NULL;

	space = &plat->reg_region[idx];

	sprintf(shm_name, "%s-io", space->name);

	err = qemu_io_register_shm(shm_name, id, space->desc.size, &ptr);
	if (err < 0)
		fprintf(stderr, "error: can't allocate IO %s:%d SHM %d\n", shm_name,
				id, err);

	return ptr;
}

void *fuzzer_create_memory_region(struct fuzz *fuzzer, int id, int idx)
{
	struct fuzz_platform *plat = fuzzer->platform;
	struct fuzzer_mem_desc *desc;
	char shm_name[32];
	int err;
	void *ptr = NULL;

	desc = &plat->mem_region[idx];

	/* shared via SHM (not shared on real HW) */
	sprintf(shm_name, "%s-mem", desc->name);
	err = qemu_io_register_shm(shm_name, id, desc->size, &ptr);
	if (err < 0)
		fprintf(stderr, "error: can't allocate %s:%d SHM %d\n", shm_name,
				id, err);

	return ptr;
}

/* frees all SHM and message queues */
void fuzzer_free_regions(struct fuzz *fuzzer)
{
	struct fuzz_platform *plat = fuzzer->platform;
    int i;

    for (i = 0; i < plat->num_mem_regions; i++)
        qemu_io_free_shm(i);

    for (i = 0; i < plat->num_reg_regions; i++)
    	 qemu_io_free_shm(i);

    qemu_io_free();
}

/* called by platform when it receives IPC message */
void fuzzer_ipc_msg_rx(struct fuzz *fuzzer)
{
	struct sof_ipc_comp_reply r;
	struct sof_ipc_cmd_hdr hdr;
	uint32_t cmd;

	printf("in %s\n", __func__);
	/* read mailbox */
	fuzzer->platform->mailbox_read(fuzzer, 0, &hdr, sizeof(hdr));
	cmd = hdr.cmd & SOF_GLB_TYPE_MASK;
	printf("cmd is 0x%x\n", cmd);

	/* check message type */
	switch (cmd) {
	case SOF_IPC_GLB_REPLY:
		fprintf(stderr, "error: ipc reply unknown\n");
		break;
	case SOF_IPC_FW_READY:
		fuzzer->platform->fw_ready(fuzzer);
		fuzzer->boot_complete = 1;
		break;
	case SOF_IPC_GLB_COMPOUND:
	case SOF_IPC_GLB_TPLG_MSG:
	case SOF_IPC_GLB_PM_MSG:
	case SOF_IPC_GLB_COMP_MSG:
	case SOF_IPC_GLB_STREAM_MSG:
	case SOF_IPC_GLB_TRACE_MSG:
		printf("cmd is 0x%x\n", cmd);
		fuzzer->platform->mailbox_read(fuzzer, 0, &r, sizeof(r));
		break;
	default:
		fprintf(stderr, "error: unknown DSP message 0x%x\n", cmd);
		break;
	}

}

/* called by platform when it receives IPC message reply */
void fuzzer_ipc_msg_reply(struct fuzz *fuzzer)
{
	fuzzer->platform->get_reply(fuzzer, &fuzzer->msg);
	ipc_dump(fuzzer, &fuzzer->msg);

	pthread_mutex_lock(&ipc_mutex);
	pthread_cond_signal(&ipc_cond);
	pthread_mutex_unlock(&ipc_mutex);
}

/* called by platform when FW crashses */
void fuzzer_ipc_crash(struct fuzz *fuzzer, unsigned offset)
{
	/* TODO: DSP FW has crashed. dump stack, regs, last IPC, log etc */
}

/* TODO: this is hardcoded atm, needs to be able to send any message */
int fuzzer_send_msg(struct fuzz *fuzzer)
{
	struct timespec timeout;
	struct timeval tp;
	int ret;

	ipc_dump(fuzzer, &fuzzer->msg);

	/* send msg */
	ret = fuzzer->platform->send_msg(fuzzer, &fuzzer->msg);
	if (ret < 0) {
		fprintf(stderr, "error: message tx failed\n");
	}

	/* wait for ipc reply */
	gettimeofday(&tp, NULL);
	timeout.tv_sec  = tp.tv_sec;
	timeout.tv_nsec = tp.tv_usec * 1000;
	timeout.tv_nsec += 300000000; /* 300ms timeout */

	/* first lock the boot wait mutex */
	pthread_mutex_lock(&ipc_mutex);

	/* now wait for mutex to be unlocked by boot ready message */
	ret = pthread_cond_timedwait(&ipc_cond, &ipc_mutex, &timeout);
	if (ret == ETIMEDOUT) {
		ret = -EINVAL;
		fprintf(stderr, "error: IPC timeout\n");
		ipc_dump_err(fuzzer, &fuzzer->msg);
		pthread_mutex_unlock(&ipc_mutex);
		exit(0);
	}

	pthread_mutex_unlock(&ipc_mutex);

	/*
	 * sleep for 5 ms before continuing sending the next message.
	 * This helps with the condition signaling working better.
	 * Otherwise the condition seems to always satisfy and
	 * the fuzzer never waits for a response from the DSP.
	 */
	usleep(50000);

	return ret;
}

int main(int argc, char *argv[])
{
	struct fuzz fuzzer;
	int ret;
	char opt;
	char *topology_file;
	char *platform_name = NULL;
	int i;
	int regions = 0;

	/* parse arguments */
	while ((opt = getopt(argc, argv, "ht:p:")) != -1) {
		switch (opt) {
		case 't':
			topology_file = optarg;
			break;
		case 'p':
			platform_name = optarg;
			break;
		case 'h':
			usage(argv[0]);
			exit(0);
			break;
		default:
			usage(argv[0]);
			exit(EXIT_FAILURE);
		}
	}

	/* initialise emulated target device */
	if (!platform_name) {
		fprintf(stderr, "error: no target platform specified\n");
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	/* find platform */
	for (i = 0; i < ARRAY_SIZE(platform); i++) {
		if (!strcmp(platform[i]->name, platform_name))
			goto found;
	}

	/* no platform found */
	fprintf(stderr, "error: platform %s not supported\n", platform_name);
	usage(argv[0]);
	exit(EXIT_FAILURE);

found:
	ret = platform[i]->init(&fuzzer, platform[i]);
	if (ret == ETIMEDOUT) {
		fprintf(stderr, "error: platform %s failed to initialise\n",
				platform_name);
		exit(EXIT_FAILURE);
	}

	fprintf(stdout, "FW boot complete\n");

	/* initialize condition */
	pthread_cond_init(&ipc_cond, NULL);

	/* load topology */
	ret = parse_tplg(&fuzzer, "../topology/sof-byt-rt5651.tplg");
	if (ret < 0)
		exit(EXIT_FAILURE);

	pthread_mutex_destroy(&ipc_mutex);
	pthread_cond_destroy(&ipc_cond);

	/* TODO: at this point platform should be initialised and we can send IPC */

	/* TODO enable trace */

	/* TODO load topology to DSP */

	/* TODO fuzz IPC */

	/* all done - now free platform */
	platform[i]->free(&fuzzer);
	return 0;
}
