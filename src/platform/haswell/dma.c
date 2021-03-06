// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright(c) 2016 Intel Corporation. All rights reserved.
//
// Author: Liam Girdwood <liam.r.girdwood@linux.intel.com>

#include <sof/dma.h>
#include <sof/dw-dma.h>
#include <platform/memory.h>
#include <platform/interrupt.h>
#include <platform/dma.h>
#include <stdint.h>
#include <sof/string.h>

static struct dw_drv_plat_data dmac0 = {
	.chan[0] = {
		.class	= 6,
		.weight = 0,
	},
	.chan[1] = {
		.class	= 6,
		.weight = 0,
	},
	.chan[2] = {
		.class	= 6,
		.weight = 0,
	},
	.chan[3] = {
		.class	= 6,
		.weight = 0,
	},
	.chan[4] = {
		.class	= 6,
		.weight = 0,
	},
	.chan[5] = {
		.class	= 6,
		.weight = 0,
	},
	.chan[6] = {
		.class	= 6,
		.weight = 0,
	},
	.chan[7] = {
		.class	= 6,
		.weight = 0,
	},
};

static struct dw_drv_plat_data dmac1 = {
	.chan[0] = {
		.class	= 7,
		.weight = 0,
	},
	.chan[1] = {
		.class	= 7,
		.weight = 0,
	},
	.chan[2] = {
		.class	= 7,
		.weight = 0,
	},
	.chan[3] = {
		.class	= 7,
		.weight = 0,
	},
	.chan[4] = {
		.class	= 7,
		.weight = 0,
	},
	.chan[5] = {
		.class	= 7,
		.weight = 0,
	},
	.chan[6] = {
		.class	= 7,
		.weight = 0,
	},
	.chan[7] = {
		.class	= 7,
		.weight = 0,
	},
};

struct dma dma[PLATFORM_NUM_DMACS] = {
{
	.plat_data = {
		.id		= DMA_ID_DMAC0,
		.base		= DMA0_BASE,
		.dir		= DMA_DIR_MEM_TO_MEM,
		.caps		= DMA_CAP_GP_HP | DMA_CAP_GP_LP,
		.devs		= DMA_DEV_SSP | DMA_DEV_DMIC | DMA_DEV_HOST,
		.irq		= IRQ_NUM_EXT_DMAC0,
		.drv_plat_data	= &dmac0,
		.channels	= 8,
	},
	.ops		= &dw_dma_ops,
},
{
	.plat_data = {
		.id		= DMA_ID_DMAC1,
		.base		= DMA1_BASE,
		.dir		= DMA_DIR_MEM_TO_MEM | DMA_DIR_MEM_TO_DEV |
				  DMA_DIR_DEV_TO_MEM | DMA_DIR_DEV_TO_DEV |
				  DMA_DIR_HMEM_TO_LMEM | DMA_DIR_LMEM_TO_HMEM,
		.caps		= DMA_CAP_GP_HP | DMA_CAP_GP_LP,
		.devs		= DMA_DEV_SSP | DMA_DEV_DMIC | DMA_DEV_HOST,
		.irq		= IRQ_NUM_EXT_DMAC1,
		.drv_plat_data	= &dmac1,
		.channels	= 8,
	},
	.ops		= &dw_dma_ops,
},};

/* Initialize all platform DMAC's */
int dmac_init(void)
{
	int i;
	/* no probing before first use */

	/* TODO: dynamic init based on platform settings */

	/* early lock initialization for ref counting */
	for (i = 0; i < ARRAY_SIZE(dma); i++)
		spinlock_init(&dma[i].lock);

	/* clear the masks for dsp of the dmacs */
	io_reg_update_bits(SHIM_BASE + SHIM_IMRD,
			   SHIM_IMRD_DMAC0, 0);

	io_reg_update_bits(SHIM_BASE + SHIM_IMRD,
			   SHIM_IMRD_DMAC1, 0);

	/* tell the lib DMAs are ready to use */
	dma_install(dma, ARRAY_SIZE(dma));

	return 0;
}
