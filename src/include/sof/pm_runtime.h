/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright(c) 2018 Intel Corporation. All rights reserved.
 *
 * Author: Tomasz Lauda <tomasz.lauda@linux.intel.com>
 */

/**
 * \file include/sof/pm_runtime.h
 * \brief Runtime power management header file
 * \author Tomasz Lauda <tomasz.lauda@linux.intel.com>
 */

#ifndef __INCLUDE_PM_RUNTIME__
#define __INCLUDE_PM_RUNTIME__

#include <sof/lock.h>
#include <sof/trace.h>
#include <sof/wait.h>

/** \addtogroup pm_runtime PM Runtime
 *  PM runtime specification.
 *  @{
 */

/** \brief Power management trace function. */
#define trace_pm(__e, ...) \
	trace_event(TRACE_CLASS_POWER, __e, ##__VA_ARGS__)
#define tracev_pm(__e, ...) \
	tracev_event(TRACE_CLASS_POWER, __e, ##__VA_ARGS__)

/** \brief Power management trace value function. */
#define tracev_pm_value(__e)	tracev_value(__e)

/* PM runtime flags */

#define RPM_ASYNC		0x01	/**< Request is asynchronous */

/** \brief Runtime power management context */
enum pm_runtime_context {
	PM_RUNTIME_HOST_DMA_L1 = 0,	/**< Host DMA L1 Exit */
	SSP_CLK,			/**< SSP Clock */
	DMIC_CLK,			/**< DMIC Clock */
	DMIC_POW,			/**< DMIC Power */
	DW_DMAC_CLK			/**< DW DMAC Clock */
};

/** \brief Runtime power management data. */
struct pm_runtime_data {
	spinlock_t lock;	/**< lock mechanism */
	void *platform_data;	/**< platform specific data */
};

/**
 * \brief Initializes runtime power management.
 */
void pm_runtime_init(void);

/**
 * \brief Retrieves power management resource (async).
 *
 * \param[in] context Type of power management context.
 * \param[in] index Index of the device.
 */
void pm_runtime_get(enum pm_runtime_context context, uint32_t index);

/**
 * \brief Retrieves power management resource.
 *
 * \param[in] context Type of power management context.
 * \param[in] index Index of the device.
 */
void pm_runtime_get_sync(enum pm_runtime_context context, uint32_t index);

/**
 * \brief Releases power management resource (async).
 *
 * \param[in] context Type of power management context.
 * \param[in] index Index of the device.
 */
void pm_runtime_put(enum pm_runtime_context context, uint32_t index);

/**
 * \brief Releases power management resource.
 *
 * \param[in] context Type of power management context.
 * \param[in] index Index of the device.
 */
void pm_runtime_put_sync(enum pm_runtime_context context, uint32_t index);

/** @}*/

#endif /* __INCLUDE_PM_RUNTIME__ */
