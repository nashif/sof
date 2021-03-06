/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright 2019 NXP
 *
 * Author: Daniel Baluta <daniel.baluta@nxp.com>
 */

#ifndef __INCLUDE_PLATFORM_MAILBOX__
#define __INCLUDE_PLATFORM_MAILBOX__

#include <platform/memory.h>

/*
 * The Window Region on i.MX8 SRAM is organised like this :-
 * +--------------------------------------------------------------------------+
 * | Offset              | Region         |  Size                             |
 * +---------------------+----------------+-----------------------------------+
 * | SRAM_TRACE_BASE     | Trace Buffer   |  SRAM_TRACE_SIZE                  |
 * +---------------------+----------------+-----------------------------------+
 * | SRAM_DEBUG_BASE     | Debug data     |  SRAM_DEBUG_SIZE                  |
 * +---------------------+----------------+-----------------------------------+
 * | SRAM_INBOX_BASE     | Inbox          |  SRAM_INBOX_SIZE                  |
 * +---------------------+----------------+-----------------------------------+
 * | SRAM_OUTBOX_BASE    | Outbox         |  SRAM_MAILBOX_SIZE                |
 * +---------------------+----------------+-----------------------------------+
 */

#define MAILBOX_DSPBOX_SIZE		SRAM_OUTBOX_SIZE
#define MAILBOX_DSPBOX_BASE		SRAM_OUTBOX_BASE
#define MAILBOX_DSPBOX_OFFSET		SRAM_OUTBOX_OFFSET

#define MAILBOX_HOSTBOX_SIZE		SRAM_INBOX_SIZE
#define MAILBOX_HOSTBOX_BASE		SRAM_INBOX_BASE
#define MAILBOX_HOSTBOX_OFFSET		SRAM_INBOX_OFFSET

#define MAILBOX_DEBUG_SIZE		SRAM_DEBUG_SIZE
#define MAILBOX_DEBUG_BASE		SRAM_DEBUG_BASE
#define MAILBOX_DEBUG_OFFSET		SRAM_DEBUG_OFFSET

#define MAILBOX_TRACE_SIZE		SRAM_TRACE_SIZE
#define MAILBOX_TRACE_BASE		SRAM_TRACE_BASE
#define MAILBOX_TRACE_OFFSET		SRAM_TRACE_OFFSET

#define MAILBOX_EXCEPTION_SIZE		SRAM_EXCEPT_SIZE
#define MAILBOX_EXCEPTION_BASE		SRAM_EXCEPT_BASE
#define MAILBOX_EXCEPTION_OFFSET	SRAM_DEBUG_SIZE

#define MAILBOX_STREAM_SIZE		SRAM_STREAM_SIZE
#define MAILBOX_STREAM_BASE		SRAM_STREAM_BASE
#define MAILBOX_STREAM_OFFSET		SRAM_STREAM_OFFSET

#endif
