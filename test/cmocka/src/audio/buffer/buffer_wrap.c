// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright(c) 2018 Intel Corporation. All rights reserved.
//
// Author: Slawomir Blauciak <slawomir.blauciak@linux.intel.com>

#include <sof/audio/component.h>
#include <sof/audio/buffer.h>
#include <sof/ipc.h>

#include <stdio.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <math.h>
#include <stdint.h>
#include <cmocka.h>

static void test_audio_buffer_write_fill_10_bytes_and_write_5(void **state)
{
	(void)state;

	struct sof_ipc_buffer test_buf_desc = {
		.size = 10
	};

	struct comp_buffer *buf = buffer_new(&test_buf_desc);

	assert_non_null(buf);
	assert_int_equal(buf->avail, 0);
	assert_int_equal(buf->free, 10);
	assert_ptr_equal(buf->w_ptr, buf->r_ptr);

	uint8_t bytes[10] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};

	memcpy(buf->w_ptr, &bytes, 10);
	comp_update_buffer_produce(buf, 10);

	assert_int_equal(buf->avail, 10);
	assert_int_equal(buf->free, 0);
	assert_ptr_equal(buf->w_ptr, buf->r_ptr);

	uint8_t more_bytes[5] = {10, 11, 12, 13, 14};

	memcpy(buf->w_ptr, &more_bytes, 5);
	comp_update_buffer_produce(buf, 5);

	uint8_t ref[10] = {10, 11, 12, 13, 14, 5, 6, 7, 8, 9};

	assert_int_equal(buf->avail, 5);
	assert_int_equal(buf->free, 5);
	assert_ptr_equal(buf->w_ptr, buf->r_ptr + 5);
	assert_int_equal(memcmp(buf->r_ptr, &ref, 10), 0);

	buffer_free(buf);
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test
			(test_audio_buffer_write_fill_10_bytes_and_write_5)
	};

	cmocka_set_message_output(CM_OUTPUT_TAP);

	return cmocka_run_group_tests(tests, NULL, NULL);
}
