#ifndef FUZZ_H
#define FUZZ_H

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <stdarg.h>

#define FUZZ 1

void fuzz(uint8_t *data, uint16_t len);
void byteflip(uint8_t *data, uint16_t len);
void make_as(uint8_t *data, uint16_t len);
void fuzz_print(uint8_t *data, uint16_t len);

void fuzz_debug(uint16_t index, const char *format, ...)
					__attribute__((format(printf, 2, 3)));

#define FUZZ_DBG_IDX(idx, fmt, arg...) do { \
	fuzz_debug(idx, "%s:%s() " fmt, __FILE__, __func__ , ## arg); \
} while (0)

#define FUZZ_DBG(fmt, arg...) FUZZ_DBG_IDX(0xffff, fmt, ## arg)

#endif // FUZZ_H
