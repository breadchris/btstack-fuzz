#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include "vec.h"

void radamsa_fuzz(uint8_t *input, size_t len);
ssize_t radamsa_read(int val, uint8_t *buff, size_t buff_size);
ssize_t radamsa_write(int val, uint8_t *buff, size_t buff_size);
void *radamsa_malloc(size_t size);
void find_and_remove_alloc(void *ptr);
void radamsa_free(void *ptr);
void *radamsa_realloc(void *ptr, size_t size);
