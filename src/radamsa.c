#include "radamsa.h"

static struct X {
  uint8_t *input;
  size_t input_len;
  uint8_t *output;
  size_t output_len;

  // Where are we in the process of reading `input`?
  size_t input_index;

  // Set of objects that remain unfreed by Radamsa.
  void** allocations;

} g_radamsa;

// Radamsa's `main` function.
void *radamsa_boot(int argc, const char *argv[]);

// Pretend to do a `read` system call from within Radamsa.
ssize_t radamsa_read(int val, uint8_t *buff, size_t buff_size) {
  size_t input_offset = g_radamsa.input_len - g_radamsa.input_index;
  size_t count = buff_size < input_offset ? buff_size : input_offset;

  memcpy(buff, g_radamsa.input + g_radamsa.input_index, count);
  g_radamsa.input_index += count;
  return (ssize_t)count;
}

// Pretend to do a `write` system call from within Radamsa.
ssize_t radamsa_write(int val, uint8_t *buff, size_t buff_size) {
  g_radamsa.output = realloc(g_radamsa.output, g_radamsa.output_len + buff_size);
  if (!g_radamsa.output) {
    return -1;
  }

  memcpy(g_radamsa.output + g_radamsa.output_len, buff, buff_size);
  g_radamsa.output_len += buff_size;
  return buff_size;
}

// Interposes on `malloc`s performed by Radamsa.
void *radamsa_malloc(size_t size) {
  void *ptr = malloc(size);
  vec_push(g_radamsa.allocations, ptr);
  return ptr;
}

void find_and_remove_alloc(void *ptr) {
  for (size_t i = 0; i < vec_len(g_radamsa.allocations); i++) {
    if (g_radamsa.allocations[i] == ptr) {
      vec_remove(g_radamsa.allocations, i);
      free(ptr);
    }
  }
}

// Interposes on `free`s performed by Radamsa.
void radamsa_free(void *ptr) {
  find_and_remove_alloc(ptr);
}

// Interposes on `realloc`s performed by Radamsa. The OWL scheme compiler uses
// `realloc` for heap allocation.
void *radamsa_realloc(void *ptr, size_t size) {
  find_and_remove_alloc(ptr);
  ptr = realloc(ptr, size);
  vec_push(g_radamsa.allocations, ptr);
  return ptr;
}

uint32_t g_radamsaSeed = 1337;

void radamsa_fuzz(uint8_t *input, size_t len) {
  g_radamsa.input = input;
  g_radamsa.input_index = 0;
  g_radamsa.output = malloc(len);
  if (!g_radamsa.output) {
    return;
  }
  g_radamsa.allocations = vec_new(20);

  char formatted_seed[64] = {0};
  snprintf(formatted_seed, sizeof(formatted_seed), "%zu", g_radamsaSeed);

  const char *args[] = {
    "radamsa",
    "--seed",
    formatted_seed,
    "--mutations",
    "ab,bd,bf,bi,br,bp,bei,bed,ber,sr,sd,ui,ft,fn,fo",
    NULL 
  };
  // I am not sure if this is even valid, due to the Radamsa heap being a
  // static char array.
  radamsa_boot(6, args);

  for (size_t i = 0; i < vec_len(g_radamsa.allocations); i++) {
    free(g_radamsa.allocations[i]);
  }

  g_radamsa.input = NULL;
  vec_free(g_radamsa.allocations);

  // TODO: Have a way to include length changes too
  memcpy(input, g_radamsa.output, len);
}
