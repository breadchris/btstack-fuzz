
#include "fuzz.h"
/**
 Fuzzing layers:
 bnep, sdp
 l2cap
 hci

 * watch out for channel ids when fuzzing

 */

int special_bytes[] = { 0x7f, 0xff, 0x00, 0x41 };
int special_words[] = { 0x7fff, 0x8000, 0xffff, 0x4141 };

void fuzz_debug(uint16_t index, const char *format, ...)
{
  va_list ap;

  va_start(ap, format);
  vsyslog(LOG_DEBUG, format, ap);
  va_end(ap);
}

/**
 * TODO: Implement more ways to fuzz here
 */
void fuzz(uint8_t *data, uint16_t len) {
#ifdef FUZZ
  //fuzz_print(data, len);
  byteflip(data, len);
  //make_as(data, *len);
#endif
}

void byteflip(uint8_t *data, uint16_t len) {
  uint8_t rand_byte = rand() % 255;

  data[rand() % len] ^= rand_byte ;
}

void make_as(uint8_t *data, uint16_t len) {
  memset(data, 0x41, len);
}

// void fuzz_print(uint8_t *data, uint16_t len) {
//   size_t i;
//   char *data_str;

//   data_str = (char *)malloc((len * 3) + 1);

//   for (i = 0; i < len; i++) {
//     snprintf(data_str + (i * 3), 3, "%02x ", data[i]);
//   }
//   data_str[len * 3] = '\0';

//   FUZZ_DBG("[fuzz] Fuzzing data: %08lx [%s]", (size_t)len, data_str);

//   free(data_str);
// }
