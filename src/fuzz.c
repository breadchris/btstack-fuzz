#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include "fuzz.h"
/**
 Fuzzing layers:
 bnep, sdp
 l2cap
 hci

 * watch out for channel ids when fuzzing
 */

#define HCI_FUZZ 0
#define L2CAP_FUZZ 1
#define GATT_FUZZ 2
#define SMP_FUZZ 3
#define SDP_FUZZ 4
#define BNEP_FUZZ 5
#define MAX_FUZZ 7

uint8_t fuzz_config[MAX_FUZZ] = {0};

int special_bytes[] = { 0x7f, 0xff, 0x00, 0x41 };
int special_words[] = { 0x7fff, 0x8000, 0xffff, 0x4141 };

void fuzz_debug(uint16_t index, const char *format, ...)
{
  va_list ap;

  va_start(ap, format);
  syslog(LOG_DEBUG, format, ap);
  va_end(ap);
}

void fuzz(uint8_t *data, uint16_t len) {
  byteflip(data, len);
}

void byteflip(uint8_t *data, uint16_t len) {
  if (rand() % 100 < 30) {
    uint8_t rand_byte = special_bytes[rand() % (sizeof(special_bytes) / sizeof(uint8_t))];
    data[rand() % len] = rand_byte ;
  }
}

void make_as(uint8_t *data, uint16_t len) {
  memset(data, 0x41, len);
}

static int verbose_flag;

int fuzz_parse_args (int argc, char **argv) {
  int c;

  while (1) {
    static struct option long_options[] = {
        {"verbose", no_argument,       &verbose_flag, 1},
        {"brief",   no_argument,       &verbose_flag, 0},
        {"fuzz-level",     required_argument,       0, 'l'},
        {"fuzz-type",    no_argument, 0, 't'},
        {0, 0, 0, 0}
      };
    /* getopt_long stores the option index here. */
    int option_index = 0;

    c = getopt_long (argc, argv, "l:t",
                     long_options, &option_index);

    /* Detect the end of the options. */
    if (c == -1)
      break;

    switch (c) {
      case 0:
        /* If this option set a flag, do nothing else now. */
        if (long_options[option_index].flag != 0)
          break;
        printf ("option %s", long_options[option_index].name);
        if (optarg)
          printf (" with arg %s", optarg);
        printf ("\n");
        break;

      case 'l':
        if (strcmp(optarg, "hci") == 0) {
          fuzz_config[HCI_FUZZ] = 1;
        } else if (strcmp(optarg, "l2cap") == 0) {
          fuzz_config[L2CAP_FUZZ] = 1;
        }
        break;

      case '?':
        /* getopt_long already printed an error message. */
        break;

      default:
        abort ();
      }
  }

  if (verbose_flag) {
    puts ("verbose flag is set");
  }

  /* Print any remaining command line arguments (not options). */
  if (optind < argc) {
    printf ("non-option ARGV-elements: ");
    while (optind < argc)
      printf ("%s ", argv[optind++]);
    putchar ('\n');
  }
  return 0;
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
