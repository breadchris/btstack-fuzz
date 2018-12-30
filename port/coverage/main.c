/*
 * Copyright (C) 2014 BlueKitchen GmbH
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holders nor the names of
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 * 4. Any redistribution, use, or modification is done solely for
 *    personal benefit and not for any commercial purpose or for
 *    monetary gain.
 *
 * THIS SOFTWARE IS PROVIDED BY BLUEKITCHEN GMBH AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL MATTHIAS
 * RINGWALD OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * Please inquire about commercial licensing options at 
 * contact@bluekitchen-gmbh.com
 *
 */

#define __BTSTACK_FILE__ "main.c"

// *****************************************************************************
//
// minimal setup for HCI code
//
// *****************************************************************************

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include "btstack_config.h"

#include "btstack_debug.h"
#include "btstack_event.h"
#include "btstack_link_key_db_fs.h"
#include "btstack_memory.h"
#include "btstack_run_loop.h"
#include "btstack_run_loop_posix.h"
#include "hci.h"
#include "hci_dump.h"
#include "btstack_stdin.h"
#include "btstack_audio.h"
#include "btstack_tlv_posix.h"
#include "hci_transport.h"
#include "vector.h"
#include <pthread.h>
#include <semaphore.h>

#define TLV_DB_PATH_PREFIX "/tmp/btstack_"
#define TLV_DB_PATH_POSTFIX ".tlv"
static char tlv_db_path[100];
static const btstack_tlv_t * tlv_impl;
static btstack_tlv_posix_t   tlv_context;
static bd_addr_t             local_addr;

static int main_argc;
static const char ** main_argv;
static const hci_transport_t * transport;

int btstack_main(int argc, const char * argv[]);

static btstack_packet_callback_registration_t hci_event_callback_registration;

vector *bt_packet_queue = NULL;

static void packet_handler (uint8_t packet_type, uint16_t channel, uint8_t *packet, uint16_t size){
    UNUSED(channel);
    UNUSED(size);
    if (packet_type != HCI_EVENT_PACKET) return;
    switch (hci_event_packet_get_type(packet)){
        case BTSTACK_EVENT_STATE:
            if (btstack_event_state_get_state(packet) != HCI_STATE_WORKING) return;
            gap_local_bd_addr(local_addr);
            printf("BTstack up and running on %s.\n", bd_addr_to_str(local_addr));
            strcpy(tlv_db_path, TLV_DB_PATH_PREFIX);
            strcat(tlv_db_path, bd_addr_to_str(local_addr));
            strcat(tlv_db_path, TLV_DB_PATH_POSTFIX);
            tlv_impl = btstack_tlv_posix_init_instance(&tlv_context, tlv_db_path);
            btstack_tlv_set_instance(tlv_impl, &tlv_context);
            break;
        default:
            break;
    }
}

static void sigint_handler(int param){
    UNUSED(param);

    printf("CTRL-C - SIGINT received, shutting down..\n");   
    log_info("sigint_handler: shutting down");

    // reset anyway
    btstack_stdin_reset();

    // power down
    hci_power_control(HCI_POWER_OFF);
    hci_close();
    log_info("Good bye, see you.\n");    
    exit(0);
}

static int led_state = 0;
void hal_led_toggle(void){
    led_state = 1 - led_state;
    printf("LED State %u\n", led_state);
}

static void intel_firmware_done(int result){

    printf("Done %x\n", result);

    // init HCI
    hci_init(transport, NULL);

#ifdef ENABLE_CLASSIC
    hci_set_link_key_db(btstack_link_key_db_fs_instance());
#endif    

#ifdef HAVE_PORTAUDIO
    btstack_audio_set_instance(btstack_audio_portaudio_get_instance());
#endif

    // inform about BTstack state
    hci_event_callback_registration.callback = &packet_handler;
    hci_add_event_handler(&hci_event_callback_registration);

    // setup app
    btstack_main(main_argc, main_argv);
}

static int cov_open(void){
    return 0;
}

static int cov_close(void){
    return 0;
}

static void dummy_handler(uint8_t packet_type, uint8_t *packet, uint16_t size); 
static void (*cov_packet_handler)(uint8_t packet_type, uint8_t *packet, uint16_t size) = dummy_handler;

static void dummy_handler(uint8_t packet_type, uint8_t *packet, uint16_t size) {
    UNUSED(packet_type);
    UNUSED(packet);
    UNUSED(size);
}

static void cov_register_packet_handler(void (*handler)(uint8_t packet_type, uint8_t *packet, uint16_t size)){
    log_info("registering packet handler");
    cov_packet_handler = handler;
}

static int cov_can_send_packet_now(uint8_t packet_type) {
    return 1;
}

struct bt_packet_t {
    uint8_t packet_type;
    uint8_t *packet;
    int size;
} bt_packet;

pthread_mutex_t bt_packet_queue_mutex = PTHREAD_MUTEX_INITIALIZER;
sem_t bt_packet_queue_sem;

static int cov_send_packet(uint8_t packet_type, uint8_t * packet, int size) {
    // TODO: Queue packet to be read
    struct bt_packet_t *queue_packet = calloc(1, sizeof(struct bt_packet_t));
    queue_packet->packet_type = packet_type;
    queue_packet->packet = calloc(size, sizeof(uint8_t));
    memcpy(queue_packet->packet, packet, size);
    queue_packet->size = size;

    pthread_mutex_lock(&bt_packet_queue_mutex);
    vector_append(bt_packet_queue, queue_packet);
    pthread_mutex_unlock(&bt_packet_queue_mutex);

    sem_post(&bt_packet_queue_sem);

    return 0;
}

static void cov_set_sco_config(uint16_t voice_setting, int num_connections){
}

void *recv_packets();
void *recv_packets() {
    // TODO: While there are packets in the queue
    struct bt_packet_t *queue_packet = NULL;

    while (1) {
        sem_wait(&bt_packet_queue_sem);

        if (vector_count(bt_packet_queue) == 0) {
            printf("wut?");
        }

        pthread_mutex_lock(&bt_packet_queue_mutex);
        vector_delete(bt_packet_queue, 0, (void **)&queue_packet);
        pthread_mutex_unlock(&bt_packet_queue_mutex);

        cov_packet_handler(queue_packet->packet_type, queue_packet->packet, queue_packet->size);

        free(queue_packet->packet);
        free(queue_packet);
    }

    return NULL;
}

// single instance
static hci_transport_t * hci_transport_cov = NULL;

const hci_transport_t * hci_transport_cov_instance(void) {
    if (!hci_transport_cov) {
        hci_transport_cov = (hci_transport_t*) malloc( sizeof(hci_transport_t));
        memset(hci_transport_cov, 0, sizeof(hci_transport_t));
        hci_transport_cov->name                          = "COVERAGE";
        hci_transport_cov->open                          = cov_open;
        hci_transport_cov->close                         = cov_close;
        hci_transport_cov->register_packet_handler       = cov_register_packet_handler;
        hci_transport_cov->can_send_packet_now           = cov_can_send_packet_now;
        hci_transport_cov->send_packet                   = cov_send_packet;
#ifdef ENABLE_SCO_OVER_HCI
        hci_transport_cov->set_sco_config                = cov_set_sco_config;
#endif
    }
    return hci_transport_cov;
}

int main(int argc, const char * argv[]){
    pthread_t bt_packet_queue_thread;

	btstack_memory_init();
    btstack_run_loop_init(btstack_run_loop_posix_get_instance());

    hci_init(hci_transport_cov_instance(), NULL);

    // use logger: format HCI_DUMP_PACKETLOGGER, HCI_DUMP_BLUEZ or HCI_DUMP_STDOUT

    char pklg_path[100];
    strcpy(pklg_path, "/tmp/hci_dump");
    strcat(pklg_path, "coverage.pklg");
    printf("Packet Log: %s\n", pklg_path);
    hci_dump_open(pklg_path, HCI_DUMP_PACKETLOGGER);

    hci_event_callback_registration.callback = &packet_handler;
    hci_add_event_handler(&hci_event_callback_registration);

    vector_alloc(&bt_packet_queue);
    sem_init(&bt_packet_queue_sem, 0, 1); 
    pthread_create(&bt_packet_queue_thread, NULL, recv_packets, NULL);

    // handle CTRL-c
    signal(SIGINT, sigint_handler);

    // go
    btstack_run_loop_execute();    

    return 0;
}
