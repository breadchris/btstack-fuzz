/**
 * SDP scan and connect to l2cap channels
 */

#define __BTSTACK_FILE__ "sdp_general_query.c"

#include "btstack_config.h"

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
    printf("Packet type: %d\n", packet_type);
}

/*
Common CIDs:
    2: L2CAP Signalling

Android:

Mac:

iOS:
    PipeDreams
    LEAP

Layers:
l2cap:
    things to fuzz: 
        l2cap retransmission

    methods to call:
        l2cap_create_signaling_classic with L2CAP_SIGNALING_COMMANDS
sdp:
    things to fuzz:
        sdp continuation
    methods to call:
        sdp_client_query_uuid16
        sdp_client_query_uuid128
        sdp_client_service_attribute_search
        sdp_client_service_search

bnep --> pan
    things to fuzz:
        extension bit
    methods to call:
        bnep_send(bnep_cid, (uint8_t*) network_buffer, network_buffer_len);
        btstack_network_packet_sent();
avdtp --> a2dp
avctp --> avrcp
gatt/att
    things to fuzz:
        osx will query the target device, can return some bogus data
        mike ryan had that thing in his pre
    methods to call:
        query shit
        response shit
smp
rfcomm

also interesting to think about the attack scenario when a device gets data from us (e.g. sdp query, gatt browse, etc.)
*/

void do_l2cap_connect() {
    uint8_t status = l2cap_create_channel(l2cap_packet_handler, remote, 3, l2cap_max_mtu(), NULL);
    printf("Status: %d", status);

    uint16_t pos = 0;
    l2cap_reserve_packet_buffer();
    uint8_t *buffer = l2cap_get_outgoing_buffer();

    buffer[pos++] = '\xff';
    buffer[pos++] = '\xff';
    buffer[pos++] = '\xff';
    buffer[pos++] = '\xff';
    int err = l2cap_send_prepared(2, pos);
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
                sdp_client_query_uuid16(&handle_sdp_client_query_result, remote, BLUETOOTH_ATTRIBUTE_PUBLIC_BROWSE_ROOT);
                /*
                For fuzzing we have:
                sdp_client_query_uuid16
                sdp_client_query_uuid128
                sdp_client_service_attribute_search
                sdp_client_service_search
                */
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

/* Definition of attribute members */
struct member_def {
    char *name;
};
/* Definition of an attribute */
struct attrib_def {
    int         num;        /* Numeric ID - 16 bits */
    char            *name;      /* User readable name */
    struct member_def   *members;   /* Definition of attribute args */
    int         member_max; /* Max of attribute arg definitions */
};
/* Definition of a service or protocol */
struct uuid_def {
    int         num;        /* Numeric ID - 16 bits */
    char            *name;      /* User readable name */
    struct attrib_def   *attribs;   /* Specific attribute definitions */
    int         attrib_max; /* Max of attribute definitions */
};
/* Context information about current attribute */
struct attrib_context {
    struct uuid_def     *service;   /* Service UUID, if known */
    struct attrib_def   *attrib;    /* Description of the attribute */
    int         member_index;   /* Index of current attribute member */
};
/* Context information about the whole service */
struct service_context {
    struct uuid_def     *service;   /* Service UUID, if known */
};
/* Allow us to do nice formatting of the lists */
static char *indent_spaces = "                                         ";
/* ID of the service attribute.
 * Most attributes after 0x200 are defined based on the service, so
 * we need to find what is the service (which is messy) - Jean II */
#define SERVICE_ATTR    0x1
/* Definition of the optional arguments in protocol list */
static struct member_def protocol_members[] = {
    { "Protocol"        },
    { "Channel/Port"    },
    { "Version"     },
};
/* Definition of the optional arguments in profile list */
static struct member_def profile_members[] = {
    { "Profile" },
    { "Version" },
};
/* Definition of the optional arguments in Language list */
static struct member_def language_members[] = {
    { "Code ISO639"     },
    { "Encoding"        },
    { "Base Offset"     },
};


// Name of the various common attributes. See BT assigned numbers
static struct attrib_def attrib_names[] = {
    { 0x0, "ServiceRecordHandle", NULL, 0 },
    { 0x1, "ServiceClassIDList", NULL, 0 },
    { 0x2, "ServiceRecordState", NULL, 0 },
    { 0x3, "ServiceID", NULL, 0 },
    { 0x4, "ProtocolDescriptorList",
        protocol_members, sizeof(protocol_members)/sizeof(struct member_def) },
    { 0x5, "BrowseGroupList", NULL, 0 },
    { 0x6, "LanguageBaseAttributeIDList",
        language_members, sizeof(language_members)/sizeof(struct member_def) },
    { 0x7, "ServiceInfoTimeToLive", NULL, 0 },
    { 0x8, "ServiceAvailability", NULL, 0 },
    { 0x9, "BluetoothProfileDescriptorList",
        profile_members, sizeof(profile_members)/sizeof(struct member_def) },
    { 0xA, "DocumentationURL", NULL, 0 },
    { 0xB, "ClientExecutableURL", NULL, 0 },
    { 0xC, "IconURL", NULL, 0 },
    { 0xD, "AdditionalProtocolDescriptorLists", NULL, 0 },
    // Definitions after that are tricky (per profile or offset)
};
const int attrib_max = sizeof(attrib_names)/sizeof(struct attrib_def);
// Name of the various SPD attributes. See BT assigned numbers
static struct attrib_def sdp_attrib_names[] = {
    { 0x200, "VersionNumberList", NULL, 0 },
    { 0x201, "ServiceDatabaseState", NULL, 0 },
};
// Name of the various SPD attributes. See BT assigned numbers
static struct attrib_def browse_attrib_names[] = {
    { 0x200, "GroupID", NULL, 0 },
};
// Name of the various Device ID attributes. See Device Id spec.
static struct attrib_def did_attrib_names[] = {
    { 0x200, "SpecificationID", NULL, 0 },
    { 0x201, "VendorID", NULL, 0 },
    { 0x202, "ProductID", NULL, 0 },
    { 0x203, "Version", NULL, 0 },
    { 0x204, "PrimaryRecord", NULL, 0 },
    { 0x205, "VendorIDSource", NULL, 0 },
};
// Name of the various HID attributes. See HID spec.
static struct attrib_def hid_attrib_names[] = {
    { 0x200, "DeviceReleaseNum", NULL, 0 },
    { 0x201, "ParserVersion", NULL, 0 },
    { 0x202, "DeviceSubclass", NULL, 0 },
    { 0x203, "CountryCode", NULL, 0 },
    { 0x204, "VirtualCable", NULL, 0 },
    { 0x205, "ReconnectInitiate", NULL, 0 },
    { 0x206, "DescriptorList", NULL, 0 },
    { 0x207, "LangIDBaseList", NULL, 0 },
    { 0x208, "SDPDisable", NULL, 0 },
    { 0x209, "BatteryPower", NULL, 0 },
    { 0x20a, "RemoteWakeup", NULL, 0 },
    { 0x20b, "ProfileVersion", NULL, 0 },
    { 0x20c, "SupervisionTimeout", NULL, 0 },
    { 0x20d, "NormallyConnectable", NULL, 0 },
    { 0x20e, "BootDevice", NULL, 0 },
};
// Name of the various PAN attributes. See BT assigned numbers 
// Note : those need to be double checked - Jean II 
static struct attrib_def pan_attrib_names[] = {
    { 0x200, "IpSubnet", NULL, 0 },     // Obsolete ???
    { 0x30A, "SecurityDescription", NULL, 0 },
    { 0x30B, "NetAccessType", NULL, 0 },
    { 0x30C, "MaxNetAccessrate", NULL, 0 },
    { 0x30D, "IPv4Subnet", NULL, 0 },
    { 0x30E, "IPv6Subnet", NULL, 0 },
};
// Name of the various Generic-Audio attributes. See BT assigned numbers 
// Note : totally untested - Jean II 
static struct attrib_def audio_attrib_names[] = {
    { 0x302, "Remote audio volume control", NULL, 0 },
};
// Same for the UUIDs. See BT assigned numbers
static struct uuid_def uuid16_names[] = {
    // -- Protocols -- 
    { 0x0001, "SDP", NULL, 0 },
    { 0x0002, "UDP", NULL, 0 },
    { 0x0003, "RFCOMM", NULL, 0 },
    { 0x0004, "TCP", NULL, 0 },
    { 0x0005, "TCS-BIN", NULL, 0 },
    { 0x0006, "TCS-AT", NULL, 0 },
    { 0x0008, "OBEX", NULL, 0 },
    { 0x0009, "IP", NULL, 0 },
    { 0x000a, "FTP", NULL, 0 },
    { 0x000c, "HTTP", NULL, 0 },
    { 0x000e, "WSP", NULL, 0 },
    { 0x000f, "BNEP", NULL, 0 },
    { 0x0010, "UPnP/ESDP", NULL, 0 },
    { 0x0011, "HIDP", NULL, 0 },
    { 0x0012, "HardcopyControlChannel", NULL, 0 },
    { 0x0014, "HardcopyDataChannel", NULL, 0 },
    { 0x0016, "HardcopyNotification", NULL, 0 },
    { 0x0017, "AVCTP", NULL, 0 },
    { 0x0019, "AVDTP", NULL, 0 },
    { 0x001b, "CMTP", NULL, 0 },
    { 0x001d, "UDI_C-Plane", NULL, 0 },
    { 0x0100, "L2CAP", NULL, 0 },
    // -- Services -- 
    { 0x1000, "ServiceDiscoveryServerServiceClassID",
        sdp_attrib_names, sizeof(sdp_attrib_names)/sizeof(struct attrib_def) },
    { 0x1001, "BrowseGroupDescriptorServiceClassID",
        browse_attrib_names, sizeof(browse_attrib_names)/sizeof(struct attrib_def) },
    { 0x1002, "PublicBrowseGroup", NULL, 0 },
    { 0x1101, "SerialPort", NULL, 0 },
    { 0x1102, "LANAccessUsingPPP", NULL, 0 },
    { 0x1103, "DialupNetworking (DUN)", NULL, 0 },
    { 0x1104, "IrMCSync", NULL, 0 },
    { 0x1105, "OBEXObjectPush", NULL, 0 },
    { 0x1106, "OBEXFileTransfer", NULL, 0 },
    { 0x1107, "IrMCSyncCommand", NULL, 0 },
    { 0x1108, "Headset",
        audio_attrib_names, sizeof(audio_attrib_names)/sizeof(struct attrib_def) },
    { 0x1109, "CordlessTelephony", NULL, 0 },
    { 0x110a, "AudioSource", NULL, 0 },
    { 0x110b, "AudioSink", NULL, 0 },
    { 0x110c, "RemoteControlTarget", NULL, 0 },
    { 0x110d, "AdvancedAudio", NULL, 0 },
    { 0x110e, "RemoteControl", NULL, 0 },
    { 0x110f, "VideoConferencing", NULL, 0 },
    { 0x1110, "Intercom", NULL, 0 },
    { 0x1111, "Fax", NULL, 0 },
    { 0x1112, "HeadsetAudioGateway", NULL, 0 },
    { 0x1113, "WAP", NULL, 0 },
    { 0x1114, "WAP Client", NULL, 0 },
    { 0x1115, "PANU (PAN/BNEP)",
        pan_attrib_names, sizeof(pan_attrib_names)/sizeof(struct attrib_def) },
    { 0x1116, "NAP (PAN/BNEP)",
        pan_attrib_names, sizeof(pan_attrib_names)/sizeof(struct attrib_def) },
    { 0x1117, "GN (PAN/BNEP)",
        pan_attrib_names, sizeof(pan_attrib_names)/sizeof(struct attrib_def) },
    { 0x1118, "DirectPrinting (BPP)", NULL, 0 },
    { 0x1119, "ReferencePrinting (BPP)", NULL, 0 },
    { 0x111a, "Imaging (BIP)", NULL, 0 },
    { 0x111b, "ImagingResponder (BIP)", NULL, 0 },
    { 0x111c, "ImagingAutomaticArchive (BIP)", NULL, 0 },
    { 0x111d, "ImagingReferencedObjects (BIP)", NULL, 0 },
    { 0x111e, "Handsfree", NULL, 0 },
    { 0x111f, "HandsfreeAudioGateway", NULL, 0 },
    { 0x1120, "DirectPrintingReferenceObjectsService (BPP)", NULL, 0 },
    { 0x1121, "ReflectedUI (BPP)", NULL, 0 },
    { 0x1122, "BasicPrinting (BPP)", NULL, 0 },
    { 0x1123, "PrintingStatus (BPP)", NULL, 0 },
    { 0x1124, "HumanInterfaceDeviceService (HID)",
        hid_attrib_names, sizeof(hid_attrib_names)/sizeof(struct attrib_def) },
    { 0x1125, "HardcopyCableReplacement (HCR)", NULL, 0 },
    { 0x1126, "HCR_Print (HCR)", NULL, 0 },
    { 0x1127, "HCR_Scan (HCR)", NULL, 0 },
    { 0x1128, "Common ISDN Access (CIP)", NULL, 0 },
    { 0x1129, "VideoConferencingGW (VCP)", NULL, 0 },
    { 0x112a, "UDI-MT", NULL, 0 },
    { 0x112b, "UDI-TA", NULL, 0 },
    { 0x112c, "Audio/Video", NULL, 0 },
    { 0x112d, "SIM Access (SAP)", NULL, 0 },
    { 0x112e, "Phonebook Access (PBAP) - PCE", NULL, 0 },
    { 0x112f, "Phonebook Access (PBAP) - PSE", NULL, 0 },
    { 0x1130, "Phonebook Access (PBAP)", NULL, 0 },
    // ... 
    { 0x1200, "PnPInformation",
        did_attrib_names, sizeof(did_attrib_names)/sizeof(struct attrib_def) },
    { 0x1201, "GenericNetworking", NULL, 0 },
    { 0x1202, "GenericFileTransfer", NULL, 0 },
    { 0x1203, "GenericAudio",
        audio_attrib_names, sizeof(audio_attrib_names)/sizeof(struct attrib_def) },
    { 0x1204, "GenericTelephony", NULL, 0 },
    // ... 
    { 0x1303, "VideoSource", NULL, 0 },
    { 0x1304, "VideoSink", NULL, 0 },
    { 0x1305, "VideoDistribution", NULL, 0 },
    { 0x1400, "MDP", NULL, 0 },
    { 0x1401, "MDPSource", NULL, 0 },
    { 0x1402, "MDPSink", NULL, 0 },
    { 0x2112, "AppleAgent", NULL, 0 },
};

static void de_traverse_sequence(uint8_t * element, de_traversal_callback_t handler, void *context){
    de_type_t type = de_get_element_type(element);
    if (type != DE_DES) return;
    int pos = de_get_header_size(element);
    int end_pos = de_get_len(element);
    while (pos < end_pos){
        de_type_t elemType = de_get_element_type(element + pos);
        de_size_t elemSize = de_get_size_type(element + pos);
        uint8_t done = (*handler)(element + pos, elemType, elemSize, context); 
        if (done) break;
        pos += de_get_len(element + pos);
    }
}

static int sdp_traverse_response(uint8_t * element, de_type_t de_type, de_size_t de_size, void *my_context){
    int indent = *(int*) my_context;
    int i;
    for (i=0; i<indent;i++) printf("    ");
    unsigned int pos     = de_get_header_size(element);
    unsigned int end_pos = de_get_len(element);
    printf("type %5s (%u), element len %2u ", attrib_names[de_type].name, de_type, end_pos);

    if (de_type == DE_DES) {
        printf("\n");
        indent++;
        de_traverse_sequence(element, sdp_traverse_response, (void *)&indent);
    } else if (de_type == DE_UUID && de_size == DE_SIZE_128) {
        printf(", value: %s\n", uuid128_to_str(element+1));
    } else if (de_type == DE_STRING) {
        unsigned int len = 0;
        switch (de_size){
            case DE_SIZE_VAR_8:
                len = element[1];
                break;
            case DE_SIZE_VAR_16:
                len = big_endian_read_16(element, 1);
                break;
            default:
                break;
        }
        printf("len %u (0x%02x)\n", len, len);

        // TODO: Check for errors
        char *str = (char *)calloc(1, len + 1);
        strncpy(str, &element[pos], len);
        printf("%s\n", str);
        free(str);
    } else {
        uint32_t value = 0;
        switch (de_size) {
            case DE_SIZE_8:
                if (de_type != DE_NIL){
                    value = element[pos];
                }
                break;
            case DE_SIZE_16:
                value = big_endian_read_16(element,pos);
                break;
            case DE_SIZE_32:
                value = big_endian_read_32(element,pos);
                break;
            default:
                break;
        }
        if (de_type == DE_UUID) {
            const char *uuid_name = NULL;
            for (size_t i = 0; i < sizeof(uuid16_names) / sizeof(struct uuid_def); i++) {
                if (uuid16_names[i].num == value) uuid_name = uuid16_names[i].name;
            }
            printf(", value: %s\n", uuid_name);
        } else {
            printf(", value: 0x%08x\n", value);
        }
    }
    return 0;
}

static void print_sdp_results(const uint8_t * record);
static void print_sdp_results(const uint8_t * record){
    int indent = 0;
    // hack to get root DES, too.
    de_type_t type = de_get_element_type(record);
    de_size_t size = de_get_size_type(record);
    sdp_traverse_response((uint8_t *) record, type, size, (void*) &indent);
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
               print_sdp_results(attribute_value);
            }
            break;
        case SDP_EVENT_QUERY_COMPLETE:
            if (sdp_event_query_complete_get_status(packet)){
                printf("SDP query failed 0x%02x\n", sdp_event_query_complete_get_status(packet));
                break;
            } 
            printf("SDP query done.\n");
            break;
    }
}

int btstack_main(int argc, const char * argv[]);
int btstack_main(int argc, const char * argv[]){
    (void)argc;
    (void)argv;

/*
    if (argc != 2) {
        printf("%d <bd addr>\n", argc);
        exit(-1);
    }
    */

    //if (!sscanf_bd_addr("98:01:A7:9D:C1:94", remote)) {
    //if (!sscanf_bd_addr("78:D7:5F:09:6E:3D", remote)) {
    //if (!sscanf_bd_addr("38:CA:DA:85:5F:E1", remote)) {
    if (!sscanf_bd_addr("18:56:80:04:42:72", remote)) {
        printf("%s <bd addr>\n", argv[0]);
        exit(-1);
    }
    
    printf("Client HCI init done\r\n");
    
    sdp_client_init();

    // turn on!
    hci_power_control(HCI_POWER_ON);
            
    return 0;
}
