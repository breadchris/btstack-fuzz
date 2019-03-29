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

#define __BTSTACK_FILE__ "gap_le_advertisements.c"
 

// *****************************************************************************
/* EXAMPLE_START(gap_le_advertisements): GAP LE Advertisements Dumper
 *
 * @text This example shows how to scan and parse advertisements.
 * 
 */
 // *****************************************************************************


#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "btstack.h"

bd_addr_t remote_addr;

static btstack_packet_callback_registration_t hci_event_callback_registration;

/* @section GAP LE setup for receiving advertisements
 *
 * @text GAP LE advertisements are received as custom HCI events of the 
 * GAP_EVENT_ADVERTISING_REPORT type. To receive them, you'll need to register
 * the HCI packet handler, as shown in Listing GAPLEAdvSetup.
 */

/* LISTING_START(GAPLEAdvSetup): Setting up GAP LE client for receiving advertisements */
static void packet_handler(uint8_t packet_type, uint16_t channel, uint8_t *packet, uint16_t size);

static void gap_le_advertisements_setup(void){
    // Active scanning, 100% (scan interval = scan window)
    gap_set_scan_parameters(1,48,48);
    gap_start_scan(); 

    hci_event_callback_registration.callback = &packet_handler;
    hci_add_event_handler(&hci_event_callback_registration);
}

/* @text BTstack offers an iterator for parsing sequence of advertising data (AD) structures, 
 * see [BLE advertisements parser API](../appendix/apis/#ble-advertisements-parser-api).
 * After initializing the iterator, each AD structure is dumped according to its type.
 */

/* LISTING_START(GAPLEAdvDataParsing): Parsing advertising data */
static char *dump_advertisement_data(const uint8_t * adv_data, uint8_t adv_size){
    ad_context_t context;
    for (ad_iterator_init(&context, adv_size, (uint8_t *)adv_data) ; ad_iterator_has_more(&context) ; ad_iterator_next(&context)){
        uint8_t data_type    = ad_iterator_get_data_type(&context);
        uint8_t size         = ad_iterator_get_data_len(&context);
        const uint8_t * data = ad_iterator_get_data(&context);


        if (data_type == BLUETOOTH_DATA_TYPE_SHORTENED_LOCAL_NAME || data_type == BLUETOOTH_DATA_TYPE_COMPLETE_LOCAL_NAME){
            char *data_str = calloc(1, size + 1);
            memcpy(data_str, data, size + 1);

            return data_str;
        }        
    }
    return NULL;
}
/* LISTING_END */

/* @section HCI packet handler
 * 
 * @text The HCI packet handler has to start the scanning, 
 * and to handle received advertisements. Advertisements are received 
 * as HCI event packets of the GAP_EVENT_ADVERTISING_REPORT type,
 * see Listing GAPLEAdvPacketHandler.  
 */

/* LISTING_START(GAPLEAdvPacketHandler): Scanning and receiving advertisements */

static void packet_handler(uint8_t packet_type, uint16_t channel, uint8_t *packet, uint16_t size){
    UNUSED(channel);
    UNUSED(size);

    if (packet_type != HCI_EVENT_PACKET) return;
    
    switch (hci_event_packet_get_type(packet)) {
        case GAP_EVENT_ADVERTISING_REPORT:{
            bd_addr_t address;
            gap_event_advertising_report_get_address(packet, address);
            uint8_t address_type = gap_event_advertising_report_get_address_type(packet);
            int8_t rssi = gap_event_advertising_report_get_rssi(packet);
            uint8_t length = gap_event_advertising_report_get_data_length(packet);
            const uint8_t * data = gap_event_advertising_report_get_data(packet);
            
            char *name = dump_advertisement_data(data, length);
            if (name != NULL) {
                printf("Found: addr-type %u, addr %s, rssi %d, name %s\n",
                   address_type, bd_addr_to_str(address), rssi, name);
            }
            free(name);
            break;
        }
        default:
            break;
    }
}
/* LISTING_END */

#ifdef HAVE_BTSTACK_STDIN
static void usage(const char *name){
    fprintf(stderr, "\nUsage: %s [-s|--search <name to search for>]\n", name);
}
#endif

int btstack_main(int argc, const char * argv[], bd_addr_t addr);
int btstack_main(int argc, const char * argv[], bd_addr_t addr){

#ifdef HAVE_BTSTACK_STDIN
    int arg = 1;
    
#else
    (void)argc;
    (void)argv;
#endif

    gap_le_advertisements_setup();

    // turn on!
    hci_power_control(HCI_POWER_ON);
        
    return 0;
}

/* EXAMPLE_END */
