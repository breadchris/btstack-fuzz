# HCI

## Notable features
* Interfaces with the bluetooth controller - For example, whenever a packet is sent, the controller will tell the stack how many packets were sent via HCI (TODO image)
* Scapy: https://sourcegraph.com/github.com/secdev/scapy/-/blob/scapy/layers/bluetooth.py#L155
* The difference between BR/EDR and LE
* GAP for LE: https://learn.adafruit.com/introduction-to-bluetooth-low-energy/gap
* A common naming convention for packet buffers is `pdu` (protocol data unit https://en.wikipedia.org/wiki/Protocol_data_unit)
* For l2cap, HCI creates `handles` which it passes up after a successful connection

## Attack Surface
* Not a whole lot going on since this layer is just in charge of talking to a controller and passing data along to higher levels
* ECC attack for MiTM (TODO: Link)

## Stack Implementations
Scapy: https://sourcegraph.com/github.com/secdev/scapy/-/blob/scapy/layers/bluetooth.py#L155
Scapy gives a nice overview of how packets are structured, but because of the weirdness of the bluetooth protocol, this information only gets you so far.

If you want to dig into the details of Bluetooth, I recommend looking through Bluekitchen's btstack. Here is BTStack's main hci event handler: https://github.com/bluekitchen/btstack/blob/d966a453850a16585ca5c468190532d5cbf0d844/src/hci.c#L1856. 

HCI is not entirely interesting, it is mainly used for configuring the Bluetooth controller, creating/configuring connections and sending/receiving data to devices (power on, off, start advertising le data, create connection). (TODO: Link to btstack hci_cmd.c)

More information on HCI can be found here: https://bluekitchen-gmbh.com/btstack/protocols/#hci-host-controller-interface

Android:
Bluez:

// TODO: iOS, other stacks

## CVEs
I don't know if there are any?

# L2CAP

## Notable features
* Basically the TCP of Bluetooth
    - Packet retransmission/reassembly - potentially sketchy code (TODO link to different implementations)
    - Both client and server send each other their `mtu`s (max transmission unit) to specify how much data they can send (one of the vulnerabilities in the BlueBourne research used this to trigger a vuln TODO: link)
* Static vs. Dynamic channels
    - There are some pre-defined ranges by the bluetooth standard 
    - The channels are different for br/edr and le connections
    - A protocol is identified by a `psm` (e.g. SDP has psm 1, ATT has psm 7, a really good list can be found in bluez's sdptool sdptool.c:259, when we get to SDP we will look at this more)
    - After connecting to a protocol, the are given a `cid` (channel id) which lets you send acl (data) packets to 
* Signalling Channel
    - The entrypoint for creating and configuring channels with a remote device (btstack l2cap_signalling.c:53)
* classic (br/edr) and low-energy (le) exist in l2cap, their code paths somewhat merge 
    - This can be seen in btstack/src/l2cap.c:3443
*

## Attack Surface
* Channels and their state are created and stored within the stack, abusing the state machine could lead to use-after-frees

TODO: Go through each bluetooth stack and show what channels are registered (point out the weird iOS stuff)

## Stack Comparisions

## CVEs
* CVE-2017-0781 (Allocate buffers of the right size when BT_HDR is included): https://android.googlesource.com/platform/system/bt/+/c513a8ff5cfdcc62cc14da354beb1dd22e56be0e

* Signalling channel information disclosures
    - There is a common pattern through out the Android code base of packet lengths not being written
* LE RCE
* That thing Joel sent
* Tesla Keen Team report

## Interactive Example
Let's run through an example POC 
