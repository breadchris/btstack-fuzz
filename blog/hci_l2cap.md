# HCI

## Notable features
* Interfaces with the bluetooth controller - For example, whenever a packet is sent, the controller will tell the stack how many packets were sent via HCI (TODO image)
* Scapy: https://sourcegraph.com/github.com/secdev/scapy/-/blob/scapy/layers/bluetooth.py#L155
* The difference between BR/EDR and LE
* GAP for LE: https://learn.adafruit.com/introduction-to-bluetooth-low-energy/gap
* A common naming convention for packet buffers is `pdu` (protocol data unit https://en.wikipedia.org/wiki/Protocol_data_unit)
* For l2cap, HCI creates `handles` which it passes up after a successful connection
* Link Manager Protocol (LMP) is also worth mentioning here as it "The Link Manager carries out link setup, authentication, link configuration and other protocols. It discovers other remote LM’s and communicates with them via the Link Manager Protocol (LMP)." (https://www.amd.e-technik.uni-rostock.de/ma/gol/lectures/wirlec/bluetooth_info/lmp.html)
* GAP https://bluekitchen-gmbh.com/btstack/profiles/#gap-generic-access-profile-classic
* GAP LE https://bluekitchen-gmbh.com/btstack/profiles/#gap-le-generic-access-profile-for-low-energy

## Attack Surface
* Not a whole lot going on since this layer is just in charge of talking to a controller and passing data along to higher levels
* ECC attack for MiTM (TODO: Link)
* What is interesting about the attack surface is that for each protocol, Android has a server and a client. For example, the Android phone can receive and parse SDP packets, as well as send them to a device it is in the process of connecting to. While we would typically need to find some triggering condition to have the client issue requests from us and parse their response, this is an interesting attack surface as it might be less likely developers will think about the security of parsing the response from the server. As we will see in the various protocol client applications, this was indeed the case.

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

## Attack Surface
* Channels and their state are created and stored within the stack, abusing the state machine could lead to use-after-frees

TODO: Go through each bluetooth stack and show what channels are registered (point out the weird iOS stuff)

## Stack Comparisions

## CVEs
* CVE-2017-0781 RCE (Allocate buffers of the right size when BT_HDR is included): https://android.googlesource.com/platform/system/bt/+/c513a8ff5cfdcc62cc14da354beb1dd22e56be0e
  - Vuln used by Bluebourne in their exploit POC, the code when run would cause a heap overflow due to the allocation being too small
  ```
  p_bcb->p_pending_data = (BT_HDR*)osi_malloc(rem_len + sizeof(BT_HDR));
  memcpy((uint8_t*)(p_bcb->p_pending_data + 1), p, rem_len);
  ```
* CVE-2018-9359 Fix OOB read in process_l2cap_cmd (signalling commands ID) - https://android.googlesource.com/platform/system/bt/+/b66fc16410ff96e9119f8eb282e67960e79075c8
  - Pretty much no signalling commands were checking minimum length and variables read from the packet were sent back to the user
  - For example:
* CVE-2018-9419	l2c ble ID - https://android.googlesource.com/platform/system/bt/+/f1c2c86080bcd7b3142ff821441696fc99c2bc9a
  - End of packet is not checked, bytes can be leaked
```
     case L2CAP_CMD_DISC_REQ:
+      if (p + 4 > p_pkt_end) {
+        android_errorWriteLog(0x534e4554, "74121659");
+        return;
+      }
```
* CVE-2018-9555	l2cap RCE: https://android.googlesource.com/platform/system/bt/+/02fc52878d8dba16b860fbdf415b6e4425922b2c
  - todo
```
+    if (sdu_length < p_buf->len) {
+      L2CAP_TRACE_ERROR("%s: Invalid sdu_length: %d", __func__, sdu_length);
+      android_errorWriteWithInfoLog(0x534e4554, "112321180", -1, NULL, 0);
+      /* Discard the buffer */
+      osi_free(p_buf);
+      return;
+    }
```
* ble l2cap retransmission RCE (regression of CVE-2018-9555) - https://android.googlesource.com/platform/system/bt/+/488aa8befd5bdffed6cfca7a399d2266ffd201fb
```
void l2c_lcc_proc_pdu(tL2C_CCB* p_ccb, BT_HDR* p_buf) {
  uint8_t* p = (uint8_t*)(p_buf + 1) + p_buf->offset;
  uint16_t sdu_length;
  /* Buffer length should not exceed local mps */
  if (p_buf->len > p_ccb->local_conn_cfg.mps) {
    /* Discard the buffer */
  }
  if (p_ccb->is_first_seg) {
    // If we do not have this check, then p_buf->len can be 0 or 1
    if (p_buf->len < sizeof(sdu_length)) {
      /* Discard the buffer */
    }

    STREAM_TO_UINT16(sdu_length, p);
    /* Check the SDU Length with local MTU size */
    if (sdu_length > p_ccb->local_conn_cfg.mtu) {
      /* Discard the buffer */
    }
    if (sdu_length < p_buf->len) {
      /* Discard the buffer */
    }
    p_data = (BT_HDR*)osi_malloc(BT_HDR_SIZE + sdu_length);

    p_buf->len -= sizeof(sdu_length);
  }

  // p_buf->len could be super huge
  memcpy((uint8_t*)(p_data + 1) + p_data->offset + p_data->len,
         (uint8_t*)(p_buf + 1) + p_buf->offset, p_buf->len);
```
* CVE-2018-9485	L2ble OOB read - https://android.googlesource.com/platform/system/bt/+/bdbabb2ca4ebb4dc5971d3d42cb12f8048e23a23
* CVE-2018-9486 l2cap check length - https://android.googlesource.com/platform/system/bt/+/bc6aef4f29387d07e0c638c9db810c6c1193f75b
```
static void hidh_l2cif_data_ind(uint16_t l2cap_cid, BT_HDR* p_msg) {
...
+  if (p_msg->len < 1) {
+    HIDH_TRACE_WARNING("Rcvd L2CAP data, invalid length %d, should be >= 1",
+                       p_msg->len);
+    osi_free(p_msg);
+    android_errorWriteLog(0x534e4554, "80493272");
+    return;
+  }
+
   ttype = HID_GET_TRANS_FROM_HDR(*p_data); // p_data has data from the server that will get leaked
   param = HID_GET_PARAM_FROM_HDR(*p_data);
   rep_type = param & HID_PAR_REP_TYPE_MASK;
```
* CVE-2018-9484 Out of Bounds read in l2cap - https://android.googlesource.com/platform/system/bt/+/d5b44f6522c3294d6f5fd71bc6670f625f716460
  - you can position p and get data out
```
if ((cfg_len + L2CAP_CFG_OPTION_OVERHEAD) <= cmd_len) {
+ if (p + cfg_len > p_next_cmd) return;
```

* That thing Joel sent
* Tesla Keen Team report - https://www.blackhat.com/docs/us-17/thursday/us-17-Nie-Free-Fall-Hacking-Tesla-From-Wireless-To-CAN-Bus-wp.pdf

## Interactive Example
Let's run through an example POC
