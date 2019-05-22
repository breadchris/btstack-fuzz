# SDP

This is probably the most sketch protocol in Bluetooth. There is a lot going on with the protocol and it is required to be exposed to all devices so they know what applications the device has registered (e.g. can I send music to you? yes! I have AV controller!). Granted, devices that operate only with BLE do not have this since information is advertised via GATT. However, all mobile devices, cars, and things that need compatability with older protocols will be listening for SDP

## Notable Features
* The SDP `server` handles remote queries of the SDP database which contains information for all registered services for the device. For example...
* The SDP `client` performs queries and parses their response
* There are three different queries which can be performed: (TODO fill in these details)
  * ServiceSearchRequest
  * ServiceAttributeRequest
  * ServiceSearchAttributeRequest
* Queries are comprised of `data elements` which are type, length, value structures (seen here: btstack sdp_util.h:105)
  * These `data elements` 
* The parsing is relatively complex, I think bluez's implementation is the clearest: https://git.kernel.org/pub/scm/bluetooth/bluez.git/tree/lib/sdp.c
* If a response is too big, a `continuation state` is created (TODO: Reference specification)
  * This `continuation state` has led to a number of vulnerabilities with Android (TODO: refs) due to the server either trusting the client's state or the internal state becomes corrupt and lengths become out of sync (TODO: ref bluebourne exploit leak)

## Attack Surface
* Since every device must always expose their SDP server (allow JustWorks pairing, see HCI/L2cap) to all nearby devices to tell them what sevices are accessible on the device, this provides a nice no-interaction attack surface. Additionally, a given bluetooth stack might have some sort of automated trigger (see iOS Airpod discovery) which causes it to use its SDP client to send a request and parse a response from the attacker's device. Again, a no-interaction needed attack surface. 
* The SDP protocol is sufficiently complex to most likely contain bugs in any implementation, as shown in researchers digging through Android.

TODO: Run sdp tool on each stack

```
➜  libusb-intel git:(fuzzable) ✗ sudo ./sdp_l2cap_scan --address 38:CA:DA:85:5F:E1
Packet Log: /tmp/hci_dump.pklg
USB Path: 07
Client HCI init done
BTstack up and running on 18:56:80:04:42:72.

---
Record nr. 0
sdp attribute: 0x0004
summary: uuid 0x0003, l2cap_psm: 0x0000

---
Record nr. 1
sdp attribute: 0x0004
summary: uuid 0x0100, l2cap_psm: 0x000f, name: BNEP
summary: uuid 0x000f, l2cap_psm: 0x0100, name: L2CAP

---
Record nr. 2
sdp attribute: 0x0004
summary: uuid 0x0003, l2cap_psm: 0x0000

---
Record nr. 3
sdp attribute: 0x0004
summary: uuid 0x0003, l2cap_psm: 0x0000

---
Record nr. 4
sdp attribute: 0x0004
summary: uuid 0x0100, l2cap_psm: 0x0017, name: AVCTP
summary: uuid 0x0017, l2cap_psm: 0x0104

---
Record nr. 5
sdp attribute: 0x0004
summary: uuid 0x0100, l2cap_psm: 0x0017, name: AVCTP
summary: uuid 0x0017, l2cap_psm: 0x0104

---
Record nr. 6
sdp attribute: 0x0004
summary: uuid 0x0100, l2cap_psm: 0x0019, name: AVDTP
summary: uuid 0x0019, l2cap_psm: 0x0103

---
Record nr. 7
sdp attribute: 0x0004
summary: uuid 0x0003, l2cap_psm: 0x0000

---
Record nr. 8
sdp attribute: 0x0004
summary: uuid 0x0003, l2cap_psm: 0x0000

---
```

## CVEs
### Android
* CVE-2018-9478	SDP RCE: https://android.googlesource.com/platform/system/bt/+/68688194eade113ad31687a730e8d4102ada58d5
    - Hard to exploit: You can cause memcpy to copy a huge amount of bytes onto the heap, but where you need to control data to write the heap cookie you aren't able to control it.
    - More details in the presentation: https://github.com/JiounDai/Bluedroid/blob/master/Dissect%20Android%20Bluetooth%20for%20Fun%20%26%20Profit.pdf
* CVE-2018-9590	SDP ID: https://android.googlesource.com/platform/system/bt/+/297598898683b81e921474e6e74c0ddaedbb8bb5
```
diff --git a/stack/sdp/sdp_discovery.cc b/stack/sdp/sdp_discovery.cc
index 95f55bf..1ca2ad3 100644
--- a/stack/sdp/sdp_discovery.cc
+++ b/stack/sdp/sdp_discovery.cc
@@ -55,7 +55,7 @@
 static uint8_t* save_attr_seq(tCONN_CB* p_ccb, uint8_t* p, uint8_t* p_msg_end);
 static tSDP_DISC_REC* add_record(tSDP_DISCOVERY_DB* p_db,
                                  const RawAddress& p_bda);
-static uint8_t* add_attr(uint8_t* p, tSDP_DISCOVERY_DB* p_db,
+static uint8_t* add_attr(uint8_t* p, uint8_t* p_end, tSDP_DISCOVERY_DB* p_db,
                          tSDP_DISC_REC* p_rec, uint16_t attr_id,
                          tSDP_DISC_ATTR* p_parent_attr, uint8_t nest_level);
 
@@ -770,7 +770,7 @@
     BE_STREAM_TO_UINT16(attr_id, p);
 
     /* Now, add the attribute value */
-    p = add_attr(p, p_ccb->p_db, p_rec, attr_id, NULL, 0);
+    p = add_attr(p, p_seq_end, p_ccb->p_db, p_rec, attr_id, NULL, 0);
 
     if (!p) {
       SDP_TRACE_WARNING("SDP - DB full add_attr");
@@ -830,7 +830,7 @@
  * Returns          pointer to next byte in data stream
  *
  ******************************************************************************/
-static uint8_t* add_attr(uint8_t* p, tSDP_DISCOVERY_DB* p_db,
+static uint8_t* add_attr(uint8_t* p, uint8_t* p_end, tSDP_DISCOVERY_DB* p_db,
                          tSDP_DISC_REC* p_rec, uint16_t attr_id,
                          tSDP_DISC_ATTR* p_parent_attr, uint8_t nest_level) {
   tSDP_DISC_ATTR* p_attr;
@@ -839,7 +839,7 @@
   uint16_t attr_type;
   uint16_t id;
   uint8_t type;
-  uint8_t* p_end;
+  uint8_t* p_attr_end;
   uint8_t is_additional_list = nest_level & SDP_ADDITIONAL_LIST_MASK;
 
   nest_level &= ~(SDP_ADDITIONAL_LIST_MASK);
@@ -856,6 +856,13 @@
   else
     total_len = sizeof(tSDP_DISC_ATTR);
 
+  p_attr_end = p + attr_len;
+  if (p_attr_end > p_end) {
+    android_errorWriteLog(0x534e4554, "115900043");
+    SDP_TRACE_WARNING("%s: SDP - Attribute length beyond p_end", __func__);
+    return NULL;
+  }
+
   /* Ensure it is a multiple of 4 */
   total_len = (total_len + 3) & ~3;
 
@@ -879,18 +886,17 @@
            * sub-attributes */
           p_db->p_free_mem += sizeof(tSDP_DISC_ATTR);
           p_db->mem_free -= sizeof(tSDP_DISC_ATTR);
-          p_end = p + attr_len;
           total_len = 0;
 
           /* SDP_TRACE_DEBUG ("SDP - attr nest level:%d(list)", nest_level); */
           if (nest_level >= MAX_NEST_LEVELS) {
             SDP_TRACE_ERROR("SDP - attr nesting too deep");
-            return (p_end);
+            return p_attr_end;
           }
 
           /* Now, add the list entry */
-          p = add_attr(p, p_db, p_rec, ATTR_ID_PROTOCOL_DESC_LIST, p_attr,
-                       (uint8_t)(nest_level + 1));
+          p = add_attr(p, p_end, p_db, p_rec, ATTR_ID_PROTOCOL_DESC_LIST,
+                       p_attr, (uint8_t)(nest_level + 1));
 
           break;
         }
@@ -949,7 +955,7 @@
           break;
         default:
           SDP_TRACE_WARNING("SDP - bad len in UUID attr: %d", attr_len);
-          return (p + attr_len);
+          return p_attr_end;
       }
       break;
 
@@ -959,22 +965,22 @@
        * sub-attributes */
       p_db->p_free_mem += sizeof(tSDP_DISC_ATTR);
       p_db->mem_free -= sizeof(tSDP_DISC_ATTR);
-      p_end = p + attr_len;
       total_len = 0;
 
       /* SDP_TRACE_DEBUG ("SDP - attr nest level:%d", nest_level); */
       if (nest_level >= MAX_NEST_LEVELS) {
         SDP_TRACE_ERROR("SDP - attr nesting too deep");
-        return (p_end);
+        return p_attr_end;
       }
       if (is_additional_list != 0 ||
           attr_id == ATTR_ID_ADDITION_PROTO_DESC_LISTS)
         nest_level |= SDP_ADDITIONAL_LIST_MASK;
       /* SDP_TRACE_DEBUG ("SDP - attr nest level:0x%x(finish)", nest_level); */
 
-      while (p < p_end) {
+      while (p < p_attr_end) {
         /* Now, add the list entry */
-        p = add_attr(p, p_db, p_rec, 0, p_attr, (uint8_t)(nest_level + 1));
+        p = add_attr(p, p_end, p_db, p_rec, 0, p_attr,
+                     (uint8_t)(nest_level + 1));
 
         if (!p) return (NULL);
       }
@@ -992,7 +998,7 @@
           break;
         default:
           SDP_TRACE_WARNING("SDP - bad len in boolean attr: %d", attr_len);
-          return (p + attr_len);
+          return p_attr_end;
       }
       break;
 
```
* CVE-2018-9566	SDP ID: https://android.googlesource.com/platform/system/bt/+/314336a22d781f54ed7394645a50f74d6743267d
  - No length check
```
+  if (p_reply + 8 > p_reply_end) {
+    android_errorWriteLog(0x534e4554, "74249842");
+    sdp_disconnect(p_ccb, SDP_GENERIC_ERROR);
+    return;
+  }
   /* Skip transaction, and param len */
   p_reply += 4;
   BE_STREAM_TO_UINT16(total, p_reply);
// ...
+  if (p_reply + ((p_ccb->num_handles - orig) * 4) + 1 > p_reply_end) {
+    android_errorWriteLog(0x534e4554, "74249842");
+    sdp_disconnect(p_ccb, SDP_GENERIC_ERROR);
+    return;
+  }
+
   for (xx = orig; xx < p_ccb->num_handles; xx++)
     BE_STREAM_TO_UINT32(p_ccb->handles[xx], p_reply);
```
* CVE-2018-9562	SDP ID in client: https://android.googlesource.com/platform/system/bt/+/1bb14c41a72978c6075c5753a8301ddcbb10d409
  - This one is actually pretty interesting. `num_uuid` was previously set to 2 which when copying from `uuid_list` (located on the stack as `Uuid uuid_list[1];`) would copy an additional `sizeof(Uuid)` bytes into the `uuid_filters` array for the SDP entry. This data would then be sent if device received a service search attribute response (sdp_discovery.cc:584) and a continuation request is needed (sdp_discovery.cc:563).
```
Uuid uuid_list[1];
...
num_uuid = 2;
...
for (xx = 0; xx < num_uuid; xx++) p_db->uuid_filters[xx] = *p_uuid_list++;
...
p = sdpu_build_uuid_seq(p, p_ccb->p_db->num_uuid_filters,
                             p_ccb->p_db->uuid_filters);
...
L2CA_DataWrite(p_ccb->connection_id, p_msg);
```
* CVE-2018-9504	ID in SDP - https://android.googlesource.com/platform/system/bt/+/11fb7aa03437eccac98d90ca2de1730a02a515e2
    - ID in the client while saving response from attacker
```
static void sdp_copy_raw_data(tCONN_CB* p_ccb, bool offset) {
  unsigned int cpy_len, rem_len;
  uint32_t list_len;
  uint8_t* p;
  uint8_t type;
#if (SDP_DEBUG_RAW == TRUE)
  uint8_t num_array[SDP_MAX_LIST_BYTE_COUNT];
  uint32_t i;
  for (i = 0; i < p_ccb->list_len; i++) {
    snprintf((char*)&num_array[i * 2], sizeof(num_array) - i * 2, "%02X",
             (uint8_t)(p_ccb->rsp_list[i]));
  }
  SDP_TRACE_WARNING("result :%s", num_array);
#endif
  if (p_ccb->p_db->raw_data) {
    cpy_len = p_ccb->p_db->raw_size - p_ccb->p_db->raw_used;
    list_len = p_ccb->list_len;
     p = &p_ccb->rsp_list[0];

     if (offset) {
+      cpy_len -= 1;
       type = *p++;
+      uint8_t* old_p = p;
       p = sdpu_get_len_from_type(p, type, &list_len);
+      if ((int)cpy_len < (p - old_p)) {
+        SDP_TRACE_WARNING("%s: no bytes left for data", __func__);
+        return;
+      }
+      cpy_len -= (p - old_p);
     }
    if (list_len < cpy_len) {
      cpy_len = list_len;
    }
    rem_len = SDP_MAX_LIST_BYTE_COUNT - (unsigned int)(p - &p_ccb->rsp_list[0]);
    if (cpy_len > rem_len) {
      SDP_TRACE_WARNING("rem_len :%d less than cpy_len:%d", rem_len, cpy_len);
      cpy_len = rem_len;
    }
    memcpy(&p_ccb->p_db->raw_data[p_ccb->p_db->raw_used], p, cpy_len);
    p_ccb->p_db->raw_used += cpy_len;
```
* CVE-2018-9355 RCE in SDP while processing data returned when looking up records - https://android.googlesource.com/platform/system/bt/+/99a263a7f04c5c6f101388007baa18cf1e8c30bf
```
// stack based buffer overflow - Stack array of arrays which has a set length, but will copy how every many times the client told it to
/*******************************************************************************
 *
 * Function         bta_dm_sdp_result
 *
 * Description      Process the discovery result from sdp
void bta_dm_sdp_result(tBTA_DM_MSG* p_data) {
...
-  uint8_t uuid_list[32][MAX_UUID_SIZE];  // assuming a max of 32 services
+  uint8_t uuid_list[BTA_MAX_SERVICES][MAX_UUID_SIZE];  // assuming a max of 32 services
                 bta_service_id_to_uuid_lkup_tbl[bta_dm_search_cb.service_index -
                                                 1];
             /* Add to the list of UUIDs */
-            sdpu_uuid16_to_uuid128(tmp_svc, uuid_list[num_uuids]);
-            num_uuids++;
+            if (num_uuids < BTA_MAX_SERVICES) {
+              sdpu_uuid16_to_uuid128(tmp_svc, uuid_list[num_uuids]);
+              num_uuids++;
+            } else {
+              android_errorWriteLog(0x534e4554, "74016921");
+            }
           }
         }
       }
...
             SDP_FindServiceInDb_128bit(bta_dm_search_cb.p_sdp_db, p_sdp_rec);
         if (p_sdp_rec) {
           if (SDP_FindServiceUUIDInRec_128bit(p_sdp_rec, &temp_uuid)) {
-            memcpy(uuid_list[num_uuids], temp_uuid.uu.uuid128, MAX_UUID_SIZE);
-            num_uuids++;
+            if (num_uuids < BTA_MAX_SERVICES) {
+              memcpy(uuid_list[num_uuids], temp_uuid.uu.uuid128, MAX_UUID_SIZE);
+              num_uuids++;
+            } else {
+              android_errorWriteLog(0x534e4554, "74016921");
+            }
           }
         }
       } while (p_sdp_rec);
```
* CVE-2017-13255 SDP RCE - https://android.googlesource.com/platform/system/bt/+/f0edf6571d2d58e66ee0b100ebe49c585d31489f
```
  // TODO: Not sure what the vuln is?
```
* CVE-2017-13290 SDP ID - https://android.googlesource.com/platform/system/bt/+/72b1cebaa9cc7ace841d887f0d4a4bf6daccde6e
  * The end of the request was never checked. This is the same problem as seen in other areas of the stack, but the approach to fixing is a lot more consistent than other fixes.
  * The end of the request is checked accross many different functions with this patch.
```
 static void process_service_search_attr_req(tCONN_CB* p_ccb, uint16_t trans_num,
                                             uint16_t param_len, uint8_t* p_req,
-                                            UNUSED_ATTR uint8_t* p_req_end);
+                                            uint8_t* p_req_end);

+
+  if (p_req + sizeof(param_len) > p_req_end) {
+    android_errorWriteLog(0x534e4554, "69384124");
+    sdpu_build_n_send_error(p_ccb, trans_num, SDP_INVALID_REQ_SYNTAX,
+                            SDP_TEXT_BAD_HEADER);
+  }
+
   BE_STREAM_TO_UINT16(param_len, p_req);
```
* CVE-2017-13259 SDP ID - https://android.googlesource.com/platform/system/bt/+/0627e76edefd948dc3efe11564d7e53d56aac80c
  * Similar to CVE-2017-13290 but this fixes reading from the end of the request in the client.
```
+static void process_service_search_rsp(tCONN_CB* p_ccb, uint8_t* p_reply,
+                                       uint8_t* p_reply_end);


+    if (p_reply + cont_len > p_reply_end) {
+      android_errorWriteLog(0x534e4554, "68161546");
+      sdp_disconnect(p_ccb, SDP_INVALID_CONT_STATE);
+      return;
+    }
```
