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
  *
* The parsing is relatively complex, I think bluez's implementation is the clearest
* If a response is too big, a continuation state is created

## Attack Surface
TODO: Run sdp tool on each stack
<<<<<<< Updated upstream

## CVEs
### Android
* CVE-2018-9478	SDP RCE: https://android.googlesource.com/platform/system/bt/+/68688194eade113ad31687a730e8d4102ada58d5
    * Hard to exploit: You can cause memcpy to copy a huge amount of bytes onto the heap, but where you need to control data to write the heap cookie you aren't able to control it.
* CVE-2018-9590	SDP ID: https://android.googlesource.com/platform/system/bt/+/297598898683b81e921474e6e74c0ddaedbb8bb5
* CVE-2018-9566	SDP ID: https://android.googlesource.com/platform/system/bt/+/314336a22d781f54ed7394645a50f74d6743267d
* CVE-2018-9562	SDP ID in client: https://android.googlesource.com/platform/system/bt/+/1bb14c41a72978c6075c5753a8301ddcbb10d409
* CVE-2018-9504	ID in SDP - https://android.googlesource.com/platform/system/bt/+/11fb7aa03437eccac98d90ca2de1730a02a515e2
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
	* Integer underflow in process_service_attr_req, max_list_len is read from request
* CVE-2017-13290 SDP ID - https://android.googlesource.com/platform/system/bt/+/72b1cebaa9cc7ace841d887f0d4a4bf6daccde6e
* CVE-2017-13259 SDP ID - https://android.googlesource.com/platform/system/bt/+/0627e76edefd948dc3efe11564d7e53d56aac80c
=======
>>>>>>> Stashed changes
