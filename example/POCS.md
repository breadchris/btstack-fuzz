# Bluetooth POCs

## POCs to make
* https://android.googlesource.com/platform/system/bt/+/2d21e75aa8c1e0c4adf178a1330f9f5c573ca045%5E%21/#F0
* ble l2cap rce - https://android.googlesource.com/platform/system/bt/+/488aa8befd5bdffed6cfca7a399d2266ffd201fb%5E%21/#F0
* https://android.googlesource.com/platform/system/bt/+/11fb7aa03437eccac98d90ca2de1730a02a515e2%5E%21/#F0
* https://android.googlesource.com/platform/system/bt/+/297598898683b81e921474e6e74c0ddaedbb8bb5%5E%21/#F0
* https://android.googlesource.com/platform/system/bt/+/94d718eb61cbb1e6fd08288039d7e62913735c6c

Bluebourne papers
* Finding bugs: https://go.armis.com/hubfs/BlueBorne%20Technical%20White%20Paper-1.pdf?t=1530135549212
* Exploiting Android: https://go.armis.com/hubfs/BlueBorne%20-%20Android%20Exploit.pdf
* Exploiting IoT: https://www.blackhat.com/docs/eu-17/materials/eu-17-Seri-BlueBorne-A-New-Class-Of-Airborne-Attacks-Compromising-Any-Bluetooth-Enabled-Linux-IoT-Device-wp.pdf

## Android
* https://github.com/JiounDai/Bluedroid

### Quarks lab
* https://blog.quarkslab.com/a-story-about-three-bluetooth-vulnerabilities-in-android.html

### Porting Bluebourne POC
* https://jesux.es/exploiting/blueborne-android-6.0.1-english/

### Android Security Advisories
* Bluetooth Pineapple: https://android.googlesource.com/platform/system/bt/+/1e77fefc8b9c832239e1b32c6a6880376065e24e
* ID - "In avrc_ctrl_pars_vendor_rsp of avrc_pars_ct.c, there is a possible out of bounds read due to a missing bounds check." https://android.googlesource.com/platform/system/bt/+/99d54d0c7dbab6c80f15bbf886ed203b2a547453

```
-void avrc_parse_notification_rsp(uint8_t* p_stream,
-                                 tAVRC_REG_NOTIF_RSP* p_rsp) {
+tAVRC_STS avrc_parse_notification_rsp(uint8_t* p_stream, uint16_t len,
+                                      tAVRC_REG_NOTIF_RSP* p_rsp) {
+  uint16_t min_len = 1;
+
+  if (len < min_len) goto length_error;
   BE_STREAM_TO_UINT8(p_rsp->event_id, p_stream);
   switch (p_rsp->event_id) {
     case AVRC_EVT_PLAY_STATUS_CHANGE:
+      min_len += 1;
+      if (len < min_len) goto length_error;
       BE_STREAM_TO_UINT8(p_rsp->param.play_status, p_stream);
       break;
```

* ID - https://android.googlesource.com/platform/system/bt/+/cc364611362cc5bc896b400bdc471a617d1ac628
* RCE (Easy to exploit) - https://android.googlesource.com/platform/system/bt/+/ebc284cf3a59ee5cf7c06af88c2f3bcd0480e3e9

```
static tAVRC_STS avrc_ctrl_pars_vendor_rsp(tAVRC_MSG_VENDOR* p_msg,
                                           tAVRC_RESPONSE* p_result,
                                           uint8_t* p_buf, uint16_t* buf_len) {
  uint8_t* p = p_msg->p_vendor_data;
  BE_STREAM_TO_UINT8(p_result->pdu, p);
  p++; /* skip the reserved/packe_type byte */
  uint16_t len;
  BE_STREAM_TO_UINT16(len, p);
  AVRC_TRACE_DEBUG("%s ctype:0x%x pdu:0x%x, len:%d", __func__, p_msg->hdr.ctype,
                   p_result->pdu, len);
  /* Todo: Issue in handling reject, check */
  if (p_msg->hdr.ctype == AVRC_RSP_REJ) {
    p_result->rsp.status = *p;
    return p_result->rsp.status;
  }
  /* TODO: Break the big switch into functions. */
  switch (p_result->pdu) {
    /* case AVRC_PDU_REQUEST_CONTINUATION_RSP: 0x40 */
    /* case AVRC_PDU_ABORT_CONTINUATION_RSP:   0x41 */
    case AVRC_PDU_REGISTER_NOTIFICATION:
      avrc_parse_notification_rsp(p, &p_result->reg_notif);
      break;
...
static tAVRC_STS avrc_ctrl_pars_vendor_rsp(tAVRC_MSG_VENDOR* p_msg,
                                           tAVRC_RESPONSE* p_result,
                                           uint8_t* p_buf, uint16_t* buf_len) {
  uint8_t* p = p_msg->p_vendor_data;
  BE_STREAM_TO_UINT8(p_result->pdu, p);
  p++; /* skip the reserved/packe_type byte */
  uint16_t len;
  BE_STREAM_TO_UINT16(len, p);
  AVRC_TRACE_DEBUG("%s ctype:0x%x pdu:0x%x, len:%d", __func__, p_msg->hdr.ctype,
                   p_result->pdu, len);
  /* Todo: Issue in handling reject, check */
  if (p_msg->hdr.ctype == AVRC_RSP_REJ) {
    p_result->rsp.status = *p;
    return p_result->rsp.status;
  }
  /* TODO: Break the big switch into functions. */
  switch (p_result->pdu) {
...
    case AVRC_PDU_LIST_PLAYER_APP_VALUES:
      if (len == 0) {
        p_result->list_app_values.num_val = 0;
        break;
      }
       BE_STREAM_TO_UINT8(p_result->list_app_values.num_val, p);
+      if (p_result->list_app_values.num_val > AVRC_MAX_APP_ATTR_SIZE) {
+        android_errorWriteLog(0x534e4554, "78526423");
+        p_result->list_app_values.num_val = AVRC_MAX_APP_ATTR_SIZE;
+      }
+
       AVRC_TRACE_DEBUG("%s value count = %d ", __func__,
                        p_result->list_app_values.num_val);
       for (int xx = 0; xx < p_result->list_app_values.num_val; xx++) {
        BE_STREAM_TO_UINT8(p_result->list_app_values.vals[xx], p);
      }
```
      
* ID - https://android.googlesource.com/platform/system/bt/+/11fb7aa03437eccac98d90ca2de1730a02a515e2
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
* ID - https://android.googlesource.com/platform/system/bt/+/92a7bf8c44a236607c146240f3c0adc1ae01fedf, https://android.googlesource.com/platform/system/bt/+/d4a34fefbf292d1e02336e4e272da3ef1e3eef85, https://android.googlesource.com/platform/system/bt/+/9fe27a9b445f7e911286ed31c1087ceac567736b
* ID - https://android.googlesource.com/platform/system/bt/+/5216e6120160b28d76e9ee4dff9995e772647511
* ID - https://android.googlesource.com/platform/system/bt/+/830cb39cb2a0f1bf6704d264e2a5c5029c175dd7
* ID - https://android.googlesource.com/platform/system/bt/+/30cec963095366536ca0b1306089154e09bfe1a9
* ID - https://android.googlesource.com/platform/system/bt/+/e8bbf5b0889790cf8616f4004867f0ff656f0551
* ID - https://android.googlesource.com/platform/system/bt/+/198888b8e0163bab7a417161c63e483804ae8e31
* ID - https://android.googlesource.com/platform/system/bt/+/6e4b8e505173f803a5fc05abc09f64eef89dc308
* ID - https://android.googlesource.com/platform/system/bt/+/75c22982624fb530bc1d57aba6c1e46e7881d6ba
* Out of Bounds read in l2cap - https://android.googlesource.com/platform/system/bt/+/d5b44f6522c3294d6f5fd71bc6670f625f716460
* L2ble OOB read - https://android.googlesource.com/platform/system/bt/+/bdbabb2ca4ebb4dc5971d3d42cb12f8048e23a23
* l2cap check length - https://android.googlesource.com/platform/system/bt/+/bc6aef4f29387d07e0c638c9db810c6c1193f75b
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

* RCE SMP (Check p_cb->role in smp_br_state_machine_event) - https://android.googlesource.com/platform/system/bt/+/49acada519d088d8edf37e48640c76ea5c70e010
	*   if (p_cb->role > HCI_ROLE_SLAVE) { --> state_table = smp_br_state_table[curr_state][p_cb->role];
	* Attacker supplied p_cb->role had ended up being used to lookup index in smp_br_state_table, letting you specify what function you wanted to call
	* also in https://android.googlesource.com/platform/system/bt/+/ae94a4c333417a1829030c4d87a58ab7f1401308
* RCE - https://android.googlesource.com/platform/system/bt/+/bc259b4926a6f9b33b9ee2c917cd83a55f360cbf
since the original packet is being reused, we are copying a certain number of bytes past the end?
not too sure about this one
avrc_proc_vendor_command
   if (status != AVRC_STS_NO_ERROR) {
-    /* use the current GKI buffer to build/send the reject message */
-    p_data = (uint8_t*)(p_pkt + 1) + p_pkt->offset;
+    p_rsp = (BT_HDR*)osi_malloc(BT_DEFAULT_BUFFER_SIZE);
+    p_rsp->offset = p_pkt->offset;
+    p_data = (uint8_t*)(p_rsp + 1) + p_pkt->offset;
     *p_data++ = AVRC_RSP_REJ;
     p_data += AVRC_VENDOR_HDR_SIZE; /* pdu */
     *p_data++ = 0;                  /* pkt_type */
     UINT16_TO_BE_STREAM(p_data, 1); /* len */
     *p_data++ = status;             /* error code */
-    p_pkt->len = AVRC_VENDOR_HDR_SIZE + 5;
-    p_rsp = p_pkt;
+    p_rsp->len = AVRC_VENDOR_HDR_SIZE + 5;
   }
* ID in BNEP - https://android.googlesource.com/platform/system/bt/+/289a49814aef7f0f0bb98aac8246080abdfeac01
* ID in BNEP - https://android.googlesource.com/platform/system/bt/+/289a49814aef7f0f0bb98aac8246080abdfeac01
* ID - https://android.googlesource.com/platform/system/bt/+/13294c70a66347c9e5d05b9f92f8ceb6fe38d7f6
* ID - https://android.googlesource.com/platform/system/bt/+/cb6a56b1d8cdab7c495ea8f53dcbdb3cfc9477d2
* l2c ble ID - https://android.googlesource.com/platform/system/bt/+/f1c2c86080bcd7b3142ff821441696fc99c2bc9a
* RCE in SDP while processing data returned when looking up records - https://android.googlesource.com/platform/system/bt/+/99a263a7f04c5c6f101388007baa18cf1e8c30bf
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
* RCE in PAN - https://android.googlesource.com/platform/system/bt/+/d7d4d5686b2e3c37c7bf10a6a2adff1c95251a13

	```
	static void bta_pan_data_buf_ind_cback(uint16_t handle, const RawAddress& src,
	                                       const RawAddress& dst, uint16_t protocol,
	                                       BT_HDR* p_buf, bool ext, bool forward) {
	tBTA_PAN_SCB* p_scb = bta_pan_scb_by_handle(handle);
	if (p_scb == NULL) {
	return;
	}

	if (sizeof(BT_HDR) + sizeof(tBTA_PAN_DATA_PARAMS) + p_buf->len >
	  PAN_BUF_SIZE) {
	android_errorWriteLog(0x534e4554, "63146237");
	APPL_TRACE_ERROR("%s: received buffer length too large: %d", __func__,
	                 p_buf->len);
	return;
	}

	BT_HDR* p_new_buf = (BT_HDR*)osi_malloc(PAN_BUF_SIZE);
	memcpy((uint8_t*)(p_new_buf + 1) + sizeof(tBTA_PAN_DATA_PARAMS),
	     (uint8_t*)(p_buf + 1) + p_buf->offset, p_buf->len);
	p_new_buf->len = p_buf->len;
	p_new_buf->offset = sizeof(tBTA_PAN_DATA_PARAMS);
	```

* RCE in BNEP - https://android.googlesource.com/platform/system/bt/+/9164ee1aaf3609b4771d39302e3af649f44c9e66
	* BNEP_Write -> if (new_len > org_len) return BNEP_IGNORE_CMD; were placed because extension bit could let you make big writes
* GATT ID - https://android.googlesource.com/platform/system/bt/+/0d7c2f5a14d1055f3b4f69035451c66bf8f1b08e
* UNUSED_ATTR in length for gatt - https://android.googlesource.com/platform/system/bt/+/0d7c2f5a14d1055f3b4f69035451c66bf8f1b08e
* Fix OOB read in process_l2cap_cmd - https://android.googlesource.com/platform/system/bt/+/b66fc16410ff96e9119f8eb282e67960e79075c8
* RCE - https://android.googlesource.com/platform/system/bt/+/6ecbbc093f4383e90cbbf681cd55da1303a8ef94
static tAVRC_STS avrc_ctrl_pars_vendor_rsp(tAVRC_MSG_VENDOR* p_msg,
                                           tAVRC_RESPONSE* p_result,
                                           uint8_t* p_buf, uint16_t* buf_len) {
  uint8_t* p = p_msg->p_vendor_data;
  BE_STREAM_TO_UINT8(p_result->pdu, p);
  p++; /* skip the reserved/packe_type byte */
  uint16_t len;
  BE_STREAM_TO_UINT16(len, p);
  AVRC_TRACE_DEBUG("%s ctype:0x%x pdu:0x%x, len:%d", __func__, p_msg->hdr.ctype,
                   p_result->pdu, len);
  /* Todo: Issue in handling reject, check */
  if (p_msg->hdr.ctype == AVRC_RSP_REJ) {
    p_result->rsp.status = *p;
    return p_result->rsp.status;
  }
  /* TODO: Break the big switch into functions. */
  switch (p_result->pdu) {
  ...
  case AVRC_PDU_LIST_PLAYER_APP_ATTR:
      if (len == 0) {
        p_result->list_app_attr.num_attr = 0;
        break;
      }
      BE_STREAM_TO_UINT8(p_result->list_app_attr.num_attr, p);
      AVRC_TRACE_DEBUG("%s attr count = %d ", __func__,
                       p_result->list_app_attr.num_attr);
      if (p_result->list_app_attr.num_attr > AVRC_MAX_APP_ATTR_SIZE) {
        android_errorWriteLog(0x534e4554, "63146237");
        p_result->list_app_attr.num_attr = AVRC_MAX_APP_ATTR_SIZE;
      }
      for (int xx = 0; xx < p_result->list_app_attr.num_attr; xx++) {
        BE_STREAM_TO_UINT8(p_result->list_app_attr.attrs[xx], p);
      }
      break;
* SDP ID - https://android.googlesource.com/platform/system/bt/+/72b1cebaa9cc7ace841d887f0d4a4bf6daccde6e
* SDP RCE - https://android.googlesource.com/platform/system/bt/+/f0edf6571d2d58e66ee0b100ebe49c585d31489f
	* Integer underflow in process_service_attr_req, max_list_len is read from request
* SDP Use after free - https://android.googlesource.com/platform/system/bt/+/ec16f7d8c7e359a68ffe6b76e88add2210bf2cbd
* PAN Use after free - https://android.googlesource.com/platform/system/bt/+/08e68337a9eb45818d5a770570c8b1d15a14d904
* BNEP ID - https://android.googlesource.com/platform/system/bt/+/a50e70468c0a8d207e416e273d05a08635bdd45f
* SDP ID - https://android.googlesource.com/platform/system/bt/+/0627e76edefd948dc3efe11564d7e53d56aac80c
* bta gattc RCE - https://android.googlesource.com/platform/system/bt/+/68a1cf1a9de115b66bececf892588075595b263f
* ble l2cap retransmission RCE - https://android.googlesource.com/platform/system/bt/+/488aa8befd5bdffed6cfca7a399d2266ffd201fb
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

## Potential bugs
https://git.kernel.org/pub/scm/bluetooth/bluez.git/tree/src/sdpd-request.c:517 rsp_count is used in copy length
https://git.kernel.org/pub/scm/bluetooth/bluez.git/tree/src/sdpd-request.c:257 possible use after free
