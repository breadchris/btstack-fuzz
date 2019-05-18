# AVRCP and AVTDP

## Notable Features
* Controls audio

## Stack Implementations
* Need to pair with device to access it on Android

Android:
bta_av_api.h:
```
/* Set to TRUE if seperate authorization prompt desired for AVCTP besides A2DP
 * authorization */
/* Typically FALSE when AVRCP is used in conjunction with A2DP */
#ifndef BTA_AV_WITH_AVCTP_AUTHORIZATION
#define BTA_AV_WITH_AVCTP_AUTHORIZATION FALSE
#endif
```

## CVEs
### Android
* CVE-2017-13281 really good length check in AVRCP: https://android.googlesource.com/platform/system/bt/+/6f3ddf3f5cf2b3eb52fb0adabd814a45cff07221%5E%21/
  - length check, but it is just plain wrong lol
```
-        if (buf_len > p_result->search.string.str_len)
-          buf_len = p_result->search.string.str_len;
+        if (p_result->search.string.str_len > buf_len) {
+          p_result->search.string.str_len = buf_len;
+        } else {
+          android_errorWriteLog(0x534e4554, "63146237");
+        }
```
* CVE-2019-1996	AVRCP ID: https://android.googlesource.com/platform/system/bt/+/525bdbd6e1295ed8a081d2ae87105c64d6f1ac4f
No length checks
```
+            min_len += 10 + AVRC_FEATURE_MASK_SIZE;
+            if (pkt_len < min_len) goto browse_length_error;
             BE_STREAM_TO_UINT16(player_len, p);
             BE_STREAM_TO_UINT16(player->player_id, p);
             BE_STREAM_TO_UINT8(player->major_type, p);
             BE_STREAM_TO_UINT32(player->sub_type, p);
             BE_STREAM_TO_UINT8(player->play_status, p);
             BE_STREAM_TO_ARRAY(p, player->features, AVRC_FEATURE_MASK_SIZE);
```
* CVE-2018-9588	AVDP ID: https://android.googlesource.com/platform/system/bt/+/bf9ff0c5215861ab673e211cd06e009f3157aab2
  - This is a juicy info leak
  - No length checks
```
+        min_len += 20;
+        if (min_len > len) {
+          android_errorWriteLog(0x534e4554, "111450156");
+          AVDT_TRACE_WARNING(
+              "%s: hdl packet length %d too short: must be at least %d",
+              __func__, len, min_len);
+          goto avdt_scb_hdl_report_exit;
+        }
         BE_STREAM_TO_UINT32(report.sr.ntp_sec, p);
         BE_STREAM_TO_UINT32(report.sr.ntp_frac, p);
         BE_STREAM_TO_UINT32(report.sr.rtp_time, p);
```
* CVE-2018-9542	ID in AVRCP - https://android.googlesource.com/platform/system/bt/+/cc364611362cc5bc896b400bdc471a617d1ac628
No length checks are performed
```
+    if (len < 1) {
+      android_errorWriteLog(0x534e4554, "111450531");
+      AVRC_TRACE_WARNING("%s: invalid parameter length %d: must be at least 1",
+                         __func__, len);
+      return AVRC_STS_INTERNAL_ERR;
+    }
     p_result->rsp.status = *p;
```
* CVE-2017-13283 RCE (Easy to exploit) - https://android.googlesource.com/platform/system/bt/+/ebc284cf3a59ee5cf7c06af88c2f3bcd0480e3e9
  - Read length from packet is not properly verified. This controls data being read into an allocation.
```
       BE_STREAM_TO_UINT8(p_result->list_app_values.num_val, p);
+      if (p_result->list_app_values.num_val > AVRC_MAX_APP_ATTR_SIZE) {
+        android_errorWriteLog(0x534e4554, "78526423");
+        p_result->list_app_values.num_val = AVRC_MAX_APP_ATTR_SIZE;
+      }
+
       for (int xx = 0; xx < p_result->list_app_values.num_val; xx++) {
        BE_STREAM_TO_UINT8(p_result->list_app_values.vals[xx], p);
      }
```

* CVE-2018-9506	ID in AVRCP - https://android.googlesource.com/platform/system/bt/+/830cb39cb2a0f1bf6704d264e2a5c5029c175dd7
  - No length check
```
+    if (p_pkt->len < AVRC_AVC_HDR_SIZE) {
+      android_errorWriteLog(0x534e4554, "111803925");
+      AVRC_TRACE_WARNING("%s: message length %d too short: must be at least %d",
+                         __func__, p_pkt->len, AVRC_AVC_HDR_SIZE);
+      osi_free(p_pkt);
+      return;
+    }
     msg.hdr.ctype = p_data[0] & AVRC_CTYPE_MASK;
```
* CVE-2018-9507	ID in AVRCP - https://android.googlesource.com/platform/system/bt/+/30cec963095366536ca0b1306089154e09bfe1a9
  - No length check
```
+        if (p_vendor->vendor_len != 5) {
+          android_errorWriteLog(0x534e4554, "111893951");
+          p_rc_rsp->get_caps.status = AVRC_STS_INTERNAL_ERR;
+          break;
+        }
         u8 = *(p_vendor->p_vendor_data + 4);
         p = p_vendor->p_vendor_data + 2;
         p_rc_rsp->get_caps.capability_id = u8;
         BE_STREAM_TO_UINT16(u16, p);
```
* CVE-2018-9450	RCE - https://android.googlesource.com/platform/system/bt/+/bc259b4926a6f9b33b9ee2c917cd83a55f360cbf
since the original packet is being reused, we are copying a certain number of bytes past the end?
not too sure about this one
```
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
```
* CVE-2018-9540	ID - "In avrc_ctrl_pars_vendor_rsp of avrc_pars_ct.c, there is a possible out of bounds read due to a missing bounds check." https://android.googlesource.com/platform/system/bt/+/99d54d0c7dbab6c80f15bbf886ed203b2a547453

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
* (CVE-2017-13266) RCE - https://android.googlesource.com/platform/system/bt/+/6ecbbc093f4383e90cbbf681cd55da1303a8ef94
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
```
* CVE-2018-9448	ID in AVRCP - https://android.googlesource.com/platform/system/bt/+/13294c70a66347c9e5d05b9f92f8ceb6fe38d7f6
  - No length check
```
+  if (p_data->p_buf->len < AVCT_HDR_LEN_SINGLE) {
+    AVCT_TRACE_WARNING("Invalid AVCTP packet length %d: must be at least %d",
+                       p_data->p_buf->len, AVCT_HDR_LEN_SINGLE);
+    osi_free_and_reset((void**)&p_data->p_buf);
+    android_errorWriteLog(0x534e4554, "79944113");
+    return;
+  }
+
   p = (uint8_t*)(p_data->p_buf + 1) + p_data->p_buf->offset;
```
* CVE-2018-9453	ID in AVDTP - https://android.googlesource.com/platform/system/bt/+/cb6a56b1d8cdab7c495ea8f53dcbdb3cfc9477d2
  - Possible RCE?
```
+        if (p + elem_len > p_end) {
+          err = AVDT_ERR_LENGTH;
+          android_errorWriteLog(0x534e4554, "78288378");
+          break;
+        }
```
