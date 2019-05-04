# AVRCP and AVTDP

## Notable Features
* Controls audio

## CVEs
### Android
* CVE-2019-1996	ACRCP ID: https://android.googlesource.com/platform/system/bt/+/525bdbd6e1295ed8a081d2ae87105c64d6f1ac4f
* CVE-2018-9588	AVDP ID: https://android.googlesource.com/platform/system/bt/+/bf9ff0c5215861ab673e211cd06e009f3157aab2
* CVE-2018-9542	ID in AVRCP - https://android.googlesource.com/platform/system/bt/+/cc364611362cc5bc896b400bdc471a617d1ac628
* CVE-2017-13283 RCE (Easy to exploit) - https://android.googlesource.com/platform/system/bt/+/ebc284cf3a59ee5cf7c06af88c2f3bcd0480e3e9

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

* CVE-2018-9506	ID in AVRCP - https://android.googlesource.com/platform/system/bt/+/830cb39cb2a0f1bf6704d264e2a5c5029c175dd7
* CVE-2018-9507	ID in AVRCP - https://android.googlesource.com/platform/system/bt/+/30cec963095366536ca0b1306089154e09bfe1a9
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
* CVE-2018-9453	ID in AVDTP - https://android.googlesource.com/platform/system/bt/+/cb6a56b1d8cdab7c495ea8f53dcbdb3cfc9477d2