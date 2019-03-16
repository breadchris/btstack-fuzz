# Bluetooth POCs

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
* ID - "In avrc_ctrl_pars_vendor_rsp of avrc_pars_ct.c, there is a possible out of bounds read due to a missing bounds check." - https://android.googlesource.com/platform/system/bt/+/99d54d0c7dbab6c80f15bbf886ed203b2a547453
* ID - https://android.googlesource.com/platform/system/bt/+/cc364611362cc5bc896b400bdc471a617d1ac628
* RCE (Easy to exploit) - https://android.googlesource.com/platform/system/bt/+/ebc284cf3a59ee5cf7c06af88c2f3bcd0480e3e9
* ID - https://android.googlesource.com/platform/system/bt/+/11fb7aa03437eccac98d90ca2de1730a02a515e2
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
* RCE SMP (Check p_cb->role in smp_br_state_machine_event) - https://android.googlesource.com/platform/system/bt/+/49acada519d088d8edf37e48640c76ea5c70e010
	*   if (p_cb->role > HCI_ROLE_SLAVE) { --> state_table = smp_br_state_table[curr_state][p_cb->role];
	* Attacker supplied p_cb->role had ended up being used to lookup index in smp_br_state_table, letting you specify what function you wanted to call
	* also in https://android.googlesource.com/platform/system/bt/+/ae94a4c333417a1829030c4d87a58ab7f1401308
* RCE - https://android.googlesource.com/platform/system/bt/+/bc259b4926a6f9b33b9ee2c917cd83a55f360cbf
* ID in BNEP - https://android.googlesource.com/platform/system/bt/+/289a49814aef7f0f0bb98aac8246080abdfeac01
* ID in BNEP - https://android.googlesource.com/platform/system/bt/+/289a49814aef7f0f0bb98aac8246080abdfeac01
* ID - https://android.googlesource.com/platform/system/bt/+/13294c70a66347c9e5d05b9f92f8ceb6fe38d7f6
* ID - https://android.googlesource.com/platform/system/bt/+/cb6a56b1d8cdab7c495ea8f53dcbdb3cfc9477d2
* l2c ble ID - https://android.googlesource.com/platform/system/bt/+/f1c2c86080bcd7b3142ff821441696fc99c2bc9a
* RCE in SDP while processing data returned when looking up records - https://android.googlesource.com/platform/system/bt/+/99a263a7f04c5c6f101388007baa18cf1e8c30bf
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
* SDP ID - https://android.googlesource.com/platform/system/bt/+/72b1cebaa9cc7ace841d887f0d4a4bf6daccde6e
* SDP RCE - https://android.googlesource.com/platform/system/bt/+/f0edf6571d2d58e66ee0b100ebe49c585d31489f
	* Integer underflow in process_service_attr_req, max_list_len is read from request
* SDP Use after free - https://android.googlesource.com/platform/system/bt/+/ec16f7d8c7e359a68ffe6b76e88add2210bf2cbd
* PAN Use after free - https://android.googlesource.com/platform/system/bt/+/08e68337a9eb45818d5a770570c8b1d15a14d904
* BNEP ID - https://android.googlesource.com/platform/system/bt/+/a50e70468c0a8d207e416e273d05a08635bdd45f
* SDP ID - https://android.googlesource.com/platform/system/bt/+/0627e76edefd948dc3efe11564d7e53d56aac80c
* bta gattc RCE - https://android.googlesource.com/platform/system/bt/+/68a1cf1a9de115b66bececf892588075595b263f

## Potential bugs
https://git.kernel.org/pub/scm/bluetooth/bluez.git/tree/src/sdpd-request.c:517 rsp_count is used in copy length
https://git.kernel.org/pub/scm/bluetooth/bluez.git/tree/src/sdpd-request.c:257 possible use after free 

