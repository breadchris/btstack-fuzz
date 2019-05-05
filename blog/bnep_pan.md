# BNEP and PAN

## Notable Features
### BNEP
* Extension bits

### PAN
* Different roles PANU, NU

## Attack Surface
* 

## CVEs
* CVE-2017-0782	(Add a missing check for PAN buffer size before copying data): https://android.googlesource.com/platform/system/bt/+/4e47f3db62bab524946c46efe04ed6a2b896b150 and (Add missing extension length check while parsing BNEP control packets
): https://android.googlesource.com/platform/system/bt/+/c568fa9088ded964e0ac99db236e612de5d82177
* CVE-2017-0783	(Disable PAN Reverse Tethering when connection originated by the Remote): https://android.googlesource.com/platform/system/bt/+/1e77fefc8b9c832239e1b32c6a6880376065e24e
* PAN Use after free - https://android.googlesource.com/platform/system/bt/+/08e68337a9eb45818d5a770570c8b1d15a14d904
* BNEP ID - https://android.googlesource.com/platform/system/bt/+/a50e70468c0a8d207e416e273d05a08635bdd45f
* CVE-2018-9436	ID in BNEP - https://android.googlesource.com/platform/system/bt/+/289a49814aef7f0f0bb98aac8246080abdfeac01
* CVE-2018-9356	RCE in PAN - https://android.googlesource.com/platform/system/bt/+/d7d4d5686b2e3c37c7bf10a6a2adff1c95251a13

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

* CVE-2018-9357 RCE in BNEP - https://android.googlesource.com/platform/system/bt/+/9164ee1aaf3609b4771d39302e3af649f44c9e66
	* BNEP_Write -> if (new_len > org_len) return BNEP_IGNORE_CMD; were placed because extension bit could let you make big writes