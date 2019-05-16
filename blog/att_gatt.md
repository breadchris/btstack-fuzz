# ATT and GATT

## Notable features
* ATT and GATT are kind of tied into each other
* It is basically a glorified database which uses UUIDs to identify elements to read and/or write
* Service, characteristics, attributes

## Attack surface
* The code for each off the different actions is relatively limited in what it does (hence the "low energy"). So for as far as exploiting the GATT protocol, there is litttle room for vulnerabilities to be introduced.
* There is a lot of research published on exploiting applications which use GATT (bleah) by identifying information that is exposed and properties that are able to be written to.

## CVEs

### Android
* CVE-2017-13160 bta gattc Priv esc? - https://android.googlesource.com/platform/system/bt/+/68a1cf1a9de115b66bececf892588075595b263f
  - Loads GATT cache with incorrect size
* CVE-2018-9358	UNUSED_ATTR in length for gatt - https://android.googlesource.com/platform/system/bt/+/0d7c2f5a14d1055f3b4f69035451c66bf8f1b08e
  - len is not used
```
+  if (len < sizeof(flag)) {
+    android_errorWriteLog(0x534e4554, "73172115");
+    LOG(ERROR) << __func__ << "invalid length";
+    gatt_send_error_rsp(tcb, GATT_INVALID_PDU, GATT_REQ_EXEC_WRITE, 0, false);
+    return;
+  }
+
   STREAM_TO_UINT8(flag, p);
```
