Bluetooth Blog Posts
* Different bluetooth stacks
  - Find where I wrote them down
* Previous research
  - Mike Ryan
  - Model based fuzzing talk !!!
  - Bluebourne
  - Bluedroid Jai talk -> super cool bugs
  - Some dude on twitter
* Research approach
  - Learn as much as I can about bluetooth
  - Try to find bugs (use some tools like Infer)
  - Use Frida to play with iOS bluetooth stack (and call cool debug functions)
  - Bluez is nice, but needed something simpler for playing with complex protocol lengths (btstack)
  - Attack surface for various stacks and their impact
    --> TODO
* POCs
  - Wormable Android POC for various vulns
  - iOS bug from earlier?
  - Bluetooth pineapple POC?
  - Bluetooth scanning app (BREDR/LE)
* Aside: Getting debug symbols for Android bluetooth stack
  - Compile AOSP (WSL fixes)
  - Get source
  - Some helpful scripts for debugging
  - Try to replace bluetooth.so with this?
* HCI
  - SCO/Other thing?
  - Handles
  - Commands
  - Scapy: https://sourcegraph.com/github.com/secdev/scapy/-/blob/scapy/layers/bluetooth.py#L155
  - btstack: https://sourcegraph.com/github.com/bluekitchen/btstack/-/blob/src/hci.c
* GAP
  - Device discovery
  - BLE has different address types (private vs public)
* L2CAP
  - BREDR/LE
  - Packet reassembly
  - Static vs dynamic channels
  - Config Commands (Android bugs)
  - Security modes and io-capabilities
  - btstack: https://sourcegraph.com/github.com/bluekitchen/btstack/-/blob/src/l2cap.c
* SDP
  - Service Discovery
  - Continuation state
* SMP/SM
  - BREDR/LE
  - Encryption types
  - That android bug with indexing role array
  - Encryption fails: https://github.com/mikeryan/crackle, https://blog.trailofbits.com/2018/08/01/bluetooth-invalid-curve-points/
* GATT/ATT
* BNEP/PANU
  - Ethernet packets
  - Extension bit
  - PANU built on top of BNEP
    - setup different roles (Android Pineapple)
* AVRCP/AVTDP
  - Audio controller
  - So many Android bugs
* HID
* OBEX

## Random Code
iOS Setting up LEAP layer

```
signed __int64 __fastcall setup_lea_layer(__int64 callbaks)
{
  signed __int64 v2; // x20@2
  _QWORD *profile_alloc; // x8@5
  __int64 v5; // x19@10

  if ( lea_mother )
    return 119LL;
  profile_alloc = do_malloc(0x18uLL);
  lea_mother = (__int64)profile_alloc;
  if ( !profile_alloc )
    return 106LL;
  v2 = oi_channel_manager_register_callback(0x2ALL, 2, 10LL, 10LL, profile_alloc, (__int64)lea_handle_data);
  if ( (_DWORD)v2 )
  {
    do_free((void *)lea_mother);
    lea_mother = 0LL;
    return v2;
  }
  if ( !(unsigned int)oi_channel_manager_register_callback(
                        0x2BLL,
                        2,
                        10LL,
                        10LL,
                        (_QWORD *)(lea_mother + 8),
                        (__int64)lea_handle_something) )
  {
    v2 = 0LL;
    *(_QWORD *)(lea_mother + 16) = callbaks;
    return v2;
  }
  v5 = do_some_other_setup(*(int **)lea_mother);
  do_free((void *)lea_mother);
  lea_mother = 0LL;
  return v5;
}
```

Frida scripts for iOS
```
var base_addr = Process.findModuleByName("bluetoothd").base;
var do_stack_dump = new NativeFunction(base_addr.add(0x17C6D4), 'void', ['int']);
do_stack_dump(9000);
```

iOS Stack Dump
```
default	15:29:02.874229 -0700	bluetoothd	------------------------- Stack Dump reason:  STATUS 9000 (9000) ------------------------------
default	15:29:02.876757 -0700	bluetoothd	LE_GAP:
default	15:29:02.876919 -0700	bluetoothd	supportedStates:FF FF FF FF FF 03 00 00 ADFlags:0000001A LeRoles:0000000C LeCurrentAddressType:00000003 discoveryType:00000002
default	15:29:02.877118 -0700	bluetoothd	gPeripheralPrivacyFlagEnabled:00000001 gLeBondable:00000001 gAutoAddressRefresh:00000001
default	15:29:02.877306 -0700	bluetoothd	LE_Connection:
default	15:29:02.877559 -0700	bluetoothd	lConnectionInProgress:00000000 lCancelConnectionInProgress:00000000 lRestartConnectionInProgress:00000000
default	15:29:02.878789 -0700	bluetoothd	ConnectionInProgressStruct: directed: address:(null) scanInterval:0142ED84 scanWin:00000030 connectionInt:00000030 ConnectionLatency:00000014 supervisionTO:00000000 CELen:00000048
default	15:29:02.878948 -0700	bluetoothd	Local EDL support: maxTxOctets 27, maxTxTime 328, maxRxOctets 27, maxRxTime 328
default	15:29:02.879157 -0700	bluetoothd	LE_Advertising:
default	15:29:02.881043 -0700	bluetoothd	gNumOfAdvHandles=2 gInitMultiAdvCb=012BC054 nonConnectableAddress=0E:D7:3D:D6:89:B2 addresstype=1 currentHandle=0
default	15:29:02.881202 -0700	bluetoothd	advertisingParams for handle 0 :
default	15:29:02.881448 -0700	bluetoothd		intervalMin=432 intervalMax=432 type=0 channelMap=7 state=2
default	15:29:02.881646 -0700	bluetoothd		data:02 01 1A 0A FF 4C 00 10 05 07 1C D0 E4 A0
default	15:29:02.881840 -0700	bluetoothd		scanRsp:
default	15:29:02.881973 -0700	bluetoothd	advertisingParams for handle 1 :
default	15:29:02.882150 -0700	bluetoothd		intervalMin=0 intervalMax=0 type=0 channelMap=0 state=0
default	15:29:02.882308 -0700	bluetoothd		data:
default	15:29:02.882515 -0700	bluetoothd		scanRsp:
default	15:29:02.882686 -0700	bluetoothd	BT_CL Peers (lNbPeers=0:
default	15:29:02.882896 -0700	bluetoothd	BT_CL LocalServices (lNbServices=4:
default	15:29:02.883114 -0700	bluetoothd		LocalService 0 : name=com.apple.BT.TS serviceType=2 requiresEnc=1 serviceID=1 priority=10 unpublishing=0 useErtm=1 useFCS=0 callbacks=0x000000016F504E60
default	15:29:02.883271 -0700	bluetoothd		LocalService 1 : name=com.apple.sharing serviceType=0 requiresEnc=1 serviceID=2 priority=6 unpublishing=0 useErtm=1 useFCS=0 callbacks=0x000000016F504E60
default	15:29:02.883467 -0700	bluetoothd		LocalService 2 : name=com.apple.BTLEServer.classic serviceType=1 requiresEnc=1 serviceID=3 priority=6 unpublishing=0 useErtm=1 useFCS=0 callbacks=0x000000016F504E60
default	15:29:02.887384 -0700	bluetoothd	Transport Switch: lNbTsPeers 0
default	15:29:02.887705 -0700	bluetoothd	No Transport Switching.
default	15:29:02.887837 -0700	bluetoothd
secmgrState: SEC_ST_IDLE
default	15:29:02.887934 -0700	bluetoothd	bondable: TRUE
default	15:29:02.888098 -0700	bluetoothd	Connections known to secmgr: 0
default	15:29:02.888527 -0700	bluetoothd	Pending Enforcement Req: 00:00:00:00:00:00, cb 00000000, cookie 00000000, incoming 0
default	15:29:02.888617 -0700	bluetoothd
default	15:29:02.888744 -0700	bluetoothd	L2CAP Queue states :
default	15:29:02.888897 -0700	bluetoothd		running = 0x00000001
default	15:29:02.889026 -0700	bluetoothd		nbQueues = 9
default	15:29:02.889163 -0700	bluetoothd		queues = 0x000000012C000770
default	15:29:02.889308 -0700	bluetoothd		fragmentedQueue = 0x000000012C000740
default	15:29:02.889397 -0700	bluetoothd	TxQ State: EMPTY
default	15:29:02.889562 -0700	bluetoothd	L2CAP Queues :
default	15:29:02.889650 -0700	bluetoothd		 cid : 0x00000001, address 0x000000012C000770
default	15:29:02.889741 -0700	bluetoothd			 stalled : No
default	15:29:02.889832 -0700	bluetoothd			 retransmitEnabled : No
default	15:29:02.889983 -0700	bluetoothd			 maxPackets : 48
default	15:29:02.890124 -0700	bluetoothd			 priority : 10
default	15:29:02.890214 -0700	bluetoothd			 transport : 0x000000FF
default	15:29:02.890371 -0700	bluetoothd			 readyForTx : Yes
default	15:29:02.890514 -0700	bluetoothd			 packetSent : 0x0109A2A4
default	15:29:02.890657 -0700	bluetoothd			 nextQueue : 0x2C002610
default	15:29:02.890744 -0700	bluetoothd			 previousQueue : 0x2C000800
default	15:29:02.891106 -0700	bluetoothd			 dataQueues : 0x000000012C0007D0
default	15:29:02.891228 -0700	bluetoothd		 cid : 0x0000002A, address 0x000000012C002610
default	15:29:02.891296 -0700	bluetoothd			 stalled : No
default	15:29:02.891425 -0700	bluetoothd			 retransmitEnabled : No
default	15:29:02.891564 -0700	bluetoothd			 maxPackets : 10
default	15:29:02.891696 -0700	bluetoothd			 priority : 10
default	15:29:02.891781 -0700	bluetoothd			 transport : 0x000000FF
default	15:29:02.891949 -0700	bluetoothd			 readyForTx : Yes
default	15:29:02.892219 -0700	bluetoothd			 packetSent : 0x0109A2A4
default	15:29:02.892578 -0700	bluetoothd			 nextQueue : 0x2C0026C0
default	15:29:02.892716 -0700	bluetoothd			 previousQueue : 0x2C000770
default	15:29:02.892862 -0700	bluetoothd			 dataQueues : 0x000000012C002670
default	15:29:02.893020 -0700	bluetoothd		 cid : 0x0000002B, address 0x000000012C0026C0
default	15:29:02.893174 -0700	bluetoothd			 stalled : No
default	15:29:02.893268 -0700	bluetoothd			 retransmitEnabled : No
default	15:29:02.894135 -0700	bluetoothd			 maxPackets : 10
default	15:29:02.894226 -0700	bluetoothd			 priority : 10
default	15:29:02.894397 -0700	bluetoothd			 transport : 0x000000FF
default	15:29:02.894485 -0700	bluetoothd			 readyForTx : Yes
default	15:29:02.894591 -0700	bluetoothd			 packetSent : 0x0109A2A4
default	15:29:02.894708 -0700	bluetoothd			 nextQueue : 0x29F003A0
default	15:29:02.894832 -0700	bluetoothd			 previousQueue : 0x2C002610
default	15:29:02.894948 -0700	bluetoothd			 dataQueues : 0x000000012C002720
default	15:29:02.895034 -0700	bluetoothd		 cid : 0x00000006, address 0x0000000129F003A0
default	15:29:02.895160 -0700	bluetoothd			 stalled : No
default	15:29:02.895357 -0700	bluetoothd			 retransmitEnabled : No
default	15:29:02.895444 -0700	bluetoothd			 maxPackets : 8
default	15:29:02.895637 -0700	bluetoothd			 priority : 8
default	15:29:02.895726 -0700	bluetoothd			 transport : 0x000000FF
default	15:29:02.895880 -0700	bluetoothd			 readyForTx : Yes
default	15:29:02.896027 -0700	bluetoothd			 packetSent : 0x0109A2A4
default	15:29:02.896167 -0700	bluetoothd			 nextQueue : 0x29F01320
default	15:29:02.896399 -0700	bluetoothd			 previousQueue : 0x2C0026C0
default	15:29:02.896511 -0700	bluetoothd			 dataQueues : 0x0000000129F00400
default	15:29:02.896654 -0700	bluetoothd		 cid : 0x0000003A, address 0x0000000129F01320
default	15:29:02.896763 -0700	bluetoothd			 stalled : No
default	15:29:02.896888 -0700	bluetoothd			 retransmitEnabled : No
default	15:29:02.897042 -0700	bluetoothd			 maxPackets : 16
default	15:29:02.897228 -0700	bluetoothd			 priority : 8
default	15:29:02.897342 -0700	bluetoothd			 transport : 0x000000FF
default	15:29:02.897483 -0700	bluetoothd			 readyForTx : Yes
default	15:29:02.897644 -0700	bluetoothd			 packetSent : 0x0109A2A4
default	15:29:02.897731 -0700	bluetoothd			 nextQueue : 0x29F004A0
default	15:29:02.897821 -0700	bluetoothd			 previousQueue : 0x29F003A0
default	15:29:02.897930 -0700	bluetoothd			 dataQueues : 0x0000000129F01380
default	15:29:02.898091 -0700	bluetoothd		 cid : 0x00000030, address 0x0000000129F004A0
default	15:29:02.898263 -0700	bluetoothd			 stalled : No
default	15:29:02.898422 -0700	bluetoothd			 retransmitEnabled : No
default	15:29:02.898520 -0700	bluetoothd			 maxPackets : 8
default	15:29:02.898671 -0700	bluetoothd			 priority : 7
default	15:29:02.898758 -0700	bluetoothd			 transport : 0x000000FF
default	15:29:02.898916 -0700	bluetoothd			 readyForTx : Yes
default	15:29:02.899017 -0700	bluetoothd			 packetSent : 0x0109A2A4
default	15:29:02.899162 -0700	bluetoothd			 nextQueue : 0x2C000920
default	15:29:02.899661 -0700	bluetoothd			 previousQueue : 0x29F01320
default	15:29:02.899798 -0700	bluetoothd			 dataQueues : 0x0000000129F00450
default	15:29:02.899888 -0700	bluetoothd		 cid : 0x00000005, address 0x000000012C000920
default	15:29:02.900043 -0700	bluetoothd			 stalled : No
default	15:29:02.900137 -0700	bluetoothd			 retransmitEnabled : No
default	15:29:02.900332 -0700	bluetoothd			 maxPackets : 6
default	15:29:02.900463 -0700	bluetoothd			 priority : 3
default	15:29:02.900552 -0700	bluetoothd			 transport : 0x000000FF
default	15:29:02.900691 -0700	bluetoothd			 readyForTx : Yes
default	15:29:02.900850 -0700	bluetoothd			 packetSent : 0x0109A2A4
default	15:29:02.900988 -0700	bluetoothd			 nextQueue : 0x2C002770
default	15:29:02.901101 -0700	bluetoothd			 previousQueue : 0x29F004A0
default	15:29:02.901241 -0700	bluetoothd			 dataQueues : 0x000000012C000980
default	15:29:02.901383 -0700	bluetoothd		 cid : 0x00000004, address 0x000000012C002770
default	15:29:02.901510 -0700	bluetoothd			 stalled : No
default	15:29:02.901624 -0700	bluetoothd			 retransmitEnabled : No
default	15:29:02.901778 -0700	bluetoothd			 maxPackets : 16
default	15:29:02.901878 -0700	bluetoothd			 priority : 3
default	15:29:02.901983 -0700	bluetoothd			 transport : 0x000000FF
default	15:29:02.902092 -0700	bluetoothd			 readyForTx : Yes
default	15:29:02.902237 -0700	bluetoothd			 packetSent : 0x0109A2A4
default	15:29:02.902375 -0700	bluetoothd			 nextQueue : 0x2C000800
default	15:29:02.902524 -0700	bluetoothd			 previousQueue : 0x2C000920
default	15:29:02.902619 -0700	bluetoothd			 dataQueues : 0x000000012C0027D0
default	15:29:02.902794 -0700	bluetoothd		 cid : 0x00000002, address 0x000000012C000800
default	15:29:02.902944 -0700	bluetoothd			 stalled : No
default	15:29:02.903038 -0700	bluetoothd			 retransmitEnabled : No
default	15:29:02.903193 -0700	bluetoothd			 maxPackets : 5
default	15:29:02.903295 -0700	bluetoothd			 priority : 1
default	15:29:02.903441 -0700	bluetoothd			 transport : 0x000000FF
default	15:29:02.903547 -0700	bluetoothd			 readyForTx : Yes
default	15:29:02.903679 -0700	bluetoothd			 packetSent : 0x0109A2A4
default	15:29:02.903837 -0700	bluetoothd			 nextQueue : 0x2C000770
default	15:29:02.903926 -0700	bluetoothd			 previousQueue : 0x2C002770
default	15:29:02.904067 -0700	bluetoothd			 dataQueues : 0x000000012C000860
default	15:29:02.904182 -0700	bluetoothd	Fragmented Queue : 0x000000012C000740
default	15:29:02.904321 -0700	bluetoothd	L2CAP data dump:
default	15:29:02.904437 -0700	bluetoothd	FX
default	15:29:02.904576 -0700	bluetoothd	cid=0x00000005
default	15:29:02.904688 -0700	bluetoothd	mtu=23
default	15:29:02.904811 -0700	bluetoothd	flushTO=65535
default	15:29:02.904937 -0700	bluetoothd	L2CAP basic mode
default	15:29:02.905051 -0700	bluetoothd
default	15:29:02.905192 -0700	bluetoothd	FX
default	15:29:02.905281 -0700	bluetoothd	cid=0x00000006
default	15:29:02.905408 -0700	bluetoothd	mtu=65
default	15:29:02.905514 -0700	bluetoothd	flushTO=65535
default	15:29:02.905658 -0700	bluetoothd	L2CAP basic mode
default	15:29:02.905761 -0700	bluetoothd
default	15:29:02.905884 -0700	bluetoothd	FX
default	15:29:02.906023 -0700	bluetoothd	cid=0x00000030
default	15:29:02.906117 -0700	bluetoothd	mtu=100
default	15:29:02.906217 -0700	bluetoothd	flushTO=65535
default	15:29:02.906363 -0700	bluetoothd	L2CAP basic mode
default	15:29:02.906498 -0700	bluetoothd
default	15:29:02.906628 -0700	bluetoothd	FX
default	15:29:02.906701 -0700	bluetoothd	cid=0x0000002A
default	15:29:02.906850 -0700	bluetoothd	mtu=672
default	15:29:02.906921 -0700	bluetoothd	flushTO=65535
default	15:29:02.907046 -0700	bluetoothd	L2CAP basic mode
default	15:29:02.907111 -0700	bluetoothd
default	15:29:02.907365 -0700	bluetoothd	FX
default	15:29:02.907467 -0700	bluetoothd	cid=0x0000002B
default	15:29:02.907533 -0700	bluetoothd	mtu=672
default	15:29:02.907634 -0700	bluetoothd	flushTO=65535
default	15:29:02.907700 -0700	bluetoothd	L2CAP basic mode
default	15:29:02.907769 -0700	bluetoothd
default	15:29:02.907834 -0700	bluetoothd	FX
default	15:29:02.907954 -0700	bluetoothd	cid=0x00000004
default	15:29:02.908031 -0700	bluetoothd	mtu=527
default	15:29:02.908100 -0700	bluetoothd	flushTO=65535
default	15:29:02.908166 -0700	bluetoothd	L2CAP basic mode
default	15:29:02.908285 -0700	bluetoothd
default	15:29:02.908369 -0700	bluetoothd	FX
default	15:29:02.908486 -0700	bluetoothd	cid=0x0000003A
default	15:29:02.908573 -0700	bluetoothd	mtu=672
default	15:29:02.909269 -0700	bluetoothd	flushTO=65535
default	15:29:02.909348 -0700	bluetoothd	L2CAP basic mode
default	15:29:02.909470 -0700	bluetoothd
default	15:29:02.909556 -0700	bluetoothd	7 channels in use
default	15:29:02.909659 -0700	bluetoothd	L2CAP data dump:
default	15:29:02.909748 -0700	bluetoothd	FX
default	15:29:02.909843 -0700	bluetoothd	cid=0x00000005
default	15:29:02.909909 -0700	bluetoothd	mtu=23
default	15:29:02.910004 -0700	bluetoothd	flushTO=65535
default	15:29:02.910151 -0700	bluetoothd	L2CAP basic mode
default	15:29:02.910277 -0700	bluetoothd
default	15:29:02.910342 -0700	bluetoothd	FX
default	15:29:02.910408 -0700	bluetoothd	cid=0x00000006
default	15:29:02.910550 -0700	bluetoothd	mtu=65
default	15:29:02.910624 -0700	bluetoothd	flushTO=65535
default	15:29:02.910723 -0700	bluetoothd	L2CAP basic mode
default	15:29:02.910861 -0700	bluetoothd
default	15:29:02.910926 -0700	bluetoothd	FX
default	15:29:02.910995 -0700	bluetoothd	cid=0x00000030
default	15:29:02.911108 -0700	bluetoothd	mtu=100
default	15:29:02.911247 -0700	bluetoothd	flushTO=65535
default	15:29:02.911313 -0700	bluetoothd	L2CAP basic mode
default	15:29:02.911417 -0700	bluetoothd
default	15:29:02.911535 -0700	bluetoothd	FX
default	15:29:02.911657 -0700	bluetoothd	cid=0x0000002A
default	15:29:02.911729 -0700	bluetoothd	mtu=672
default	15:29:02.911823 -0700	bluetoothd	flushTO=65535
default	15:29:02.911899 -0700	bluetoothd	L2CAP basic mode
default	15:29:02.911968 -0700	bluetoothd
default	15:29:02.912034 -0700	bluetoothd	FX
default	15:29:02.912124 -0700	bluetoothd	cid=0x0000002B
default	15:29:02.912242 -0700	bluetoothd	mtu=672
default	15:29:02.912329 -0700	bluetoothd	flushTO=65535
default	15:29:02.912415 -0700	bluetoothd	L2CAP basic mode
default	15:29:02.912533 -0700	bluetoothd
default	15:29:02.912617 -0700	bluetoothd	FX
default	15:29:02.912712 -0700	bluetoothd	cid=0x00000004
default	15:29:02.912797 -0700	bluetoothd	mtu=527
default	15:29:02.912882 -0700	bluetoothd	flushTO=65535
default	15:29:02.912949 -0700	bluetoothd	L2CAP basic mode
default	15:29:02.913028 -0700	bluetoothd
default	15:29:02.913150 -0700	bluetoothd	FX
default	15:29:02.913218 -0700	bluetoothd	cid=0x0000003A
default	15:29:02.913312 -0700	bluetoothd	mtu=672
default	15:29:02.913417 -0700	bluetoothd	flushTO=65535
default	15:29:02.913502 -0700	bluetoothd	L2CAP basic mode
default	15:29:02.913619 -0700	bluetoothd
default	15:29:02.913688 -0700	bluetoothd	7 channels in use
default	15:29:02.913804 -0700	bluetoothd	RequestQueue: empty
default	15:29:02.913919 -0700	bluetoothd	Current Request: none
default	15:29:02.914026 -0700	bluetoothd	HciCmdQueue:
default	15:29:02.914106 -0700	bluetoothd	   0 cmds queued:
default	15:29:02.914174 -0700	bluetoothd	   queueHighWaterMark = 3
default	15:29:02.914313 -0700	bluetoothd	   Command Transport Ready = TRUE
default	15:29:02.914381 -0700	bluetoothd	   OI_HCIFlow_NumCmdPktsAllowed = 1
default	15:29:02.914474 -0700	bluetoothd	HciFlow - txFlowControl
default	15:29:02.914588 -0700	bluetoothd	   gAssertOnControllerFlowPRoblems  = 0
default	15:29:02.914709 -0700	bluetoothd	   MaxAclDataPacketSize			= 1021
default	15:29:02.914793 -0700	bluetoothd	   MaxScoDataPacketSize			= 192
default	15:29:02.914903 -0700	bluetoothd	   MaxLeDataPacketSize			= 27
default	15:29:02.914985 -0700	bluetoothd	   sharedACLandLEbuffers     	= FALSE
default	15:29:02.915106 -0700	bluetoothd	   totalNumOutstandingTransmits	= 0
default	15:29:02.915190 -0700	bluetoothd	   totalNumAclSlots				= 8
default	15:29:02.915270 -0700	bluetoothd	   totalNumScoSlots				= 1
default	15:29:02.915560 -0700	bluetoothd	   totalNumLeSlots				= 15
default	15:29:02.915641 -0700	bluetoothd	   curNumAclSlotsAvail			= 8
default	15:29:02.915736 -0700	bluetoothd	   curNumLeSlotsAvail			= 15
default	15:29:02.915861 -0700	bluetoothd	   aclTransportReady				= TRUE
default	15:29:02.915943 -0700	bluetoothd	   scoTransportReady				= TRUE
default	15:29:02.916059 -0700	bluetoothd	   leTransportReady				= TRUE
default	15:29:02.916141 -0700	bluetoothd	   needScoBuffers				= 0
default	15:29:02.916260 -0700	bluetoothd	   _OI_HCIAPI_ReadyToTransmitLe  = 1
default	15:29:02.916341 -0700	bluetoothd	   _OI_HCIAPI_ReadyToTransmitAcl  = 1
default	15:29:02.916456 -0700	bluetoothd	   _OI_HCIAPI_ReadyToTransmitOther  = 1
default	15:29:02.916911 -0700	bluetoothd	HciFlow - aclRxFlowControl not enabled
default	15:29:02.916994 -0700	bluetoothd	HciFlow - scoRxFlowControl not enabled
default	15:29:02.917062 -0700	bluetoothd	HciFlow - leRxFlowControl not enabled
default	15:29:02.917140 -0700	bluetoothd	pcie_dump_state: [START]
default	15:29:02.917206 -0700	bluetoothd	pcie_dump_state: [END]
default	15:29:03.050784 -0700	bluetoothd	Discovered device <private>
default	15:29:03.051986 -0700	bluetoothd	HandsfreeService supports device <private>
default	15:29:03.052112 -0700	bluetoothd	A2DPService supports device <private>
```
