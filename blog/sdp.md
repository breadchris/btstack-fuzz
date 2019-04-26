# SDP

This is probably the most sketch protocol in Bluetooth. There is a lot going on with the protocol and it is required to be exposed to all devices so they know what applications the device has registered (e.g. can I send music to you? yes! I have AV controller!). Granted, devices that operate only with BLE do not have this since information is advertised via GATT. However, all mobile devices, cars, and things that need compatability with older protocols will be listening for SDP

## Notable Features
* The SDP `server` handles remote queries of the SDP database which contains information for all registered services for the device. For example...
* The SDP `client` performs queries and parses their response
* There are three different queries which can be performed: 
* Queries are comprised of `data elements` which are type, length, value structures (seen here: btstack sdp_util.h:105)
* The parsing is relatively complex, I think bluez's implementation is the clearest
* If a response is too big, 

## Attack Surface