# Misc Profiles

Given bluetooth's age, there are a number of profiles that have been developed over the years to integrate devices with each other. Want to share contacts with another device? OBEX is for you. Looking to create a wireless mouse? Check out HID.

While we are on HID, I thought playing around with the HID emulator provided by btstack was pretty fun to play with (especially when you pair it with someone's computer when they walk away ;).

The exotic world of Bluetooth protocols does not stop at those which have published standards for them. Apple has a few proprietary protocols of their own.

Most of these other protocols require pairing before you can connect to them. If you are pentesting a Bluetooth stack however, you should always try to connect to them in the off case you can actually create a connection and unlock some attack surface or extract some data from the victim.

# Attack Surface
* It is probably a good idea to try to find the specification for the profile you want to find bugs in. Here Bluetooth's list of available

## CVEs
### Apple
* Low energy audio memcpy RCE from the Bluebourne paper (TODO link here)

### Android
* CVE-2018-9591	HID client ID: https://android.googlesource.com/platform/system/bt/+/e1685cfa533db4155a447c405d7065cc17af2ae9
  - send a malformed GET_IDLE command with no parameters
  - data is read out of bounds
* CVE-2018-9502	ID in RFCOMM - https://android.googlesource.com/platform/system/bt/+/92a7bf8c44a236607c146240f3c0adc1ae01fedf, https://android.googlesource.com/platform/system/bt/+/d4a34fefbf292d1e02336e4e272da3ef1e3eef85, https://android.googlesource.com/platform/system/bt/+/9fe27a9b445f7e911286ed31c1087ceac567736b
* CVE-2018-9505	ID in MCAP - https://android.googlesource.com/platform/system/bt/+/5216e6120160b28d76e9ee4dff9995e772647511
  - MCAP is actually a protocol, not a profile :/ but close enough
* CVE-2018-9480	ID in HID - https://android.googlesource.com/platform/system/bt/+/75c22982624fb530bc1d57aba6c1e46e7881d6ba
* CVE-2019-1992	UAF in Health Device Profile - https://android.googlesource.com/platform/system/bt/+/c365ae6444b86c3ddd19197fd2c787581ebb31df
