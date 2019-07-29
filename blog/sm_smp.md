# SM and SMP

## SMP - Notable Features
- Capabilities and security levels

## CVEs
### Android
* CVE-2019-1991	RCE in SMP - https://android.googlesource.com/platform/system/bt/+/2d21e75aa8c1e0c4adf178a1330f9f5c573ca045
* CVE-2018-9507	ID in SMP - https://android.googlesource.com/platform/system/bt/+/e8bbf5b0889790cf8616f4004867f0ff656f0551
* CVE-2018-9509	ID in SMP - https://android.googlesource.com/platform/system/bt/+/198888b8e0163bab7a417161c63e483804ae8e31
* CVE-2018-9510	ID in SMP - https://android.googlesource.com/platform/system/bt/+/6e4b8e505173f803a5fc05abc09f64eef89dc308
* CVE-2018-9446 RCE SMP (Check p_cb->role in smp_br_state_machine_event) - https://android.googlesource.com/platform/system/bt/+/49acada519d088d8edf37e48640c76ea5c70e010
	*   if (p_cb->role > HCI_ROLE_SLAVE) { --> state_table = smp_br_state_table[curr_state][p_cb->role];
	* Attacker supplied p_cb->role had ended up being used to lookup index in smp_br_state_table, letting you specify what function you wanted to call
	* also in CVE-2018-9365 https://android.googlesource.com/platform/system/bt/+/ae94a4c333417a1829030c4d87a58ab7f1401308
* SMP use after free: https://android.googlesource.com/platform/system/bt/+/fe621261a1f66463df71cfef2bdd037374e3c6b2