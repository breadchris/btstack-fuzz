# Conclusions
* Security is hard, especially when you are implementing code to match a specification that has a number of protocols some legacy, some new.
* When you are parsing data, for the love of god, properly keep track of where you are. Linux and iOS do this well by having the position in the packet always being kept updated and checked. Android fails to do this and is the root cause of the majority of the CVEs that have been reported.

## Attack surface
* Following the guidelines put forth by NIST, a Bluetooth stack can take some steps to become secure to the passer by attacker. While a Bluetooth social engineering attack (prompting the user to pair a device) can open up the attack surface to other protocols, it does put at least some barrier to protect devices from rampantly spreading malware.

## Vulnerability Patterns
* It is important to identify vulnerability trends and cut the head off the Hydra before you have new ones. As seen in reported Bluetooth vulnerabilities in Android, the head was not cut off. You have patches which fix a vulnerability, but create a new one (BNEP UAF), lack of length checks (all the information disclosures), and overall neglect of properly checking lengths in general (AVCTP length check, the bnep off by one).
*
