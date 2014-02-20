cs255-proj2
===========

1. How do we hide the lengths of the passwords stored in our manager?
=====================================================================

We make all encrypted password blobs the same length of 600 bytes. Since
passwords are a max of 64 bytes, HMAC(domain) = 256 bytes, and salt = 256
bytes, the maximum "real" information is 64 + 256 + 256 = 576 bytes. Thus,
if we pad all password blobs to 600 bytes before authenticated encryption,
we know that all password blobs will have the same length.


2. How do we prevent swap attacks?
==================================

We prevent swap attacks by binding each password to its domain. In our
KVS, our password entries contain both the password and the HMAC of the
domain name; these entries are then secured via authenticated
encryption. Thus, it is impossible for an attacker to modify the contents
of a password entry without breaking authenticated encryption. 
Now, for every keychain.get(domain_name) request, our password manager
checks to see if HMAC(domain_name) is contained within the decrypted password
entry. The only time this can occur (excluding negligible probability
events) is if the password entry is for the requested domain name
(otherwise the attacker can break CI for HMAC's).
Thus, because we bind each password to the HMAC of its domain in the
password entry, we are guaranteed under the security of HMAC that a
password entry must correspond to the correct domain. A swap attack
will now fail because the HMAC in the swapped password entry won't match
the domain_name's HMAC; furthermore, an attacker cannot successfully
modify this swapped password entry to make the HMAC's match up because the
password entries' integrity are guaranteed by authenticated encryption.

3. Is it necessary for a trusted location to exist against rollback
attacks in the proposed defense?
===================================================================
Yes, in the proposed defense and our implementation, a trusted location
must exist. Suppose we stored the trusted_data_check in an
insecure/untrusted location. Then an attacker can simply modify the
contents of our password manager dump, compute the new SHA-256 hash of
this modified dump, and then replace the trusted_data_check with this new
SHA hash. Anyone can compute the SHA-256 hash of anything, so this attack
is completely within the attacker's power.

4. What if we used a different MAC on the domain names to produce the keys
for the KVS. Does the scheme still satisfy the desired security
properties?
=======================================================================
It depends on the MAC. Consider the following secure MAC, GMAC(k,
domain_name) = domain_name || HMAC(k, domain_name). GMAC is secure MAC
because finding two messages that output the same GMAC tag requires
finding two messages that output the same HMAC tag (since all GMAC tags
use an HMAC output as its tag suffix). However, GMAC clearly reveals the
domain name for each password entry - which violates the security property
that the domain names should be hidden.

5. How can we reduce/completely eliminate the information leaked about the
number of records?
========================================================================
Everytime we set (add) a password entry, we can randomly decide to add a
dummy record to the password manager (i.e. securely generate a random
number from [0,1] and check if it's greater than 0.5 in keychain.set(). If
it's greater than 0.5, then we generate a random string and a random
password and add them to the password manager just like any other valid
password record). At best, the attacker knows the maximum number of
records our password manager stores under this implementation, but the
exact number of records is hidden. 