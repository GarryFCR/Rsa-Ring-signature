# RSA RING SIGNATURES SCHEME(Ongoing)

This repository contain an implementation of **RING SIGNATURES SCHEME** in Rust. The current implementation is based on the following paper:
* [How to Leak a Secret](https://www.iacr.org/archive/asiacrypt2001/22480554.pdf) by **Ronald L. Rivest, Adi Shamir, Yael Tauman Kalai**. This is the first paper which formalizes the notion of Ring Signatures.

Application layer protocol technology like CryptoNote uses Ring signatures.
Cryptocurriencies like ShadowCash and Monero uses Ring Signatures.

Ring Signatures provide an elegant way to produce a digital signature by a member from the set of possible signers, without revealing which member actually produced the signature. 
It can be used as a way to leak a secret.


Terminology:
The set of possible signers is called a Ring. The member who produces the actual signature is called a signer and others are called non-signer.

## Proposed Signature Scheme using RSA Trapdoor

**sign:** 
* Given the message m to be signed, a symmetric key k is chosen by  k = Hash(m)
* Random glue value v is chosen uniformly at random from {0,1}^b where all public key n_i are less that 2^b
* Signer picks random x_i for all other ring member except for him and calculate y_i = g(x_i) where g is a trapdoor permutation.
* The signer solves the ring equation, C_k_v(y_1, y_2, ..., y_r) = v where C_k_v is a Symmetric Key Encryption to get y_s
* Signer invert the trapdor using his secret key to get the value of x_s
* Signer will output the list of pulic keys, x_i's and the glue v

**Verify:**
* on input the public keys glue v and x_i's
Verifier will generate y_i = g(x_i) where g is trapdoor funtion.
* Verifier will obtain the key k = Hash(m)
* Verifier will verify the ring equation.
* If ring equation is satisfied, verifier will accept. Otherwise, rejects.

