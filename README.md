# PKITool
Certificate management utility

- Basic utility to create certificates
- Requires CMake (https://cmake.org)
- Requires Conan (https://conan.io)

Setup, run before opening VS Code
- conan remote add conancenter https://center.conan.io 
- conan profile detect  <- Must run once, before the following
- ./configure.sh  (executes the following)
  - rm -rf ./build CMakeUserPresets.json
  - conan install . -r conancenter --build missing -s build_type=Debug
  - conan install . -r conancenter --build missing -s build_type=Release
  - cmake --preset conan-debug
  - cmake --preset conan-release



Building - CLI
- cmake --build --preset conan-debug
- cmake --build --preset conan-release


Usage examples:

```
========================================================================
PKITool - version 5.2.1
========================================================================

Usage: pkitool [ rootca|intca|user|client|server|selfserv|crl ] [ -options ]

rootca          Root ca cert generation.
intca           Intermediate ca cert generation.
user            User (end entity for any purpose) cert generation.
client          Client cert generation.
server          Server cert generation.
selfserv        Self-signed server cert generation.
crl             Certificate revocation list (CRL) generation / update.
print           Print the contents of a .cer file

-out            Output pfx file for saved cert.
-issuer         Input pfx file for issuer cert to sign with.
-subject        Subject name string [ default:<filename> ].
-email          Email address [ default:<none> ].
-password       Password phrase for pfx used or saved [ default:test ].
-days           Validity days, like 365, 730 [ default:396 ].
-key_type       rsa, rsa-pss, ecdsa, ed25519, ed448 [ default:ecdsa ].
-rsa_size       Key size in bits, like 512, 1024, 2048, 4096 [ default:1024 ].
-ec_curve       ECDSA curve for Suite B.  p256/p384 [ default:p256 ].
-sig_hash       Signature hash, default for RSA is sha256, for ECDSA is based on key size.
-cert           .cer file to be revoked (or unrevoked using removeFromCRL).
-reason         Reason for revocation.
-req            Certificate Request (CSR) file to use (PEM format).
-savekey        Save private key in .key file.
-der            Save .cer/.key file in DER format instead of base64.
-renew          Renew existing .pfx
-config         Location of config file (default is ./pkitool.ini)

Examples:
        pkitool rootca -out rootca.pfx -subject "My Root CA"
        pkitool intca -issuer rootca.pfx -out intca.pfx -subject "My Int CA"
        pkitool user -issuer intca.pfx -out user.pfx -subject "My Cert" -email "me@my.net"
        pkitool client -issuer intca.pfx -out client.pfx -subject "My Client Cert"
        pkitool server -issuer intca.pfx -out server.pfx -subject "My Server Cert"
        pkitool server -issuer intca.pfx -req csr.pem -out server.pfx -subject "My Server Cert"
        pkitool selfserv -out selfserv.pfx  -subject "My Server Cert"
        pkitool crl -issuer intca.pfx -cert client.cer -reason keyCompromise
        pkitool print -cert client.cer
        pkitool user -issuer intca.pfx -out user.pfx -renew
        pkitool rootca -out rootca.pfx -renew

Notes:  1. pkitool.ini is the configuration file for cert details.
        2. Revocation reasons: unspecified, keyCompromise, cACompromise,
           affiliationChanged, superseded, cessationOfOperation, certificateHold,

========================================================================
```

  
