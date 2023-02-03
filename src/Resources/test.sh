#!/bin/sh

./pkitool rootca -out root.pfx -key_type rsa
./pkitool rootca -out root-pss.pfx -key_type rsa-pss
./pkitool rootca -out root-ec.pfx -key_type ecdsa

./pkitool intca -issuer root-ec.pfx -out intca-ec.pfx -key_type ecdsa

./pkitool server -issuer root.pfx -out mycert.pfx -savekey -key_type rsa
./pkitool server -issuer root.pfx -out mycert-pss.pfx -savekey -key_type rsa-pss
./pkitool server -issuer root-pss.pfx -out mycert-pss2.pfx -savekey -key_type rsa-pss
./pkitool server -issuer root-pss.pfx -out mycert-ec.pfx -savekey -key_type ecdsa

./pkitool selfserv -out self25519.pfx -key_type ed25519
./pkitool server -issuer root-ec.pfx -out mycert-ed.pfx -savekey -key_type ed25519

./pkitool client -issuer root-ec.pfx -out mycert-ec-ec.pfx -savekey -key_type ecdsa
./pkitool client -issuer root-ec.pfx -out mycert-ec-ec.pfx -renew

./pkitool user -issuer root-ec.pfx -out user.pfx -subject "My Cert" -email "me@my.net"

./pkitool crl -issuer root-pss.pfx -cert mycert-ec.cer -reason removkeyCompromiseeFromCRL
./pkitool print -crl root-pss.crl
./pkitool crl -issuer root-pss.pfx -cert mycert-ec.cer -reason removeFromCRL

./pkitool print -cert mycert-ec.cer
