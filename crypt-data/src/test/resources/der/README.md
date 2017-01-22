The file private.pem is generated with the following command:
```
# openssl rsa -inform DER -outform PEM -in private.der -out private.pem
```
this is the same output with the following command:
```
openssl rsa -inform PEM -outform PEM -in keypair.pem -out private.pem
```