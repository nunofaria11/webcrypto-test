# webcrypto-test

A webcrypto tests page.

## Dependencies:
- [webcrypto-shim.js](https://github.com/vibornoff/webcrypto-shim)
- [promise.min.js](https://github.com/lahmatiy/es6-promise-polyfill)

Test it here [https://nunofaria11.github.io/webcrypto-test](https://nunofaria11.github.io/webcrypto-test/).

## Implementations
- RSA-OAEP (SHA-256)
- Elliptic Curve Diffie-Hellman
- Elliptic Curve Diffie-Hellman + Passive Eavesdrop
- Elliptic Curve Diffie-Hellman + Active Man-in-the-middle simulation
- Shared Secret: RSASSA-PKCS1-v1_5 (SHA-256) + RSA-OAEP (SHA-1 for Safari support) + AES-CBC (length 256)