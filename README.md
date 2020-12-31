# pasteme-wasm

A set of functions built in golang, used on paste.me live!

The wasm binary was created as a replacement for the crypto functions provided by javascript.

The binary provides functions for text encryption, file encryption, also the decryption of these texts and files.

Alongside now the binary supports generating a password hash using bcrypt with a default cost. This feature is used on paste.me
to provide the password protected pastes in a correct manner, securely.

This is included as part of the frontend functionality!
