# rsa_rt_server
This Rust code provides functionality for secure communication over a TCP connection using the RSA public-key encryption algorithm. The involved structures are `Message`, `EncryptAbleMessage`, `PublicRSAKey`, `PrivateRSAKey`, and `RsaKey`.

1. `Message`: This structure consists of a receiver, represented by a `PublicRSAKey`, and the encrypted part of the message, represented by a vector of `BigUint`.

2. `EncryptAbleMessage`: This structure consists of a sender, represented by a `PublicRSAKey`, and a text field. The text field must be a string with a maximum size of 1024 bits. It provides a method `encrypt` that encrypts the message text along with sender's public key information using the RSA encryption algorithm.

3. `PublicRSAKey` and `PrivateRSAKey`: These structures represent the public and private components of an RSA key pair. The `PublicRSAKey` struct has a method `to_string` that converts the public key components `public_n` and `public_e` into a string.

4. `RsaKey`: This structure combines the public and private RSA keys into a single structure.

The code establishes a TCP connection and expects to receive an RSA public key immediately. The public key should be sent in the format `big_n,big_e`, where these values are encoded as strings using the `BigUint.to_string()` method on `public_n` and `public_e`.

Once the public key is received, the server encrypts a secret message using the `rsa_encrypt_simple` function and sends it back over the socket as a sequence of bytes obtained via `BigUint.to_le_bytes()`.

The server then expects to receive the decrypted secret message. Upon receipt, the server verifies the secret message. If the decrypted message is verified successfully, the connection is maintained; otherwise, it is dropped.

Once verified, the server is ready to receive encrypted messages. These messages should be in the format `big_n,big_e-[MESSAGE]`, where `big_n,big_e` represents the recipient's public key and `[MESSAGE]` is the encrypted message text.
