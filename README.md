
# Data encryption standard (DES)[![GPLv3 License](https://img.shields.io/badge/License-GPL%20v3-yellow.svg)](https://opensource.org/licenses/)

The Advanced encryption standard (AES) coded in python as a proof of concept.





## Usage/Examples
Clone the project

```bash
  git clone https://github.com/TJulesL/Data-Encryption-Standard.git
```

Go to the project directory

```bash
  cd Data-Encryption-Standard
```

Execute the file

```bash
  python3 DES-encryption.py
```

## Features

- DES Cipher
- ECB encryption



## Sources

 - [DES encryption on wikipedia](https://en.wikipedia.org/wiki/Data_Encryption_Standard)
 - [DES modes of operation on wikipedia](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation)
- [Feistel network](https://en.wikipedia.org/wiki/Feistel_network)
## Authors

- [@TJulesL](https://www.github.com/TJulesL)


## FAQ

#### Where is the decryption?

The decryption function is not implemented however if you want to do it yourself it is very easy to do since you only need to reverse the [feistel network](https://en.wikipedia.org/wiki/Feistel_network). At the time of writing this i will not implement it in the future since the project was more of a way to show how the feistel network works, and if really needed people can implement the decryption function themselves pretty easily building on this repository's code.

#### Is this code safe to use for encrypting sensitive data?

Short answer : No, not at all

Long answer : The DES cipher in itself is safe to use for encryption however since this code uses the ECB mode it is not safe for encrypting data because it will reveal patterns in some data. There are other [modes of operation](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation) however they are not added yet to the code.

