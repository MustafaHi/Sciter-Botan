# Sciter-Botan

Sciter binding for [Botan cryptography library](https://github.com/randombit/botan)


> Version : 2.0  
> [API / Usage Guide](https://github.com/MustafaHi/Sciter-Botan/wiki/API)  
> [Setup Guide](https://github.com/MustafaHi/Sciter-Botan/wiki/Setup)  
> [Change Log & Features](https://github.com/MustafaHi/Sciter-Botan/wiki/Change-log-&-Features)  
> [Dev Guide](https://github.com/MustafaHi/Sciter-Botan/wiki/Dev-Guide)  
> More information in the [wiki](https://github.com/MustafaHi/Sciter-Botan/wiki)  

Provide easy to use API for Botan to Sciter's script

```js
var key = Botan.hash("SHA-256", "secret");
var data = "will be secret";

const crypto = await Botan.cipher("AES-256/CBC", data, key);
// returns Object with Data and IV(nonce)

crypto.data
// hex code of the encrypted data

crypto.iv
// IV(nonce) used for encryption
```

And to decrypt that data

```js
const decrypt = await Botan.decipher("AES-256/CBC", crypto.data, key, crypto.iv);

decrypt.data
// String "will be secret"
```
More [examples](https://github.com/MustafaHi/Sciter-Botan/wiki/Examples) and the entire [API](https://github.com/MustafaHi/Sciter-Botan/wiki/API) in the wiki
