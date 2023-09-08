
# secure-caesar v6.0.0 

## Made with much screen time & care for the community, by: Yaron Koresh, Israel.

### This project is licensed under MIT open-source license.

* secure-caesar cipher, is a symetric key cipher, based on caesar shift cipher.

* Unicode support.

* PKCS #1 padding (version 2).

* Secure random salt, generated with each encryption.

* Versions before v3.0.0 are discovered to be NOT SECURE, because of patterns that are being generated.

* Please upgrade to v3.0.0 or above.

# Example

```
// Import this package

import { Encrypt, Decrypt } from "secure-caesar" // or: const { Encrypt, Decrypt } = await import("secure-caesar");

// Select a password
const password = "gt785fy54dt897rgV#Yf3f98ktu9803xdj,9$#Y$#^TV%$GTB";

// Select a message to encrypt
const message = "Hello there! my name is Yaroni Makaroni! You have a good taste in choosing npm libraries :)";

// 1-4 is the amount of power usage needed by the encryption & decryption (the last parameter)
const powerUsage = 2;

// Encrypt
const ciphertext = Encrypt(password, message, powerUsage );

// Decrypt
const plaintext = Decrypt(password, ciphertext, powerUsage );

// "Hello there! my name is Yaroni Makaroni! You have a good taste in choosing npm libraries :)"
console.log(plaintext);
```

### Enjoy!
