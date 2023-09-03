
# secure-caesar v4.0.0 

## Made with much screen time & care for the community, by: Yaron Koresh, Israel.

### This project is licensed under MIT open-source license.

* secure-caesar cipher, is a symetric key cipher, based on caesar shift cipher.

* Unicode support.

* PKCS #1 padding (version 2).

* Versions before v3.0.0 are discovered to be NOT SECURE, because of patterns that are being generated.

* Please upgrade to v3.0.0 or above.

# Example

```
// Require/Import this package

import "secure-caesar" // or: require("secure-caesar");

// Now you have a new global async function, called: "SecureCaesar"

// Select a password
const password = "gt785fy54dt897rgV#Yf3f98ktu9803xdj,9$#Y$#^TV%$GTB";

// Select a message to encrypt
const message = "Hello there! my name is Yaroni Makaroni! You have a good taste in choosing npm libraries :)";

// Encrypt
// 1-4 is the amount of power usage needed by the encryption (the last parameter)
const ciphertext = await SecureCaesar( "Encrypt", password, message, 1 );

// Encrypt
// 1-4 is the amount of power usage needed by the decryption (the last parameter)
const plaintext = await SecureCaesar( "Decrypt", password, ciphertext, 1 );

// "Hello there! my name is Yaroni Makaroni! You have a good taste in choosing npm libraries :)"
console.log(plaintext);

/* encryption/decryption power usage factor, should be equal */
```

---

The "SecureCaesar" global async function, has a spesific syntax, of: `action` & `parameter(s)`;

We have 2 actions:

# Encrypt:

* key: the key being used (required).

* message: the plain text, encrypted number can also be used. It will become a string before encryption, anyway (required).

* power: the power factor (default = 1).

* * Could only be: 1, 2, 3 or 4.

* * It should match on decryption.

# Decrypt:

* key: the key being used (required).

* Ciphertext: The ciphertext from the previous encryption (required).

* power: the power factor (default = 1).

* * Could only be: 1, 2, 3 or 4.

* * It should match to the encryption power factor.

# Enjoy!
