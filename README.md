
# secure-caesar

* secure-caesar cipher, is a symetric key cipher, based on caesar shift cipher.

* Unicode support.

* PKCS #1 padding (version 2).

* Secure password generator (with length-by-demand).

* Secure random number generator.

* Versions before v3.0.0 are discovered to be NOT SECURE, because of patterns that are being generated.

* Please upgrade to v3.0.0 ASAP.

# Example

```
// Require/Import this package

import "secure-caesar" // or: require("secure-caesar");

// Now you have a new global async function, called: "SecureCaesar"

// Create a key
const key = await SecureCaesar( "Key" );

// Encrypt
const ciphertext = await SecureCaesar( "Encrypt", key, "welcome to the cyberzone!" );

// Decrypt
const plaintext = await SecureCaesar( "Decrypt", key, ciphertext );

// "welcome to the cyberzone!"
console.log(plaintext);
```

---

The "SecureCaesar" global async function, has the spesific syntax, of: `action` & `parameter(s)`;

We have 3 actions:

# Key:

* Generate a password to use with the `Encrypt`/`Decrypt` actions listed below.

* One optional parameter: key length (default = 1).

* * The real length of the new key, will be much longer, that number is just a factor for the new key real length.

# Encrypt:

* key: the key being used (required).

* message: the plain text, encrypted number can also be used. It will become a string before encryption, anyway (required).

* You will get in return, cipher text with unicode characters.

# Decrypt:

* key: the key being used (required).

* Ciphertext: The ciphertext from the previous encryption (required).

### Enjoy!
