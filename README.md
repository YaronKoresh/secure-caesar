
# secure-caesar v9.0.0

### Made with much screen time & care for the community, by: Yaron Koresh, Israel.

### This project is licensed under MIT open-source license.

### Notice: credits for the Scrypt algorithm implementation, belong to Richard Moore, the author of [scrypt-js](https://www.npmjs.com/package/scrypt-js/v/3.0.1). I couldn't use it externally as a CommonJS inside my ESModule project.

### secure-caesar cipher, is a symetric key cipher, based on caesar shift cipher.

* Unicode support.

* Message padding.

* Secure random salt, generated with each encryption.

* ECDH support.

# Example without ECDH

```
// Import this package

import { Encrypt, Decrypt } from "secure-caesar"; // or: const { Encrypt, Decrypt } = await import("secure-caesar");

// Select a password
const password = "gt785fy54dt897rgV#Yf3f98ktu9803xdj,9$#Y$#^TV%$GTB";

// Select a message to encrypt
const message = "Hello there! my name is Yaroni Makaroni! You have a good taste in choosing npm libraries :)";

// 1 or above is the amount of power usage needed by the encryption & decryption (the last parameter)
const powerUsage = 2;

// Encrypt
const ciphertext = Encrypt(password, message, powerUsage );

// Decrypt
const plaintext = Decrypt(password, ciphertext, powerUsage );

// "Hello there! my name is Yaroni Makaroni! You have a good taste in choosing npm libraries :)"
console.log(plaintext);
```

# Example with ECDH

```
// Import this package

import { Curve } from "secure-caesar"; // or: const { Curve } = await import("secure-caesar");

// First friend:
const curve = new Curve();
curve.init();

// Second friend:
const curve = new Curve();
curve.init();

// Now they need to publish their curve.public.x & curve.public.y .
// After that, each one of them need to insert the other friend's public X & Y...

curve.x(<publicX>);
curve.y(<publicY>);

// Now, let's talk! :)

// First friend:
curve.msg("I need help! SOS! I can't finish all that ice cream alone!!");
const iceCreamEmergencyCall = curve.enc();

// First friend send the encrypted message to the second friend.
// But without the ability to send the password, with their unsafe internet connection...
// How would the original message will be decrypted?
// Well... it could be decrypted easily!
// Their secrets are already the same :)
// If you do not believe, run: `console.log(curve.secret)` for both of the friends - the secret.x & secret.y should be equal.

// Second friend:
curve.msg( iceCreamEmergencyCall );
const decryptedSos = curve.dec();

console.log( decryptedSos );
// I need help! SOS! I can't finish all that ice cream alone!!

```

### Enjoy!