
# secure-caesar

* secure-caesar cipher, is a symetric key cipher, based on caesar shift cipher.

* New algorithms.

* Unicode support.

* PKCS #1 padding (version 2).

* Secure password generator (with length-by-demand).

* Secure random number generator.

# Example

```
// Require/Import this package

import "secure-caesar" // or: require("secure-caesar");

// Now you have a new global async function, called: "SecureCaesar"
```

---

The "SecureCaesar" global async function, has the spesific syntax, of: `action` & `parameter(s)`;

We have 3 actions:

# Key:

* Generate a password to use with the `Encrypt`/`Decrypt` actions listed below.

* One optional parameter: key length.

* * The real length will be multiplied by 32 & will have a starting "K" character.

* * The "K" is just for the password to never become an integer, even with JSON.stringify, so it can be send to your server, to encrypt each server response with a new key.

* An example: `await SecureCaesar( "Key" )`.

# Encrypt:

* With 3 parameters (1 required & 2 optional):

* message: the encrypted text, encrypted number can also be used. It will become a string before encryption, anyway.

* key/keylength: the key specifier.

* * If that parameter is a key you have already generated - you have to pass `true` in the next parameter into the algorithm.

* * If that parameter is a key length (multiplied by 32), you do not have to pass anything to the next parameter.

* * Lastly, for the algorithm to generate a minimal-length key ("K" and 32 secure random numbers), just keep that empty, while the next parameter will also be just empty.

* You will get in return, an Object type with `key` & `cipher` (the password & the result cipher text).

* An example: `await SecureCaesar( "Encrypt", "welcome to the cyberzone!" )`.

# Decrypt:

* With 2 required parameters:

* * Ciphertext: The cipher from the previous encryption.

* * Key: The long generated password used for the encryption.

* An example:

```
const key = 'K13457816176816512081192216512539237719912531209611436596168623515171223121411401253216641971240220315958113130112224255112213920';
const ciphertext = 'ՁẊ޵ݰ࣊ࠎڥੑ঵ࡺઝࣈә᧰ۋॊᓂׅࣜࣳ਺ܭࡿ্࠸᝟ѻಗট੩շ࿩ไ₹Ḡᨚ΅⒲ᥰᖇ༠\x14ᔣа؉ឮ᫮ฯܟन׷နᔮᨑ♓ုƝ◒֓êऱᗵऊι';
const plaintext = await SecureCaesar( "Decrypt", ciphertext, key );

console.log(plaintext); // 'welcome to the cyberzone!'

```

### Enjoy!
