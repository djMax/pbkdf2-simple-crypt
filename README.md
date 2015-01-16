# pbkdf2-simple-crypt
[![Build Status](https://travis-ci.org/djMax/pbkdf2-simple-crypt.png)](https://travis-ci.org/djMax/pbkdf2-simple-crypt)
[![Dependency Status](https://gemnasium.com/djMax/pbkdf2-simple-crypt.png)](https://gemnasium.com/djMax/pbkdf2-simple-crypt)
[![Coverage Status](https://coveralls.io/repos/djMax/pbkdf2-simple-crypt/badge.png?branch=master)](https://coveralls.io/r/djMax/pbkdf2-simple-crypt?branch=master)
[![npm version](https://badge.fury.io/js/pbkdf2-simple-crypt.svg)](http://badge.fury.io/js/pbkdf2-simple-crypt)

A simple encrypt/decrypt library that uses PBKDF2 to derive a key from a password (while generating a securely-random salt),
encrypt using aes-256-cbc and return a string. That string includes the salt, the iv, an HMAC (hmac-sha1, which is fine
as a mac), and the cipher text. The upshot of all this is you can simply encrypt and decrypt simple strings and we'll work
out validity checking, etc. I really tried to find another module that did this simple thing properly but could not. If there
is one, file an issue; if there's an issue with mine I promise to fix it.

A simple example of encrypting and decrypting some text:


```js
        crypt.encrypt('this is a test', 'youcantseeme', function (err, cipherText) {
            crypt.decrypt(cipherText, 'youcantseeme', function (decErr, plain) {
                assert.equal(plain, plainText);
            });
        });
```