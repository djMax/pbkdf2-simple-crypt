/*!
 * pbkdf2-simple-crypt
 * Copyright(c) 2015 Max Metral <opensource@pyralis.com>
 * MIT Licensed
 */
'use strict';

var crypto = require('crypto'),
    debuglog = require('debuglog')('pbkdf2-simple-crypt');

var external = {
    ITERATIONS: 1000
};

/**
 * Encrypt plainText using a key derived from password and return a string suitable
 * for submitting to decrypt. That string is a base64 of the salt(16),iv(16),hmac(20) and buffer (variable).
 */
external.encrypt = function (plainText, password, callback) {
    var salt = new Buffer(crypto.randomBytes(16), 'binary');
    var iv = new Buffer(crypto.randomBytes(16), 'binary');

    crypto.pbkdf2(password, salt, external.ITERATIONS, 32, function (err, key) {
        if (err) {
            debuglog('Failed to generate key.', err);
            return callback(err, null);
        }

        var cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
        var buffer = new Buffer(cipher.update(plainText, 'utf8', 'binary'), 'binary');
        buffer = Buffer.concat([buffer, new Buffer(cipher.final('binary'), 'binary')]);

        // Before you file the "DUDE you can't use SHA1 anymore" issue,
        // http://crypto.stackexchange.com/questions/15382/hmac-sha1-vs-hmac-sha256
        var hashKey = crypto.createHash('sha1').update(key).digest('binary');
        var hmac = new Buffer(crypto.createHmac('sha1', hashKey).update(buffer).digest('binary'), 'binary');

        buffer = Buffer.concat([salt, iv, hmac, buffer]);
        callback(null, buffer.toString('base64'));
    });
};

/**
 * Decrypt a base64 encoded string that came from encrypt using the same password
 */
external.decrypt = function (cipherText, password, callback) {
    var cipher = Buffer.isBuffer(cipherText) ? cipherText : new Buffer(cipherText, 'base64');
    var salt = cipher.slice(0, 16);

    crypto.pbkdf2(password, salt, external.ITERATIONS, 32, function (err, key) {
        if (err) {
            debuglog('Failed to generate key.', err);
            return callback(err, null);
        }
        external.decryptWithKey(cipher, key, callback);
    });
};

/**
 * Decrypt a base64 encoded string with the aes-256-cbc key directly, rather than deriving from
 * a password. This is not typically used since the salt is part of the cipherText (first 16 bytes)
 * and that wouldn't be relevant w/o PBKDF, but just in case you need your own.
 */
external.decryptWithKey = function (cipherText, key, callback) {
    var cipher = Buffer.isBuffer(cipherText) ? cipherText : new Buffer(cipherText, 'base64');

    var iv = cipher.slice(16, 32);
    var hmac = cipher.slice(32, 52);
    cipherText = cipher.slice(52);

    var decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);

    // Verify the HMAC first
    var hashKey = crypto.createHash('sha1').update(key).digest('binary');
    var hmacgen = new Buffer(crypto.createHmac('sha1', hashKey).update(cipherText).digest('binary'), 'binary');
    if (hmacgen.toString('base64') !== hmac.toString('base64')) {
        return callback(new Error('HMAC Mismatch!'), null);
    }
    var buffer = new Buffer(decipher.update(cipherText), 'binary');
    buffer = Buffer.concat([buffer, new Buffer(decipher.final('binary'))]);
    callback(null, buffer.toString('utf8'), key);
};

module.exports = external;