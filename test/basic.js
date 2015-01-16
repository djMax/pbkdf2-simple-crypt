/*global describe:false, it:false*/

/*!
 * pbkdf2-simple-crypt
 * Copyright(c) 2015 Max Metral <opensource@pyralis.com>
 * MIT Licensed
 */
'use strict';

var crypt = require('..'),
    assert = require('assert');

describe('/', function () {

    var plainText = 'this is a test message !@)(#*)(*!@$)(*(@()';
    var password = 'quick brown fox dog and etc.';
    var knownCipher = 'tGOckDCTOhaYLNmLG8YxDvlJmD/UVXCosIFraKBwOjJWc0Vs7SWR8LDizGW04/D3rXuIX1hfN69F7osbL0pG98mGKJXyenzQyTeidONL4sLFmSk3TKDkEZaq0gbDMU9yff5ogw==';

    it('should encrypt and decrypt', function (done) {
        crypt.encrypt(plainText, password, function (err, cipher) {
            assert.ifError(err);
            crypt.decrypt(cipher, password, function (decErr, plain) {
                assert.ifError(decErr);
                assert.equal(plain, plainText);
                done();
            });
        });
    });

    it('should decrypt known good cipher text to make sure the format does not change', function (done) {
       crypt.decrypt(knownCipher, password, function (decErr, plain) {
           assert.ifError(decErr);
           assert.equal(plain, plainText);
           done();
       });
    });
});