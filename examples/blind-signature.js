'use strict'

/**
 * 	Blind signature scheme is a protocol that allows the provider
 *  to obtain a valid signature for a message m from the signer
 *  without him seeing the message and its signature.
 */

const bignum = require('bignum');
const rsa = require('../lib/rsa');

// Alice get the publicKey from server

const { publicKey, privateKey } = rsa.generateRandomKeys(512); // Change to at least 2048 bits in production state


let m = 'RSA is going to dissapear with QC';
console.log('message: '+m);
console.log('');
// Alice must find the blind the message
//
const blinded = publicKey.blind(bignum.fromBuffer(Buffer.from(m)));
console.log('blinded msg: '+blinded.toString());
console.log('');
// Bob now need to sign it

const signed = privateKey.sign(blinded);
console.log('signed msg: '+signed.toString());
console.log('');


// Alice unblind it 

const unblinded = publicKey.unblind(signed);
console.log('unblinded msg: '+unblinded.toString(16));

// And verifies it

const verified = publicKey.verify(unblinded);
console.log('verified msg: '+verified.toBuffer().toString());


