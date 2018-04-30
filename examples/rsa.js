'use strict'
const bignum = require('bignum');
const rsa = require('../lib/rsa');

/**
 * 	Alice wants to send a message m to Bob using RSA algorithm
 * 	Change to at least 2048 bits in production state
 */

// Alice (client) requests the public key from the server

const { publicKey, privateKey } = rsa.generateRandomKeys(512); // Change to at least 2048 bits in production state

// Alice then encrypts the message with the server's public key

let msg = 'RSA is going to dissapear with QC';
console.log('message: '+msg);
console.log('');
const encryptedMsg = publicKey.encrypt(bignum.fromBuffer(Buffer.from(msg))); 
console.log('encrypted msg: '+encryptedMsg.toString());
console.log('');
// Bob (server) decrypts msg with its private key

const decryptedMsg = privateKey.decrypt(encryptedMsg);

console.log('decrypted msg: '+decryptedMsg.toBuffer().toString());


