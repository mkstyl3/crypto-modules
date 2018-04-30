'use strict'

/**
 * 	Alice wants to send a message m to Bob in a unreliable channel and non-honest entities using protocol 5 seen in class.
 * 	Added authorized timestamps
 */

const bignum = require('bignum');
const rsa = require('../lib/rsa');
const crypto = require('crypto');


const { publicKey : publicKeyBob, privateKey : privateKeyBob } = rsa.generateRandomKeys(512); // Change to at least 2048 bits in production state
const { publicKey : publicKeyAlice, privateKey : privateKeyAlice } = rsa.generateRandomKeys(512); // Change to at least 2048 bits in production state
const { publicKey : publicKeyTTP, privateKey : privateKeyTTP } = rsa.generateRandomKeys(512); // Change to at least 2048 bits in production state

//	Alice's environment init 

let m = 'RSA is going to dissapear with QC';
console.log('message in Alice: '+m);
console.log('');

const alice = toHex('Alice'); // Convert to hex for coherence
const bob = toHex('Bob');
const ttp = toHex('TTP');
const rand = bignum.rand(bignum('D41D8CD98F00B204E9800998ECF8427E', 16)); // A simple random number
console.log('rand: '+rand.toString()); 

// 	Alice encrypts the message m with a hash of a random number
const aliceSecretKey = crypto.createHash('sha256').update(rand.toString(16), 'hex').digest('hex');
console.log('aliceSecretKey: '+aliceSecretKey.toString()); 
 
const cipher = crypto.createCipher('aes-256-cbc', Buffer.from(aliceSecretKey, 'hex'), 'hex');
let encrypted = cipher.update(m, 'utf8', 'hex');
encrypted += cipher.final('hex');
console.log('encrypted: '+encrypted.toString()); 

// 	Then Alice build a proof Of Origin (Po) and sends it back to Bob (proof that he is INTERESTED in the message)
// 	Po = [H(A, B, L, C)]A

const timestampAB = privateKeyTTP.sign(bignum.fromBuffer(Buffer.from((new Date()).toString())));
console.log('timestampAB: '+timestampAB.toString(16)); 
const proofOfOrigin = crypto.createHash('sha256').update(alice.concat(bob).concat(timestampAB).concat(encrypted), 'utf8').digest('hex');
console.log('proofOfOrigin: '+proofOfOrigin); 

const signedProofOfOrigin = privateKeyAlice.sign(bignum(proofOfOrigin, 16));

const aToBData = {
    'timestamp': timestampAB.toString(16), 
    'crypto': encrypted, 
    'signedProofOfOrigin': signedProofOfOrigin.toString(16) 
};

console.log('signedProofOfOrigin: '+signedProofOfOrigin.toString(16)); 
console.log('aToBData: '+JSON.stringify(aToBData)); 

// 	Then, Bob receives de data and sends back a Proof of Reception (Pr) to Alice 
// 	Pr = [H(B, A, L, C)]B  || Pr = [H(A, B, L, C)]B

const timestampBA = privateKeyTTP.sign(bignum.fromBuffer(Buffer.from((new Date()).toString())));

const unsignedProofOfOrigin = publicKeyAlice.unsign(bignum(aToBData.signedProofOfOrigin, 16));
console.log('unsignedProofOfOrigin: '+unsignedProofOfOrigin.toString(16));

const signedProofOfReception = privateKeyBob.sign(unsignedProofOfOrigin)
console.log('ProofOfReception: '+signedProofOfReception.toString(16));

const bToAData = {
    'timestamp': timestampBA.toString(16), // signed by from TTP
    'signedProofOfReception': signedProofOfReception.toString(16) //Po = [H(A, B, L, C)]A
};

// 	Alice when receives Pr, sends the key to the TTP which encrypts the message m and a proof of Origin Of Key (Pko)
//	Pko = [H(A, TTP, B, L, K)] A

const timestampATTP = privateKeyTTP.sign(bignum.fromBuffer(Buffer.from((new Date()).toString())));
const encryptedAliceSecretKey = publicKeyTTP.encrypt(bignum.fromBuffer(Buffer.from(aliceSecretKey)));
console.log('encryptedAliceSecretKey: '+encryptedAliceSecretKey.toString(16)); 

const proofOfOriginOfK = crypto.createHash('sha256').update(alice.concat(ttp).concat(bob).concat(timestampATTP).concat(aliceSecretKey), 'utf8').digest('hex');
const signedProofOfOriginOfK = privateKeyAlice.sign(bignum(proofOfOriginOfK, 16));

const aToTTPData = {
	'timestamp': timestampATTP.toString(16), // signed by from TTP
	'k' : encryptedAliceSecretKey.toString(16),
    'signedProofOfReception': signedProofOfReception.toString(16) //Po = [H(A, B, L, C)]A
};
console.log('aToTTPData: '+JSON.stringify(aToTTPData)); 

// 	TTP when receives the alice key, publish it expecting that bob get it (in this case
//	we are going to send it to both Alice and Bob )

const timestampTTP = privateKeyTTP.sign(bignum.fromBuffer(Buffer.from((new Date()).toString()))); // 1 for both, like in a publication
const decryptedAliceSecretKey = privateKeyTTP.decrypt(bignum(aToTTPData.k, 16));
console.log('decryptedAliceSecretKey: '+decryptedAliceSecretKey.toBuffer()); // Important to use buffer 

const encryptedAliceSecretKeyFinalA = publicKeyAlice.encrypt(decryptedAliceSecretKey);

const proofOfPublicationOfKA = crypto.createHash('sha256').update(ttp.concat(alice).concat(bob).concat(timestampTTP).concat(encryptedAliceSecretKeyFinalA.toString(16)), 'utf8').digest('hex');
const signedproofOfPublicationOfKA = privateKeyTTP.sign(bignum(proofOfPublicationOfKA, 16));

const tTPtoAData = {
	'timestamp': timestampTTP.toString(16), // signed by from TTP
	'k' : encryptedAliceSecretKeyFinalA.toString(16),
    'signedproofOfPublicationOfK': signedproofOfPublicationOfKA.toString(16) // Pkp = [H(TTP, A, B, L, K)] TTP
};
console.log('tTPtoAData: '+JSON.stringify(tTPtoAData)); 

// The same with Bob

const encryptedAliceSecretKeyFinalB = publicKeyBob.encrypt(decryptedAliceSecretKey);

const proofOfPublicationOfKB = crypto.createHash('sha256').update(ttp.concat(alice).concat(bob).concat(timestampTTP).concat(encryptedAliceSecretKeyFinalB.toString(16)), 'utf8').digest('hex');
const signedproofOfPublicationOfKB = privateKeyTTP.sign(bignum(proofOfPublicationOfKB, 16));

const tTPtoBData = {
	'timestamp': timestampTTP.toString(16), // signed by from TTP
	'k' : encryptedAliceSecretKeyFinalB.toString(16),
    'signedproofOfPublicationOfKB': signedproofOfPublicationOfKB.toString(16) // Pkp = [H(TTP, A, B, L, K)] TTP
};
console.log('tTPtoBData: '+JSON.stringify(tTPtoBData)); 

// Then Bob receives K can fully decrypt the message

const decryptedAliceSecretKeyFinalB = privateKeyBob.decrypt(bignum(tTPtoBData.k, 16));
console.log('decryptedAliceSecretKeyFinalB: '+decryptedAliceSecretKeyFinalB);

console.log('encryptedAliceSecretKeyFinalB: '+encryptedAliceSecretKeyFinalB.toString(16));
console.log('encrypted: '+encrypted);
let decipher = crypto.createDecipher('aes-256-cbc', Buffer.from(decryptedAliceSecretKeyFinalB.toBuffer().toString(), 'hex'));
let decrypted = decipher.update(aToBData.crypto, 'hex', 'utf8');
decrypted += decipher.final('utf8');
console.log('');
console.log('message in Bob: '+decrypted);

// The same for Alice (not implemented)

function toHex(str) {
	var hex = '';
	for(var i=0;i<str.length;i++) {
		hex += ''+str.charCodeAt(i).toString(16);
	}
	return hex;
}
