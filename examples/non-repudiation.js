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

const m = 'RSA is going to dissapear with QC';
console.log('message in Alice: '+m);
console.log('');

const alice = toHex('Alice'); // Convert to hex for coherence
const bob = toHex('Bob'); // Convert to hex for coherence
const ttp = toHex('TTP'); // Convert to hex for coherence

const rand = privateKeyAlice.getRand();
console.log('rand: '+rand.toString(16)); 

// 	Alice encrypts the message m with a hash of a random number

const aliceSecretKey = hashKey('sha256', rand.toString(16), 'hex');
console.log('aliceSecretKey: '+aliceSecretKey); 

const encrypted = encryptMsg(aliceSecretKey, m, 'aes-256-cbc', 'utf8', 'hex');
console.log('encrypted: '+encrypted.toString()); 

// 	Then Alice build a proof Of Origin (Po) and sends it back to Bob (proof that he is INTERESTED in the message)
// 	Po = [H(A, B, L, C)]A

const timestampAB = generateTs(new Date().toString());
console.log('timestampAB: '+timestampAB.toString(16)); 

const po = buildProof(alice, bob, timestampAB.toString(16), encrypted);
console.log('proofOfOrigin: '+po); 

const signedPo = privateKeyAlice.sign(bignum(po, 16));
console.log('signedProofOfOrigin: '+signedPo.toString(16)); 

const aToBData = {
    'timestamp': timestampAB.toString(16), 
    'crypto': encrypted, 
    'signedProofOfOrigin': signedPo.toString(16) 
}; console.log('aToBData: '+JSON.stringify(aToBData)); 


//  Bob now needs to verify Po from Alice

const signedPoBob = aToBData.signedProofOfOrigin;

const unsignedPo = publicKeyAlice.unsign(bignum(signedPoBob, 16));
console.log('unsignedPo'+unsignedPo.toString(16));

const poVerified = verifyProof(unsignedPo.toString(16));
console.log('poVerified: '+poVerified.toString());

// 	Bob sends back a Proof of Reception (Pr) to Alice 
// 	Pr = [H(B, A, L, C)]B  || Pr = [H(A, B, L, C)]B

const timestampBA = generateTs(new Date().toString());

const signedPr = privateKeyBob.sign(unsignedPo)
console.log('ProofOfReception: '+signedPr.toString(16));

const bToAData = {
    'timestamp': timestampBA.toString(16), // signed by from TTP
    'signedPr': signedPr.toString(16) //Po = [H(A, B, L, C)]A
};

// Alice when receives Pr, needs to verify it first

const signedPrAlice = bToAData.signedPr;

const unsignedPr = publicKeyBob.unsign(bignum(signedPrAlice, 16));
console.log('unsignedPr'+unsignedPr.toString(16));

const prVerified = verifyProof(unsignedPr.toString(16));
console.log('prVerified: '+prVerified.toString());

// 	Then, Alice sends the key to the TTP which encrypts the message m and a proof of Origin Of Key (Pko)
//	Pko = [H(A, TTP, B, L, K)] A

const timestampATTP = privateKeyTTP.sign(bignum.fromBuffer(Buffer.from((new Date()).toString())));
const encryptedAliceSecretKey = publicKeyTTP.encrypt(bignum.fromBuffer(Buffer.from(aliceSecretKey)));
console.log('encryptedAliceSecretKey: '+encryptedAliceSecretKey.toString(16)); 

const proofOfOriginOfK = crypto.createHash('sha256').update(alice.concat(ttp).concat(bob).concat(timestampATTP).concat(aliceSecretKey), 'utf8').digest('hex');
const signedProofOfOriginOfK = privateKeyAlice.sign(bignum(proofOfOriginOfK, 16));

const aToTTPData = {
	'timestamp': timestampATTP.toString(16), // signed by from TTP
	'k' : encryptedAliceSecretKey.toString(16),
    'signedProofOfReception': signedPr.toString(16) //Po = [H(A, B, L, C)]A
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
};

function buildProofTTP(ttp, client, server, l, m) {
	return crypto.createHash('sha256').update(ttp.concat(client).concat(server).concat(l).concat(m.toString(16)), 'utf8').digest('hex');
};

function stringToBignum(bignum, string) {
	return bignum.fromBuffer(Buffer.from(string));
}

function hashKey(algorithm, key, base) {
	return crypto.createHash(algorithm).update(key, base).digest(base);
}

function encryptMsg(secret, m, algorithm, inputEncoding, outputEncoding) {
	const cipher = crypto.createCipher(algorithm, Buffer.from(secret, outputEncoding), outputEncoding);
	let encrypted = cipher.update(m, inputEncoding, outputEncoding);
	return encrypted += cipher.final(outputEncoding);	
}

function generateTs(string) {
	return stringToBignum(bignum, string);
}

function buildProof(origin, dest, l, m) {
	const key = origin.concat(dest).concat(l).concat(m);
	return hashKey('sha256',key, 'hex');
}

function verifyProof(po) { 
	const testProof = buildProof(alice, bob, aToBData.timestamp, aToBData.crypto);
	if(testProof === po) {
		return true;
	} 
	return false;
}






