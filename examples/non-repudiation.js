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

const aliceSecretKey = hashKey('sha256', rand.toBuffer(), 'hex');
console.log('aliceSecretKey: '+aliceSecretKey); 

const cryptogram = encryptMsg(aliceSecretKey, m, 'aes-256-cbc', 'utf8', 'hex');
console.log('encrypted: '+cryptogram.toString()); 

// 	Then Alice build a proof Of Origin (Po) and sends it back to Bob (proof that he is INTERESTED in the message)
// 	Po = [H(A, B, L, C)]A

const timestampAB = generateTs();
console.log('timestampAB: '+timestampAB.toString(16)); 

const po = buildProof(alice, bob, timestampAB.toString(16), cryptogram.toString(16), 'sha256', 'hex');
console.log('proofOfOrigin: '+po); 

const signedPo = privateKeyAlice.sign(bignum(po, 16));
console.log('signedProofOfOrigin: '+signedPo.toString(16)); 

const aToBData = {
    'timestamp': timestampAB.toString(16), 
    'crypto': cryptogram, 
    'signedPo': signedPo.toString(16) 
}; console.log('aToBData: '+JSON.stringify(aToBData)); 

//  Bob now needs to verify Po from Alice

const poVerified = verifyProof(aToBData, 'ab');
console.log('poVerified: '+poVerified.toString());

// 	Bob sends back a Proof of Reception (Pr) to Alice 
// 	Pr = [H(B, A, L, C)]B  || Pr = [H(A, B, L, C)]B

const timestampBA = generateTs();

const pr = buildProof(bob, alice, timestampBA.toString(16), aToBData.crypto.toString(16), 'sha256', 'hex');
console.log('pr: '+ pr); 

const signedPr = privateKeyBob.sign(bignum(pr, 16));
console.log('signedPr: '+signedPr.toString(16));

const bToAData = {
    'timestamp': timestampBA.toString(16), 
    'signedPr': signedPr.toString(16) //Po = [H(A, B, L, C)]A
};

// Alice when receives Pr, needs to verify it first

const prVerified = verifyProof(bToAData, 'ba');
console.log('prVerified: '+prVerified.toString());


// 	Then, Alice sends the key to the TTP which encrypts the message m and a proof of Origin Of Key (Pko)
//	Pko = [H(A, TTP, B, L, K)] A

const timestampATTP = generateTs();
const encryptedAliceSecretKey = publicKeyTTP.encrypt(stringToBignum(aliceSecretKey));
console.log('encryptedAliceSecretKey: '+encryptedAliceSecretKey.toString(16)); 
console.log('timestampATTP.toString(16): '+timestampATTP.toString(16));
		
const pko = buildProofTTP(ttp, alice, bob, timestampATTP.toString(16), encryptedAliceSecretKey.toString(16), 'sha256', 'hex');
const signedPko = privateKeyAlice.sign(bignum(pko, 16));

const aToTTPData = {
	'origin' : alice,
	'dest' : bob,
	'timestamp': timestampATTP.toString(16), 
	'k' : encryptedAliceSecretKey.toString(16),
    'signedPko': signedPko.toString(16) //Po = [H(A, B, L, C)]A
};
console.log('aToTTPData: '+JSON.stringify(aToTTPData)); 

// TTP must verify Pko

const pkoVerified = verifyProof(aToTTPData, 'attp');
console.log('pkoVerified: '+pkoVerified.toString());

const signedPkoAlice = aToTTPData.signedPko;

const unsignedPko = publicKeyTTP.unsign(bignum(signedPkoAlice, 16));
console.log('unsignedPko: '+unsignedPko.toString(16));

// Then, publish it expecting that bob get it (in this case
// we are going to send it to Bob and Alice with the Pkp).
// First to Alice

const timestampTTPA = generateTs(); 
const decryptedAliceSecretKey = privateKeyTTP.decrypt(bignum(aToTTPData.k, 16));
console.log('decryptedAliceSecretKey: '+decryptedAliceSecretKey.toBuffer()); // Important to use buffer 

const encryptedAliceSecretKeyFinalA = publicKeyAlice.encrypt(decryptedAliceSecretKey);

const pkpToAlice = buildProofTTP(ttp, alice, bob, timestampTTPA.toString(16), encryptedAliceSecretKeyFinalA.toString(16), 'sha256', 'hex');
console.log('pkp = buildProofTTP: '+pkpToAlice); // Important to use buffer 

const signedPkpToAlice = privateKeyTTP.sign(bignum(pkpToAlice, 16));

const tTPtoAData = {
	'timestamp': timestampTTPA.toString(16), 
	'k' : encryptedAliceSecretKeyFinalA.toString(16),
    'signedPkpToAlice': signedPkpToAlice.toString(16) // Pkp = [H(TTP, A, B, L, K)] TTP
};
console.log('tTPtoAData: '+JSON.stringify(tTPtoAData)); 

// Alice Verifies Proof of Publication from TTP

const pkpVerifiedByA = verifyProof(tTPtoAData, 'ttpa');
console.log('pkpVerified: '+pkpVerifiedByA.toString());

const signedPkpToAliceReceived = tTPtoAData.signedPkpToAlice;

const unsignedPkpToA = publicKeyTTP.unsign(bignum(signedPkpToAliceReceived, 16));
console.log('unsignedPko: '+unsignedPko.toString(16));


// Then, to Bob

const encryptedAliceSecretKeyToBob = publicKeyBob.encrypt(decryptedAliceSecretKey);
const pkpToBob = buildProofTTP(ttp, alice, bob, timestampTTPA.toString(16), encryptedAliceSecretKeyToBob.toString(16), 'sha256', 'hex');
console.log('pkp = buildProofTTP: '+pkpToBob); // Important to use buffer 
const signedPkpToBob = privateKeyTTP.sign(bignum(pkpToBob, 16));

const tTPtoBData = {
	'timestamp': timestampTTPA.toString(16), 
	'k' : encryptedAliceSecretKeyToBob.toString(16),
    'signedPkpToBob': signedPkpToBob.toString(16) // Pkp = [H(TTP, A, B, L, K)] TTP
};
console.log('tTPtoBData: '+JSON.stringify(tTPtoBData)); 

// Then Bob verifies the pkp

const pkpVerifiedByBob = verifyProof(tTPtoBData, 'ttpb');
console.log('pkpVerifiedByBob: '+pkpVerifiedByBob.toString());

const signedPkpToBobReceived = tTPtoBData.signedPkpToBob;

const unsignedPkpToBob = publicKeyTTP.unsign(bignum(signedPkpToBobReceived, 16));
console.log('unsignedPkpToBob: '+unsignedPkpToBob.toString(16));

// Then Bob receives K can decrypt the message
const decrypted = decrypt(tTPtoBData.k, aToBData.crypto, 'aes-256-cbc', 'hex', 'utf8');
console.log('');
console.log('message in Bob: '+ decrypted);

// Helpers

function toHex(str) {
	var hex = '';
	for(var i=0;i<str.length;i++) {
		hex += ''+str.charCodeAt(i).toString(16);
	}
	return hex;
};

function stringToBignum(string) {
	return bignum.fromBuffer(Buffer.from(string));
}

function hashKey(algorithm, key, base) {
	return crypto.createHash(algorithm).update(key).digest(base);
}

function encryptMsg(secret, m, algorithm, inputEncoding, outputEncoding) {
	const cipher = crypto.createCipher(algorithm, Buffer.from(secret, outputEncoding), outputEncoding);
	let encrypted = cipher.update(m, inputEncoding, outputEncoding);
	return encrypted += cipher.final(outputEncoding);	
}

function decrypt(key, m, algorithm, inputEncoding, outputEncoding) {
	const decryptedAliceSecretKeyToBob = privateKeyBob.decrypt(bignum(key, 16));
	let decipher = crypto.createDecipher(algorithm, Buffer.from(decryptedAliceSecretKeyToBob.toBuffer().toString(), inputEncoding));
	let decrypted = decipher.update(m, inputEncoding, outputEncoding);
	decrypted += decipher.final(outputEncoding);
	return decrypted;
}

function generateTs() {
	return stringToBignum(new Date().toString());
}

function buildProof(origin, dest, l, m, algorithm, outputEncoding) {
	const key = Buffer.from(origin.concat(dest).concat(l).concat(m));
	return hashKey(algorithm, key, outputEncoding);
}

function buildProofTTP(ttp, origin, dest, l, m, algorithm, outputEncoding) {
	const key = Buffer.from(ttp.concat(origin).concat(dest).concat(l).concat(m));
	return hashKey(algorithm, key, outputEncoding);
};

function verifyProof(proof, channel) { 
	let testProof , signedProof, unsignedProof;
	switch (channel) {
		case 'ab':
			signedProof = proof.signedPo;
			unsignedProof = publicKeyAlice.unsign(bignum(signedProof, 16));
			console.log('unsignedPo: '+unsignedProof.toString(16));
			testProof = buildProof(alice, bob, proof.timestamp, proof.crypto, 'sha256', 'hex');
			console.log('testProof: '+testProof);
			break;
		case 'ba': 
			signedProof = proof.signedPr;
			unsignedProof = publicKeyBob.unsign(bignum(signedProof, 16));
			console.log('unsignedPr: '+unsignedProof.toString(16));
			testProof = buildProof(bob, alice, proof.timestamp, cryptogram, 'sha256', 'hex');
			console.log('testProof: '+testProof);
			break;
 		case 'attp': 
 			signedProof = proof.signedPko;
 			unsignedProof = publicKeyAlice.unsign(bignum(signedProof, 16)); 
			console.log('unsignedPko: '+unsignedProof.toString(16));
			testProof = buildProofTTP(ttp, proof.origin, proof.dest, proof.timestamp, proof.k, 'sha256', 'hex');
			console.log('testProof: '+testProof);
			break;
		case 'ttpa': 
			signedProof = proof.signedPkpToAlice;
			unsignedProof = publicKeyTTP.unsign(bignum(signedProof, 16)); 
		   	console.log('unsignedPkpToAlice: '+unsignedProof.toString(16));
		   	testProof = buildProofTTP(ttp, alice, bob, proof.timestamp, proof.k, 'sha256', 'hex');
			console.log('pkp = buildProofTTP: '+pkpToAlice); // Important to use buffer    
			console.log('testProof: '+testProof);
			break;
		case 'ttpb': 
			signedProof = proof.signedPkpToBob;
			unsignedProof = publicKeyTTP.unsign(bignum(signedProof, 16)); 
		   	console.log('unsignedPkpToBob: '+unsignedProof.toString(16));
		   	testProof = buildProofTTP(ttp, alice, bob, proof.timestamp, proof.k, 'sha256', 'hex');
			console.log('pkp = buildProofTTP: '+pkpToBob); // Important to use buffer    
			console.log('testProof: '+testProof);
			break;
	}
	
	if (testProof === unsignedProof.toString(16)) {
		return true;
	} 
	return false;		
}



