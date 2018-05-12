'use strict';

const bignum = require('bignum');
//const crypto = require('crypto');

//const hash = (type, rand,  )
const generateRandomKeys = (bitLength = 2048) => {
    let p, q, n, phi, e, d;

    do {
        p = bignum.prime(bitLength / 2);
        q = bignum.prime(bitLength / 2);
        n = p.mul(q);
    } while (q.cmp(p) == 0 || n.bitLength() != bitLength);

    phi = p.sub(1).mul(q.sub(1));
    e = bignum(65537); //Fermat prime number
    d = e.invertm(phi);

    const publicKey = new RSAPublicKey(e, n);
    const privateKey = new RSAPrivateKey(d,n);

    return { publicKey, privateKey };

}

const RSAPublicKey = class RSAPublicKey {

    constructor(e,n) {
        this.e = bignum(e);
        this.n = bignum(n);
        this.k;
    };

    encrypt(m) {
        // E[m] = m^e mod n
        return m.powm(this.e, this.n);   
    };

    blind(m) {
        // Alice compute an aleatory k, the blinding factor
        this.k = bignum.rand(this.n);
        // Alice blinds the message, m'= m*(k^e mod n)
        return m.mul(this.k.powm(this.e,this.n));
    };

    unblind(m) {
        // Alice computes de k inverse
        const kInv = this.k.invertm(this.n);
        // Alice computes sigma, s =  m'^k^-1 mod n
        return m.mul(kInv).mod(this.n);
    };

    verify(s) {
        // alice unblinds it with sigma
        return s.powm(this.e, this.n); // Verify
    };

    unsign(m) { 
        // m is the signed message
        // US[m] = m^d mod n
        return m.powm(this.e, this.n)
    };
}

const RSAPrivateKey = class RSAPrivateKey {
    constructor(d,n) {
        this.d = bignum(d);
        this.n = bignum(n);
    };

    decrypt(m) { 
        // m is the encrypted message
        // D[m] = m^d mod n
        return m.powm(this.d, this.n);
    };

    sign(m) { 
        // Blinded m in case of blind signature
        // Alice computes sigma', s' =  m'^d mod n 
        return m.powm(this.d,this.n);
    };

    getRand() {
        return this.n.rand(); 
    }
}

module.exports = {
    generateRandomKeys: generateRandomKeys,
    PrivateKey: RSAPrivateKey,
    PublicKey: RSAPublicKey
};