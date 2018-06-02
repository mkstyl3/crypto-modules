'use strict';

const bignum = require('bignum');

class Key {
    constructor(value, position, prime) {
      this.value = value;
      this.position = position;
      this.p = prime;
    }
}

/*
    Auxiliary function for laGrangeInterpolation()
*/
function genCorrPosArrayVector(keys) {
    let posCorrVector = [];
    keys.forEach(element => {
        posCorrVector.push(bignum(element.position));  
    });

    return posCorrVector;
}

/*
    p must be greater than k
*/
function genPrimeGreaterThanK(bitLength, k) {
    let p;
    do {
        p = bignum.prime(bitLength);
    }
    while(p.bitLength() != bitLength && k.ge(p));

    return p;
}

module.exports = {
    Key: Key,
    /*
        t: min needed shares, polynomial will be t-1 degree
        n: number of shares
        k: stand-alone value of the polynomial (master-key)
        p: no. bits of the prime (default = 512)
    */
    genShares(t, n, key, bits = 512) {
        let coefs = [], keys = [], it = 1;
        const k = bignum(key);
        
        const p = genPrimeGreaterThanK(bits, k);
        coefs.push(k);
        // Gererate random coeficients
        for (let i = 0; i < t-1; i++) {
            coefs.push(k.rand());
        }
        for (let i = 0; i < n; i++) {
            const x = bignum(i + 1);
            let key = coefs.reduce((sum, next) => {
                let z = sum.add(next.mul(x.pow(bignum(it))));
                it++;
                return z;
            });
    
            key = key.mod(p);
            keys.push(new Key(key.toString(10), i.toString(10), p.toString(16)));
            it = 1;
        }
        
        return keys;
    },
    /*
        keys: Array of "Key" Objects. Key Object has 3 atributes that are "value", "position" and "p"
        Where,
            value: string-number
            position: string-number
            p: string-number-base16
    */
    laGrangeInterpolation(keys) {
        let monomial_i = [], monomial_j, k_positions_correlative = genCorrPosArrayVector(keys);
        const p = bignum(keys[0].p, 16);
        for(var i=0;i<keys.length;i++) {
            let num = bignum(1), den = bignum(1), den_inv;
            for(let j=0;j<k_positions_correlative.length;j++) {
                let monomial;
                if(j==i) {
                    //console.log('keys[j].value'+j+': '+keys[j].value);
                    //console.log('num'+j+': '+num);
                    num = num.mul(bignum(keys[j].value));
                    //console.log('num'+j+': '+num);
                } else {
                    num = num.mul(k_positions_correlative[j]);
                    den = den.mul(k_positions_correlative[j].sub(k_positions_correlative[i]));
                    //console.log('num'+j+': '+num);
                    //console.log('den'+j+': '+den);
                    //console.log('p'+j+': '+p);
                    //console.log('k_positions_correlative[j])'+j+': '+k_positions_correlative[j]);
                    //console.log('k_positions_correlative[i])'+j+': '+k_positions_correlative[i]);
                }
            }
            den_inv = den.invertm(p);   
            //console.log('den_inv: '+den_inv.toString(16));
            monomial_j = num.mul(den_inv);
            monomial_i.push(monomial_j);
            //console.log(monomial_i.toString(16));
        }
        //console.log((monomial_i).toString(16));
        let sum = monomial_i.reduce((a, b) => a.add(b));
        
        return sum.mod(p);
    }
}

