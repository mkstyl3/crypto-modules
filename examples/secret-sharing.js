'use strict'

const bignum = require('bignum');

/**
 * 	Simple implementation of Shamir's Secret Sharing (SSS) for nodeJS
 */
 
const BITLENGHT = 2048;

/*
t: min needed shares, polynomial will be t-1 degree
n: number of shares
k: stand-alone value of the polynomial
p: polynomial will be evaluated at mod p
*/




class Key {
    constructor(value, position) {
      this.value = value;
      this.position = position;
    }
}

const keys = build(bignum(3), bignum(5), bignum(11), bignum(17));
console.log('keys: '+keys);

 // for instance



const k = [new Key(bignum(9),1), new Key(bignum(4),2), new Key(bignum(2),4)];
console.log('k: '+k);
const k_positions_correlative = [bignum(1), bignum(2), bignum(4)];
console.log('keyPosArray: '+k_positions_correlative);
const kFinal = f(k, k_positions_correlative, 17);
console.log('kFinal: '+kFinal);


















function build(t, n, k, p) {
    let polynomial = [], Fx = [], coef, xPow, monomial;
    
    if (k.gt(p)) {
        return new Error("k must be smaller than p")
    }
    // Generate shares
    for (let i=0; i<n; i++) {
        for (let j=1; j<t; j++) {
            if (j==1) coef = bignum(8);
            else if (j==2) coef = bignum(7);
            xPow = bignum(i+1).pow(j);
            
            //console.log(xPow = Math.pow(i+1, j));
            monomial = coef.mul(xPow);
            console.log('monomial: '+ monomial);
            //console.log(monomial = coef*xPow);
            polynomial.push(monomial);
        }
        //let sum = polynomial.reduce((a, b) => a + b, 0);
            //combine the coefficients to get the secret
        //let sum = polynomial.reduce((first, next) => first.add(next), 0);
        let sum = polynomial.reduce((a, b) => a.add(b));
        polynomial = [];
        Fx.push(new Key((k.add(sum)).mod(p), i+1));
    }
    
    return Fx;
}

function f(keys, k_positions_correlative, p) {
    let monomial_i = [], monomial_j, isNeg;
    for(var i=0;i<keys.length;i++) {
        let num = bignum(1),  den = bignum(1),  den_inv;
        for(let j=0;j<k_positions_correlative.length;j++) {
            let monomial;
            if(j==i) {
                console.log('keys[j].value'+j+': '+keys[j].value);
                console.log('num'+j+': '+num);
                num = num.mul((keys[j].value));
                console.log('num'+j+': '+num);
            } else {
                num = num.mul(k_positions_correlative[j]);
                den = den.mul(k_positions_correlative[j].sub(k_positions_correlative[i]));
                console.log('num'+j+': '+num);
                console.log('den'+j+': '+den);
                console.log('p'+j+': '+p);
                console.log('k_positions_correlative[j])'+j+': '+k_positions_correlative[j]);
                console.log('k_positions_correlative[i])'+j+': '+k_positions_correlative[i]);
            }
        }
        den_inv = den.invertm(p); // Intermedian step  
        console.log('den_inv: '+den_inv);
        monomial_j = num.mul(den_inv);
        monomial_i.push(monomial_j);
        console.log(monomial_i.toString(10));
    }
    console.log((monomial_i).toString(10));
    let sum = monomial_i.reduce((a, b) => a.add(b));
    
    return sum.mod(p);
}

function generateKeyPosArray (keys) {
    let keyPositionsArray = [];
    for (let i=1; i<keys.length; i++) {
        keyPositionsArray.push(keys.position);
    }

    return keyPositionsArray;
}

function generateLargePrime(bitLength) {
    let p;
    do {
        p = bignum.prime(bitLength);
    }
    while(p.bitLength() != bitLength);

    return p;
}



