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
console.log(build(3,5,11,17));
function build(t, n, k, p) {
    let polynomial = [], Fx = [], coef = 0, xPow = 0, monomial = 0;
    
    if (k > p) {
        return new Error("k must be smaller than p")
    }
    // Generate shares
    for (let i=0; i<n; i++) {
        for (let j=1; j<t; j++) {
            if (j==1) coef = 8;
            else if (j==2) coef = 7;
            xPow = Math.pow(i+1, j);
            monomial = coef*xPow;
            polynomial.push(monomial);
        }
        let sum = polynomial.reduce((a, b) => a + b, 0);
        polynomial = [];
        Fx.push(k+sum);
    }
    
    return Fx;
}

function multiply(a,b) {
    if(a == null) {
        return b;
    } else {
        return a*b;
    }
}

function f(keys) {
    var result = 0;
    for(var i=0;i<keys.length;i++) {
        console.log(keys[i]);
        var result_i = null;
        for(let j=0;j<keys.length;j++) {
            if(j==i) {
                console.log("K ",keys[j]);
                result_i = multiply(result_i, keys[j]);
            } else {
                console.log("NUM ", keys[j])
                console.log("DEN ", keys[j], " - ", keys[i])
                result_i = multiply(result_i,( keys[j] / (keys[j] - keys[i] ) ));
            }
        }
        result = result + result_i;
    }
    return result;
}

var k = [1,2,4];
console.log(f(k));

 /*function lagrangeInterpolation(keys, keysPositions){
    let num;
    let sharesLength = keys.length;
    let k;
    if (sharesLength > this.t) throw console.error('only t keys');
    
    for (let i=0; i<sharesLength; i++) {
        for (let j=1; j<sharesLength; j++) {
             num *= keysPositions[j];
             den *= keysPositions[j]-keysPositions[i];       
        }
        polynomial.push(monomial);
        
    }


 }
    

/*
Generate prime numbers
*/
function generateLargePrime(bitLength) {
    let p;
    do {
        p = bignum.prime(bitLength);
    }
    while(p.bitLength() != bitLength);

    return p;
}

