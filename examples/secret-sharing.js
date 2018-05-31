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



function f(keys, k_positions_correlative, p) {
    var result_i = bignum(0);
    for(var i=0;i<keys.length;i++) {
        var result_j = bignum(1);
        for(let j=0;j<k_positions_correlative.length;j++) {
            if(j==i) {
                result_j = result_j.mul(keys[j]);
            } else {
                let proba;
                console.log("proba"+ (proba = bignum(1).invertm(17)));
                const num = k_positions_correlative[j].mod(p);
                const den = k_positions_correlative[j].sub(k_positions_correlative[i]);
                console.log('num'+j+': '+num);
                console.log('den'+j+': '+den);
                const invDenMod = (k_positions_correlative[j].sub(k_positions_correlative[i])).invertm(p); // Intermedian step  
                console.log('p'+j+': '+p);
                console.log('invDenMod'+j+': '+invDenMod);
                console.log('k_positions_correlative[j])'+j+': '+k_positions_correlative[j]);
                console.log('k_positions_correlative[i])'+j+': '+k_positions_correlative[i]);
                const mon2 = num.mul(invDenMod);
                const mon = num.mul(invDenMod);
                console.log('monomial2'+j+': '+mon2);
                console.log('monomial'+j+': '+mon);
                result_j = result_j.mul(mon);
                console.log('mon*prev_mon'+j+': '+result_j);
            }
        }
        console.log('now: '+result_j);
        result_i = result_i.add(result_j);
        console.log(result_i.toString(10));
    }
    console.log(result_i.mod(p).toString(10));
    return result_i.mod(p);
}

var k = [bignum(9), bignum(4), bignum(2)];
var k_positions_correlative = [bignum(1), bignum(2), bignum(4)];
const p = bignum(17);
console.log(f(k,k_positions_correlative,p));

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

