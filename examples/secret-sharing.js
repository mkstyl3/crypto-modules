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

 function lagrangeInterpolation(sharesArray, sharesPosition){
    let num;
    let sharesLength = sharesArray.length;
    let k;
    if (sharesLength > this.t) throw console.error('only t keys');
    
    for (let i=0; i<sharesLength; i++) {
        for (let j=1; j<sharesLength; j++) {
             num *= sharesPosition[j];
             den *= sharesPosition[j]-sharesPosition[i];       
        }
        polynomial.push(monomial);
        
    }


 }
    console.log(LagrangeFormaI(new Array(1,2,4)));
    function LagrangeFormaI(x) {
		var suma = 0;
		for (var i = 0; i < N; i++) {
			var produs = y_array[i];
			for (var j = 0; j < N; j++) {
				if (i != j) {
					produs *= ( (x - x_array[j]) / (x_array[i] - x_array[j]) );
				}
			}
			suma += produs;
		}
		return suma;
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

