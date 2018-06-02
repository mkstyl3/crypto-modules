'use strict';

const { Key }  = require('../lib/secret-sharing');
const sss = require('../lib/secret-sharing');
const bignum = require('bignum');

/**
 * 	Simple implementation of Shamir's Secret Sharing (SSS) for nodeJS
 */

const BITLENGHT = 512;

const keys = sss.genShares(3, 5, 11, BITLENGHT);
console.log(' ');
console.log('Example of keys generation');
console.log(' ');
for (let i = 0, len = keys.length; i < len; i++) {
    ++i;
    console.log('k'+i+': '+keys[--i].value.toString(10));
}

const p = "ed3ec69af9d19dbd91e638c0c074e1001a94295427ebf5abad9fed426763f1b8e3961da78276709e0d800861b61f6452fbda72972badd121a4f34a1e98a36303";

console.log(' ');
console.log('Example of key combining using the following keys:');
console.log(' ');
const k = [new Key(22 ,1, p), new Key(53 ,2, p), new Key(175 ,4, p)];
for (let i = 0, len = k.length; i < len; i++) {
    ++i;
    console.log('k'+k[--i].position+': '+k[i].value);
}

const kFinal = sss.laGrangeInterpolation(k);
console.log('kObtained: '+kFinal);







