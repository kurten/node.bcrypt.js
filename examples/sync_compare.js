var bcrypt = require('../bcrypt');

var start = Date.now();
var salt = bcrypt.genSaltSync(10);
console.log('salt: ' + salt);
console.log('salt end: ' + (Date.now() - start) + 'ms');
var crypted = bcrypt.hashSync('test', salt);
console.log('crypted: ' + crypted);
console.log('crypted cb end: ' + (Date.now() - start) + 'ms');
console.log('rounds used from hash:', bcrypt.getRounds(crypted));
var res = bcrypt.compareSync('test', crypted);
console.log('compared true: ' + res);
console.log('compared true end: ' + (Date.now() - start) + 'ms');

res = bcrypt.compareSync('bacon', crypted);
console.log('compared false: ' + res);
console.log('compared false end: ' + (Date.now() - start) + 'ms');
console.log('end: ' + (Date.now() - start) + 'ms');
