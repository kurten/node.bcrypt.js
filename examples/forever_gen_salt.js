var bcrypt = require('../bcrypt');

// (function printSalt() {
//   bcrypt.genSalt(10, function(err, salt) {
//     console.log('salt: ' + salt);
//     printSalt();
//   });
// })()
var salt = bcrypt.genSalt(10);
console.log(salt);
var pw = bcrypt.hash('123456', salt);
console.log(pw);
console.log(bcrypt.compare('123456', pw));