var bcrypt = require('../bcrypt');

// (function printSalt() {
//   bcrypt.genSalt(10, function(err, salt) {
//     console.log('salt: ' + salt);
//     printSalt();
//   });
// })()
var salt = bcrypt.genSaltSync(10);
console.log(salt);
var pw = bcrypt.hashSync('123456', salt);
console.log(pw);
console.log(bcrypt.compareSync('123456', pw));