var crypto = require('crypto');
var sha256 = crypto.createHash('sha256').update('Apple').digest('base64');
console.log(sha256);