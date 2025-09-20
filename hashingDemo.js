const bcrypt = require('bcrypt');

const password = "mySecret123";
const saltRounds = 12; 


bcrypt.hash(password, saltRounds, function(err, hash) {
    if (err) {
        console.error("Error hashing password:", err);
        return;
    }
    console.log("Hashed Password (to be stored in DB):", hash);


    bcrypt.compare(password, hash, function(err, result) {
        if (err) {
            console.error("Error comparing passwords:", err);
            return;
        }
        console.log("Password verification result:", result);     });


    bcrypt.compare("wrongPassword", hash, function(err, result) {
        console.log("Wrong password verification result:", result); 
    });
});