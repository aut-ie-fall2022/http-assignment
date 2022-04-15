const jwt = require('jsonwebtoken');
const user = require('../../models/dummyUser');
var XMLHttpRequest = require('xhr2');

module.exports = (app) => {

    app.post('/user/login', (req, res, next) => {
        const { body } = req;
        const { username } = body;
        const { password } = body;
        let flag = 1; 
        user.forEach(function(u) {
            //checking to make sure the user entered the correct username/password combo
            if(username === u.username && password === u.password) { 
                //if user log in success, generate a JWT token for the user with a secret key
                jwt.sign({user}, 'privatekey', { expiresIn: '1h' },(err, token) => {
                    if(err) { console.log(err) }    
                    res.send(token);
                });
                flag = 0;
            }
        });
        if(flag == 1){
            //send Forbidden (401)
            res.sendStatus(401);
            console.log('ERROR: Could not log in');
        }
    })

    //This is a protected route 
    app.get('/user/data', checkToken, (req, res) => {
        //verify the JWT token generated for the user
        jwt.verify(req.token, 'privatekey', (err, authorizedData) => {
            if(err){
                //If error send Forbidden (403)
                console.log('ERROR: Could not connect to the protected route');
                res.sendStatus(403);
            } else {
                //If token is successfully verified, we can send the autorized data
                // res.json({
                //     message: 'Successful log in',
                //     authorizedData
                // });
                console.log('SUCCESS: Connected to protected route');
                const xhr = new XMLHttpRequest();
                xhr.open("GET", 'http://localhost:6000', true);
                xhr.send( null );
                xhr.onreadystatechange = function() {
                    if (xhr.readyState == 4)
                        res.send(xhr.responseText);
                };
            }
        })
    });

}

//Check to make sure header is not undefined, if so, return Forbidden (403)
const checkToken = (req, res, next) => {
    const header = req.headers['authorization'];

    if(typeof header !== 'undefined') {

        const bearer = header.split(' ');
        const token = bearer[1];

        req.token = token;

        next();
    } else {
        //If header is undefined return Forbidden (403)
        res.sendStatus(403)
    }
}