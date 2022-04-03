var XMLHttpRequest = require('xhr2');
const jwt = require('jsonwebtoken');
const users = require('../../users/uesrList');

module.exports = (app) => {

    app.post('/login', (req, res, next) => {
        const { body } = req;
        const { username } = body;
        const { password } = body;

        //checking to make sure the user entered the correct username/password combo
        let found = false;
        for (let i = 0; i < users.length; i++)
        {
            user = users[i];
            if(username === user.username && password === user.password) { 
                //if user log in success, generate a JWT token for the user with a secret key
                jwt.sign(user, 'privatekey', { expiresIn: '1h' },(err, token) => {
                    if(err) { console.log(err) }
                    console.log('username: ' + user.username + ' password: ' + user.password);
                    res.send(token);
                });
                found = true;
                break;
            } 
        }
        if (found !== true){
            console.log('ERROR: Could not log in');
            res.sendStatus(401);
        }
    })

    //This is a protected route 
    app.get('/*', checkToken, (req, res) => {
        //verify the JWT token generated for the user
        jwt.verify(req.token, 'privatekey', (err, authorizedData) => {
            if(err){
                //If error send Forbidden (403)
                console.log('ERROR: Could not connect to the protected route');
                res.sendStatus(403);
            } else {
                //If token is successfully verified, we can send the autorized data 
                let url;
                if (req.originalUrl === '/') {
                    url = 'http://0.0.0.0:80';
                }
                else {
                    url = 'http://0.0.0.0' + req.originalUrl + ':80';
                }
                const priviledge = authorizedData.priviledge;
                if (priviledge === 'all')
                {
                    const request = new XMLHttpRequest();
                    console.log('URL: ' + url)
                    request.open("GET", url, true);
                    request.send(null);
                    request.onreadystatechange = function() {
                        if (request.readyState == 4)
                            res.send(request.responseText);
                    };
                }
                else {
                    res.json({
                        message: 'unauthorised'
                    });
                    console.log('ERROR: Connected to unauthorised route');
                }
            }
        })
    });

}

//Check to make sure header is not undefined, if so, return Forbidden (403)
const checkToken = (req, res, next) => {
    const header = req.headers['authorization'];
    if(typeof header !== 'undefined') {
        req.token = header;
        next();
    } else {
        //If header is undefined return Forbidden (403)
        res.sendStatus(403)
    }
}
