const jwt = require('jsonwebtoken');

function verifyAccessToken(req,res,next){
    try{
        const bearerHeader = req.headers['authorization']
        if(typeof bearerHeader !== "undefined"){
        const bearer = bearerHeader.split(' ');
        const bearerToken = bearer[1];
        // req.token = bearerToken;
        jwt.verify(bearerToken,process.env.ACCESS_SECRET||'secretsecret');
        next();
    }else{
        res.sendStatus(403)
    }
    }catch(err){
        console.log(err);
        res.sendStatus(403);
    }
    
}

function generateAccessToken(user){
   return jwt.sign({user},process.env.ACCESS_SECRET||'secretsecret')
}

module.exports = {verifyAccessToken , generateAccessToken}