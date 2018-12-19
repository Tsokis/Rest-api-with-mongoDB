const errors = require('restify-errors');
const bcrypt = require('bcryptjs');
const User = require('../models/User');
const auth = require('../auth');
const jwt = require('jsonwebtoken');
const config = require('../config');

module.exports = server => {
    //Register User
    server.post('/register',(req,res,next)=>{
        //destructuring
        const {email,password} = req.body;
        const user = new User({
            email,
            password
        });
        bcrypt.genSalt(10, (err,salt)=>{
            bcrypt.hash(user.password,salt,async (err,hash)=>{
                //hash password
                user.password = hash;
                //save the user
                try{
                    const newUser = await user.save();
                    res.send(201);
                    next();
                }catch(err){
                    return next(new errors.InternalError(err.message))
                }
            });
        })
    });
    //Authenticate User
    server.post('/auth', async (req,res,next)=> {
        const {email,password} = req.body
        try{
            //authenticate user
            const user =await auth.authenticate(email,password);
            //create JWT
            const token = jwt.sign(user.toJSON(),config.JWT_SECRET, {
                expiresIn: '15m'
            });
            const { iat,exp } = jwt.decode(token);
            //respond with token
            res.send({iat,exp,token});            
            next();
        }catch(error){
            //user unauthorized
            return next(new errors.UnauthorizedError(error));
        }
    });
};