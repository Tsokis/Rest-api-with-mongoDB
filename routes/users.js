const errors = require('restify-errors');
const bcrypt = require('bcryptjs');
const User = require('../models/User');

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
}