
        require('dotenv').config(); 
      
        let express = require('express'),
        app = express(),
      
        jwt = require('jsonwebtoken'),
        bodyParser = require('body-parser'),
        passport = require('passport'),
        JwtStrategy = require('passport-jwt').Strategy,
        ExtractJwt = require('passport-jwt').ExtractJwt;
        let passgen=require('./helper/passgen');
        
        
           
        let User = require('./database/user');
        let jwtOptions = {};
        jwtOptions.jwtFromRequest = ExtractJwt.fromAuthHeaderAsBearerToken();
        jwtOptions.secretOrKey = process.env.SECRET;
    
        
        let myStrategy = new JwtStrategy(jwtOptions, (payload, done) => {
            let email = payload.email;
            let name = payload.name;
            User.findByEmail(email)
                .then(user => {
                    if (user.name == name) {
                        done(null, user);
                    }
                })
                .catch(err => done(err, null));
        });
       
        app.use(bodyParser.json());
        app.use(bodyParser.urlencoded({ extended: true }));
        passport.use(myStrategy);


    
        app.post('/api/login', (req, res) => {
            let email = req.body.email;
            let pass = req.body.password;
    
            User.findByEmail(email)
                .then(user => {
                    passgen.compare(pass, user.password)
                        .then(result => {
                            let payload = { email: user.email, name: user.name };
                            let token = jwt.sign(payload, process.env.SECRET);
                            res.send({ con: true, token: token,msg:user , successmsg: "Successfully Login" });
                        })
                        .catch(err => res.send({ con: false, msg: err, errmsg: "Password Wrong" }))
                })
                .catch(err => res.send({ con: false, msg: err, errmsg: "No user with that email" }))
    
        });
    
        app.post('/api/register', (req, res) => {
            let name = req.body.name;
            let email = req.body.email;
            let password = req.body.password;
    
            passgen.encrypt(password)
                .then(pass => {
                    let uObj = {
                        "name": name,
                        "email": email,
                        "password": pass
                    };
                    User.save(uObj)
                        .then(user => res.send({ con: true, msg: user , successmsg: "Successfully Register"}))
                        .catch(err => res.send({ con: false, msg: err ,errmsg: "Something Wrong"}))
                }).catch(err => res.send({ con: false, msg: err }))
        });

        app.get('/user/all', passport.authenticate('jwt', { session: false }), (req, res) => {
            User.all()
                .then(result => res.json({ con: true, msg: result }))
                .catch(err => res.json({ con: false, msg: err }));
        })
        
        app.listen(process.env.PORT, () => {
            console.log("server is running at" + process.env.PORT);
        });
            
       
    