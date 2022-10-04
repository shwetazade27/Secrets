//jshint esversion:6
require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");

//   require express session 
const session = require("express-session");

//  require remaining 
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");

//const encrypt=require("mongoose-encryption");
//const md5 =require("md5");
//const bcrypt=require("bcrypt");
//const saltRounds=10;

const app = express();
//console.log(process.env.API_KEY);
//console.log(md5("!23456"));

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(
  bodyParser.urlencoded({
    extended: true,
  })
);

//set up session 

app.use(
  session({
    secret: "Our little secret.",
    resave: false,
    saveUninitialized: false,
  })
);

//  telling passport to use session 
app.use(passport.initialize());
app.use(passport.session());

//Set up default mongoose connection
mongoose.connect("mongodb://localhost:27017/userDB", { useNewUrlParser: true });
// mongoose.set("useCreateIndex", true); // ==> to fix error names (DeprecationWarning)

// **** Schema encrypted type ****
const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  secret: String,
});

//userSchema.plugin(encrypt, { secret: process.env.SECRET,encryptedFields: ["password"] });

//setup mongoose schema plugin
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
// **** Model ****
const User = new mongoose.model("User", userSchema);

//  from npm website of passport-local-mongoose
passport.use(User.createStrategy());
passport.serializeUser(function (user, cb) {
  process.nextTick(function () {
    cb(null, { id: user.id, username: user.username });
  });
});

passport.deserializeUser(function (user, cb) {
  process.nextTick(function () {
    return cb(null, user);
  });
});

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
      passReqToCallback: true,
    },
    function (request, accessToken, refreshToken, profile, done) {
      User.findOrCreate({ googleId: profile.id }, function (err, user) {
        return done(err, user);
      });
    }
  )
);

app.get("/", function (req, res) {
  res.render("home");
});

app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

app.get("/login", function (req, res) {
  res.render("login");
});

app.get("/register", function (req, res) {
  res.render("register");
});

app.get("/secrets", function (req, res) {
  // if(req.isAuthenticated()){
  //     res.render("secrets");
  // }
  // else{
  //     res.redirect("/login");
  // }
  User.find({ secret: { $ne: null } }, function (err, foundUser) {
    if (err) {
      console.log(err);
    } else {
      if (foundUser) {
        res.render("secrets", { userWithSecrets: foundUser });
      }
    }
  });
});

app.get("/submit", function (req, res) {
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

app.post("/submit", function (req, res) {
  const submittedSecret = req.body.secret;

  console.log(req.user.id);
  User.findById(req.user.id, function (err, foundUser) {
    if (err) {
      console.log(err);
    } else {
      if (foundUser) {
        foundUser.secret = submittedSecret;
        foundUser.save(function () {
          res.redirect("/secrets");
        });
      }
    }
  });
});

// ****** We need call back function here : On /logout : *****
app.get("/logout", function (req, res) {
  req.logout(function (err) {
    if (err) {
      console.log(err);
    } else {
      res.redirect("/");
    }
  });
});

app.post("/register", function (req, res) {
  User.register(
    { username: req.body.username },
    req.body.password,
    function (err, user) {
      if (err) {
        console.log(err);
        res.redirect("/register");
      } else {
        passport.authenticate("local")(req, res, function () {
          res.redirect("/secrets");
        });
      }
    }
  );
});

app.post("/login", function (req, res) {
  const user = new User({
    username: req.body.username,
    password: req.body.password,
  });
  req.login(user, function (err) {
    if (err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function () {
        res.redirect("/secrets");
      });
    }
  });
});

// ***** Port Section *****
app.listen(3000, function () {
  console.log("Server started on port 3000.");
});

/*   const username=req.body.username;
    const password= req.body.password;

    User.findOne({email:username},function(err,foundUser){
 if(err){
    console.log(err);
 }
 else{
    if(foundUser){
        bcrypt.compare(password, foundUser.password, function(err, result) {
            // result == true
            if(result===true){
                res.render("secrets");
            }
        });
    }
 }
});*/

/* bcrypt.hash(req.body.password, saltRounds, function(err, hash) { 
    const newUser= new User({
        email:req.body.username,
        password:hash
    });
    newUser.save(function(err){
      if(err)  {
        console.log(err);
      }
      else{
        res.render("secrets");
      }
    }); 
    });*/
