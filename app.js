require("dotenv").config();
const bodyParser = require("body-parser");
const express = require("express");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");
const app = express();

app.use(bodyParser.urlencoded({
    extended: true
}));
app.use(express.static("public"));
app.set('view engine', 'ejs');

app.use(session({
    secret: "Our little secret.",
    resave: false,
    saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDb", {
    useNewUrlParser: true,
    useUnifiedTopology: true
});
mongoose.set("useCreateIndex", true);

const UserSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: String
});

UserSchema.plugin(passportLocalMongoose);
UserSchema.plugin(findOrCreate);

const UserModel = new mongoose.model("User", UserSchema);

passport.use(UserModel.createStrategy());

passport.serializeUser(function (user, done) {
    done(null, user.id);
});

passport.deserializeUser(function (id, done) {
    UserModel.findById(id, function (err, user) {
        done(err, user);
    });
});

passport.use(new GoogleStrategy({
        clientID: process.env.CLIENT_ID,
        clientSecret: process.env.CLIENT_SECRET,
        callbackURL: "http://localhost:3000/auth/google/secrets",
        userProfileURL: 'https://www.googleapis.com/oauth2/v3/userinfo'
    },
    function (accessToken, refreshToken, profile, cb) {
        console.log(profile);
        UserModel.findOrCreate({
            googleId: profile.id
        }, function (err, user) {
            return cb(err, user);
        });
    }
));

app.get("/", function (req, res) {
    res.render("home");
});

app.get("/auth/google",
    passport.authenticate('google', {
        scope: ["profile"]
    }));

app.get("/auth/google/secrets",
    passport.authenticate("google", {
        failureRedirect: "/login"
    }),
    function (req, res) {
        res.redirect("/secrets");
    });

app.get("/register", function (req, res) {
    res.render("register");
});

app.get("/login", function (req, res) {
    res.render("login");
});

app.get("/logout", function (req, res) {
    req.logout();
    res.redirect("/");
});

app.get("/secrets", function (req, res) {
    UserModel.find({"secret": {$ne: null}}, function(err, foundusers){
        if(err){
            console.log(err);
        }else{
            if(foundusers){
                res.render("secrets", {usersWithSecrets: foundusers});
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

app.post("/register", function (req, res) {

    UserModel.register({
        username: req.body.username
    }, req.body.password, function (err) {
        if (err) {
            console.log(err);
            res.redirect("/register");
        } else {
            passport.authenticate("local")(req, res, function () {
                res.redirect("/secrets");
            });
        }
    });

});


app.post("/login", function (req, res) {

    const user = new UserModel({
        username: req.body.username,
        password: req.body.password
    });

    req.logIn(user, function (err) {
        if (err) {
            console.log(err);
        } else {
            passport.authenticate("local")(req, res, function () {
                res.redirect("/secrets");
            });
        }
    });

});

app.post("/submit", function (req, res) {
    const secretSubmitted = req.body.secret;

    UserModel.findById(req.user.id, function (err, founduser) {
        if (err) {
            console.log(err);
        } else {
            if (founduser) {
                founduser.secret = secretSubmitted;
                founduser.save(function () {
                    res.redirect("/secrets");
                });
            }
        }
    });
});

app.listen(3000, function () {
    console.log("server is up and running");
});