import env from "dotenv";
env.config();
import express from "express";
import bodyParser from "body-parser";
import ejs from "ejs";
import mongoose from "mongoose";
import session from "express-session";
import passport from "passport";
import passportLocalMongoose from "passport-local-mongoose";
import GoogleStrategy from "passport-google-oauth20";
GoogleStrategy.Strategy;
import findOrCreate from 'mongoose-findorcreate';


const app = express();
app.use(express.static("public"));
app.set('view engine', "ejs");
app.use(bodyParser.urlencoded({
  extended: true
}));

app.use(session({
  secret: "OurLittleSecret",
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://127.0.0.1/userDB");

const userSchema = new mongoose.Schema({
  googleId: String,
  email: String,
  password: String,
  secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(user, done) {
  done(null, user);
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    // console.log(profile);

    User.findOrCreate({
      googleId: profile.id
    }, function(err, user) {
      return cb(err, user);
    });
  }
));

app.get('/', (req, res) => {
  res.render("home");
})

app.get('/auth/google',
  passport.authenticate("google", {
    scope: ["profile"]
  })
);

app.get("/auth/google/secrets",
  passport.authenticate("google", {
    failureRedirect: "/login"
  }),
  function(req, res) {
    // Successful authentication, redirect to secrets
    res.redirect('/secrets');
  });

app.get('/login', (req, res) => {
  res.render("login");
})

app.get('/register', (req, res) => {
  res.render("register");
})

app.get("/secrets", (req, res) => {
  User.find({"secret": {$ne: null}}, (err, foundUsers)=>{
    if (err) {
      console.log(err);
    } else {
      if (foundUsers) {
        res.render("secrets", {usersWithSecrets: foundUsers});
      }
    }
  })
});

app.get('/logout', (req, res, next) => {
  req.logout((err) => {
    if (err) {
      console.log(err);
    }
  });
  res.redirect('/');
});

app.get('/submit', (req, res) => {
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect('/login');
  }
})

app.post("/register", (req, res) => {
  User.register({
    username: req.body.username
  }, req.body.password, (err, user) => {
    if (err) {
      console.log(err);
      res.redirect('/register');
    } else {
      passport.authenticate("local")(req, res, () => {
        res.redirect('/secrets');
      })
    }
  })
});

app.post("/login", (req, res) => {
  const user = new User({
    username: req.body.username,
    password: req.body.password
  });

  req.login(user, (err) => {
    if (err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, () => {
        res.redirect('/secrets');
      })
    }
  })
});

app.post("/submit", (req, res) => {
  const submittedSecret = req.body.secret;

  User.findById(req.user._id, (err, foundUser) => {
    if (err) {
      console.log(err);
    } else {
      if (foundUser) {
        foundUser.secret = submittedSecret;
        foundUser.save(() => {
          res.redirect('/secrets');
        })
      }
    }
  })
})



app.listen("3000", () => {
  console.log("Server started at port 3000.");
});
