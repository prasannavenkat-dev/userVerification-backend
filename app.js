const express = require("express");
const app = express();

require("dotenv").config();

const bodyParser = require("body-parser");
app.use(express.json());
bodyParser.urlencoded({ extended: true });

const bcrypt = require("bcrypt");
const saltRounds = 10;
const mongoose = require("mongoose");
mongoose.connect(process.env.DB_URL);

const cors = require("cors");
const corsOptions = {
  origin: "*",
  credentials: true, //access-control-allow-credentials:true
  optionSuccessStatus: 200,
};

app.use(cors(corsOptions)); // Use this after the variable declaration

const PORT = process.env.port || 4000;

const nodemailer = require("nodemailer");

const { google } = require("googleapis");
const OAuth2 = google.auth.OAuth2;

const oauth2Client = new OAuth2(
  process.env.CLIENT_ID, // ClientID
  process.env.CLIENT_SECRET, // Client Secret
  process.env.REDIRECT_URL // Redirect URL
);

oauth2Client.setCredentials({
  refresh_token:
   process.env.REFRESH_TOKEN,
});
const accessToken = oauth2Client.getAccessToken();

//OTP Schema
const otpSchema = new mongoose.Schema({
  verified: Boolean,
  otp: Number,
});
//User Schema
const userSchema = new mongoose.Schema({
  fullName: {
    type: String,
    minlength: 2,
    maxlength: 20,
    required: true,
  },
  age: {
    type: Number,
    required: true,
  },
  gender: {
    type: String,
    required: true,
  },
  mail: {
    type: String,
    required: true,
  },
  password: {
    type: String,
    required: true,
  },
  verifiedUser: otpSchema,
});

const User = mongoose.model("User", userSchema);

//Register User
app.post("/register", async function (req, res) {
  try {
    console.log(req.body);
    const { fullName, age, gender, mail, password } = req.body;
    //Checks If User Existed
    const userExisted = await User.findOne({ mail });

    if (userExisted) {
      console.log("User Already Existed!!");
      res.send({ message: "User Already Existed!!" });
    } else {
      const salt = bcrypt.genSaltSync(saltRounds);
      const hash = bcrypt.hashSync(password, salt);
      const otp = Math.floor(Math.random() * 1000000 + 1);
      const userData = new User({
        fullName,
        age,
        gender,
        mail,
        password: hash,
        verifiedUser: { verified: false, otp: otp },
      });

      userData.save(function (err) {
        if (err) {
          console.log(err);
          res.send({ message: "Registration Failed!" });
        } else {
          console.log("Registered Successfully!!");
          async function sendMail() {
            try {
              //Mail Config
              const smtpTransport = nodemailer.createTransport({
                service: "gmail",
                auth: {
                  type: "OAuth2",
                  user: "prasannavenkatesh.dev@gmail.com",
                  clientId: process.env.CLIENT_ID,
                  clientSecret: process.env.CLIENT_SECRET,
                  refreshToken: process.env.REFRESH_TOKEN,
                  accessToken: accessToken,
                },
                tls: {
                  rejectUnauthorized: false,
                },
              });

              //Mail Options
              const mailOptions = {
                from: "prasannavenkatesh.dev@gmail.com",
                to: mail,
                subject: "Node.js Email with Secure OAuth",
                generateTextFromHTML: true,
                html: `Dear Customer, <br/>Your OTP for USERAUTH app is <b>${otp}</b>. Use this Passcode to complete your registration. Thank you. Secured by OAuth2.`,
              };

              //Sending Mail
               smtpTransport.sendMail(mailOptions, (error, response) => {
                error ? console.log(error) : console.log(response);
                smtpTransport.close();
              });
            } catch (error) {
              console.log("sdsdds");

              console.log(error);
            }
          }
          sendMail();
          res.send({ message: "Registerd Successfully!" });
        }
      });
    }
  } catch (error) {
    console.log(error);
  }
});

//Login User

app.post("/login", function (req, res) {
  try {
    const { mail, password } = req.body;
    User.findOne({ mail }, function (err, user) {
      if (err) {
        console.log(err);
      } else {
        //Checks user if Existed
        if (user) {
          //Checks Verified Account
          if (user.verifiedUser.verified) {
            //Checks Password
            if (bcrypt.compareSync(password, user.password)) {
              res.send({ message: "Login Successfully!!" });
            } else {
              res.send({ message: "Invalid Login!!" });
            }
          } else {
            res.send({ message: "Account Verification Required!!" });
          }
        } else {
          res.send({ message: "User Not existed!!" });
        }
      }
    });
  } catch (error) {
    console.log(error);
  }
});

//Login Verify

app.post("/verification", function (req, res) {
  try {
    const { mail, otp } = req.body;

    User.findOne({ mail }, function (error, data) {
      console.log(data);
      if (data) {
        console.log(data);
        if (!data.verifiedUser.verified) {
          if (data.verifiedUser.otp == otp) {
            User.findOneAndUpdate(
              { mail },
              { verifiedUser: { verified: true } },
              function (err, data) {
                if (err) {
                  console.log("Error Verifying OTP");
                  res.send({ message: "Error Verifyin OTP!" });
                }
                console.log(data);
              }
            );
            console.log("User Account verified!");
            res.send({ message: "User Account verified!" });
          } else {
            console.log("Invalid OTP!!");
            res.send({ message: "Invalid OTP!!" });
          }
        } else {
          console.log("User Account Already verified!");
          res.send("User Account Already verified!");
        }
      } else {
        console.log("User Not Existed!");
        res.send({ message: "User not existed" });
      }
    });
  } catch (error) {
    console.log(error);
  }
});

//App Listener
app.listen(PORT, function (err) {
  if (err) {
    console.log(err);
  } else {
    console.log(`Server Started at ${PORT}`);
  }
});
