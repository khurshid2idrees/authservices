const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const UserModel = require("./Models/UserModel");

const app = express();

// middlewares
app.use(express.json());
app.use(
  cors({
    origin: "http://localhost:3000",
    methods: ["GET", "POST", "PUT", "DELETE"],
    credentials: true,
  })
);
app.use(cookieParser());
app.use(express.static("public"));

mongoose
  .connect("mongodb://localhost:27017/authservice")
  .then((res) => console.log("database connected"))
  .catch((err) => console.log(err));

const verifyUser = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) {
    return res.json("token is missing");
  } else {
    jwt.verify(token, "jwt-secret-key", (err, decoded) => {
      if (err) {
        return res.json("token is wrong");
      } else {
        req.email = decoded.email;
        req.name = decoded.name;
        next();
      }
    });
  }
};

app.get("/", verifyUser, (req, res) => {
  return res.json({ email: req.email, name: req.name });
});

app.post("/register", (req, res) => {
  const { username, email, password } = req.body;

  bcrypt
    .hash(password, 10)
    .then((bcrypedpassword) => {
      UserModel.create({
        name: username,
        email: email,
        password: bcrypedpassword,
      })
        .then((user) => {
          res.json("success");
        })
        .catch((err) => {
          console.log(err);
        });
    })
    .catch((err) => console.log(err));
});

app.post("/login", (req, res) => {
  const { email, password } = req.body;

  UserModel.findOne({ email: email })
    .then((user) => {
      if (!user) {
        return res.json("user does not exist");
      } else {
        bcrypt.compare(password, user.password, (err, response) => {
          if (response) {
            const token = jwt.sign(
              { name: user.name, email: user.email },
              "jwt-secret-key",
              { expiresIn: "1d" }
            );
            res.cookie("token", token);
            return res.json("success");
          } else {
            return res.json("password did not match");
          }
        });
      }
    })
    .catch((err) => {
      console.log(err);
    });
});

app.get("/logout", (req, res) => {
  res.clearCookie("token");
  return res.json("success");
});

app.listen(4000, () => {
  console.log("server started at port 4000");
});
