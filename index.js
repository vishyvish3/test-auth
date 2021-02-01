const express = require("express");
const mongodb = require("mongodb");
const cors = require("cors");
const dotenv = require("dotenv");
const bcrypt = require("bcrypt");
const nodemailer = require("nodemailer")

const app = express();
app.use(cors());
app.use(express.json());

dotenv.config();

const mongoClient = mongodb.MongoClient;
const objectId = mongodb.ObjectID;
const port = process.env.PORT || 3000;
let dbUrl = process.env.DB_URL || "mongodb://127.0.0.1:27017";






app.listen(port, () => console.log("Password reset app server running on port:", port));

var transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.email,
    pass: process.env.password
  },
  tls: {
    rejectUnauthorized: false
  }
});

var mailOptions = {
  from: process.env.email, 
  to: '', 
  subject: "Reset password app", 
  html: '', 
};



app.put("/reset-password", async (req, res) => {
  try {
    let client = await mongodb.connect(dbUrl);
    let db = client.db("emailId_db");
    let result = await db.collection("users").findOne({ email: req.body.email });
    let salt = await bcrypt.genSalt(10);

    if (result) {
      let randomString = { 'randomString': salt };
      console.log("randome string is:" + JSON.stringify(randomString) + " and salt is: " + salt);
      await db.collection("users").findOneAndUpdate({ email: req.body.email }, { $set: randomString });
      mailOptions.to = req.body.email;
      let resetUrl = process.env.resetUrl;
      resetUrl = resetUrl + "?id=" + result._id + "&rs=" + randomString.randomString;

      let sampleMail = '<p>Hi,</p>'
        + '<p>Please click on the link below to reset your Password</p>'
        + '<a target="_blank" href=' + resetUrl + ' >' + resetUrl + '</a>'
        + '<p>Regards,</p>'

      let resetMailToBeSend = sampleMail;
    
      mailOptions.html = resetMailToBeSend;
      await transporter.sendMail(mailOptions, function (err, info) {
        if (err) {
           res.status(401).json({
      message: "Internal mail Server Error"
    });
        } else {
          console.log(info, "mail sent")
        }
      });

      res.status(200).json({
        message: "Verification mail is sent"
      });

    }
    else {
      res.status(400).json({
        message: "User doesn't exist"
      })
    }
    client.close();
  }
  catch (error) {
    res.status(500).json({
      message: "Internal Server gmail Error"
    });
  }
});


app.put("/change-password/", async (req, res) => {

  console.log(req.query.id, req.query.rs);
  try {

    let client = await mongodb.connect(dbUrl, { useNewUrlParser: true, useUnifiedTopology: true });
    let db = client.db("emailId_db");
    let checkString = await db.collection("users").find({ $and: [{ _id: objectId(req.query.id) }, { "randomString": req.query.rs }] }).toArray();
    if (checkString.length !== 0) {
      let salt = await bcrypt.genSalt(10);
      let hash = await bcrypt.hash(req.body.password, salt);
      req.body.password = hash;
      await db.collection("users").findOneAndUpdate({ _id: objectId(req.params.id) }, { $set: { "password": req.body.password } })

      res.status(200).json({
        message: "Password Updated Successfully"
      });
    } else {
      res.status(200).json({
        message: "Invalid url string"
      });
    }
    client.close();
  }
  catch (error) {
    res.status(500).json({
      message: "Invalid url string"
    })
  }
});

app.post("/register", async (req, res) => {
  try {
    let client = await mongodb.connect(dbUrl);
    let db = client.db("emailId_db");
    console.log(db)
    let data = await db.collection("users").findOne({ email: req.body.email });
    if (data) {
      res.status(400).json({
        message: false,
      });
    } else {
      let salt = await bcrypt.genSalt(10);
      let hash = await bcrypt.hash(req.body.password, salt);
      req.body.password = hash;
      let result = await db.collection("users").insertOne(req.body);
      res.status(200).json({
        message: true,
      });
    }
    client.close();
  } catch (error) {
    res.status(500).json({
      message: "servererror"
    });
  }
});

app.post("/login", async (req, res) => {
  try {
    let email = req.body.email;
    let client = await mongodb.connect(dbUrl);
    let db = client.db("emailId_db");
    let data = await db.collection("users").findOne({ email });
    if (data) {
      let isaMatch = await bcrypt.compare(req.body.password, data.password);
      if (isaMatch) {
        res.status(200).json({ message: "login" });
      } else {
        res.status(400).json({ message: "loginerror" });
      }
    } else {
      res.status(400).json({
        message: "notregistered",
      });
    }
    client.close();
  } catch (error) {
    res.status(500).json({
      message: error
    });
  }
});



