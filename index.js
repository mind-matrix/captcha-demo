const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const svgc = require('svg-captcha');
const { sha256 } = require('crypto-hash');
const mongoose = require('mongoose');
const rateLimit = require("express-rate-limit");
const loadtest = require('loadtest');
const expressWs = require('express-ws');

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});

mongoose.connect("mongodb://localhost:27017/captcha", { useUnifiedTopology: true, useNewUrlParser: true});

const userSchema = new mongoose.Schema({
    name: String,
    enrollment: String,
    phone: String
});

const User = mongoose.model("User", userSchema);

const app = express();

app.use(cors({
  origin:['http://localhost:8080'],
  methods:['GET','POST'],
  credentials: true
}));

const SECRET = 'MOGADISHU';

app.use(bodyParser.json());

app.use(express.static('public'));

app.use('/captcha/', limiter);

app.get('/captcha', async (req, res) => {
  var captcha = svgc.create({ noise: 3 });
  res.status(200).send({
    data: captcha.data,
    hash: await sha256(SECRET + captcha.text)
  });
});

app.post('/captcha/signup', async (req, res) => {
  if(req.body.name && req.body.roll && req.body.phone && req.body.captcha && req.body.hash) {
    if(await sha256(SECRET + req.body.captcha) === req.body.hash) {
      var user = new User({
        name: req.body.name,
        roll: req.body.roll,
        phone: req.body.phone
      });
      user.save();
      res.status(200).send({
        auth: true,
        name: req.body.name,
        roll: req.body.roll,
        phone: req.body.phone
      });
    } else {
      res.status(403).send({
        error: `Wrong Captcha`
      });
    }
  } else {
    res.status(403).send({
      error: `Incomplete or Invalid data`
    });
  }
});

app.post('/nocaptcha/signup', async (req, res) => {
  if(req.body.name && req.body.roll && req.body.phone) {
    var user = new User({
      name: req.body.name,
      roll: req.body.roll,
      phone: req.body.phone
    });
    user.save();
    res.status(200).send({
      auth: true,
      name: req.body.name,
      roll: req.body.roll,
      phone: req.body.phone
    });
  } else {
    res.status(403).send({
      error: `Incomplete or Invalid data`
    });
  }
});

app.get('/me', (req, res) => {
  if(req.session.user) {
    res.status(200).send(req.session.user);
  } else {
    res.status(404).send({
      error: `User not signed in`
    });
  }
});

app.listen(8000, () => {
  console.log(`Server running at port 8000`);
});

function randstr(length, onlyDigits = false) {
  var result           = '';
  let characters;
  if(onlyDigits)
   characters          = '0123456789';
  else
   characters           = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  var charactersLength = characters.length;
  for ( var i = 0; i < length; i++ ) {
     result += characters.charAt(Math.floor(Math.random() * charactersLength));
  }
  return result;
}

const loadtester = express();

expressWs(loadtester);

loadtester.use(cors());

loadtester.ws('/test', function (ws, req) {
  ws.on('message', function (msg) {
    var message = JSON.parse(msg);
    let url;
    if(message.page === 'nocaptcha') {
      url = `http://localhost:8000/nocaptcha/signup`;
    } else if(message.page === 'captcha') {
      url = `http://localhost:8000/captcha/signup`
    }
    loadtest.loadTest({
      url,
      method: 'POST',
      body: JSON.stringify({
        name: randstr(10),
        roll: randstr(10),
        phone: randstr(10),
        captcha: randstr(10),
        hash: randstr(32)
      }),
      contentType: 'application/json',
      agentKeepAlive: true,
      requestsPerSecond: message.rps || 5000,
      maxRequests: message.max || 200000,
      statusCallback (error, result, latency) {
        ws.send(JSON.stringify({
          latency,
          error,
          result
        }));
      },
      concurrency: 4
    }, (err) => {
      ws.send({
        error: err
      });
    });
  });
});

loadtester.listen(8001, () => {
  console.log(`Load Tester running at 8001`);
});