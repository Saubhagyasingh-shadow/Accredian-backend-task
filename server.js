import express from 'express';
import mysql from 'mysql';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import cookieParser from 'cookie-parser';

const saltRounds = 10; // Instead of 'secret', use a salt rounds value

const app = express();
app.use(express.json());
const allowlist = /^http:\/\/localhost:300\d*/;

app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin || allowlist.test(origin)) {
        callback(null, true);
      } else {
        callback(new Error('Not allowed by CORS'));
      }
    },
    credentials: true,
  })
);
app.use(cookieParser());

const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'signup',
});

const verifyUser = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) {
    return res.status(401).json({ Error: 'You are not authenticated' });
  } else {
    jwt.verify(token, 'jwt-secret-key', (err, decoded) => {
      if (err) {
        return res.status(401).json({ Error: 'Token is not valid' });
      } else {
        req.name = decoded.name;
        next();
      }
    });
  }
};

app.get('/', verifyUser, (req, res) => {
  return res.json({ Status: 'SUCCESS', name: req.name });
});

app.post('/register', (req, res) => {
  const sql = 'INSERT INTO login (`name`, `email`, `password`) VALUES (?)';
  bcrypt.hash(req.body.password.toString(), saltRounds, (err, hash) => {
    if (err) return res.status(500).json({ Error: 'Error for hashing password' });

    const values = [req.body.name, req.body.email, hash];

    db.query(sql, [values], (err, result) => {
      if (err) return res.status(500).json({ Error: 'Inserting data error in server' });
      return res.status(201).json({ Status: 'Success' });
    });
  });
});

app.post('/login', (req, res) => {
  const sql = 'SELECT * FROM login WHERE email = ?';
  db.query(sql, [req.body.email], (err, data) => {
    if (err) {
      console.error('Error: ', err);
      return res.status(500).json({ Error: 'Logging in error' });
    }

    if (data.length > 0) {
      bcrypt.compare(req.body.password.toString(), data[0].password, (err, response) => {
        if (err) {
          console.error('Password compare error: ', err);
          return res.status(500).json({ Error: 'Password comparison failed' });
        }

        if (response) {
          const name = data[0].name;
          const token = jwt.sign({ name }, 'jwt-secret-key', { expiresIn: '1d' });
          res.cookie('token', token);
          return res.status(200).json({ Status: 'Success' });
        } else {
          return res.status(401).json({ Error: 'Password not matched' });
        }
      });
    } else {
      return res.status(404).json({ Error: 'No email existed' });
    }
  });
});

app.get('/logout', (req, res) => {
  res.clearCookie('token');
  return res.status(200).json({ Status: 'Success' });
});

app.listen(8081, () => {
  console.log('Server is running on port 8081');
});
