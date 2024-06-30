require("dotenv").config()
const express = require('express');
const mysql = require('mysql2');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcryptjs');

const app = express();
const port = 8080;
const secretKey = process.env.secretKey;

app.use(bodyParser.json());

app.use(cors());

// Database connection
const db = mysql.createConnection({
  host: process.env.MYSQLHOST,
  user: process.env.MYSQLUSER,
  password: process.env.MYSQLPASSWORD,
  database: process.env.MYSQLDATABASE,
  port: process.env.MYSQLPORT
});

db.connect(err => {
  if (err) {
    console.error('Error connecting to the database:', err);
    return;
  }
  console.log('Connected to the database.');
});

// Utility function to authenticate JWT tokens
const authenticateToken = (req, res, next) => {
  const token = req.header('Token');
  if (!token) return res.sendStatus(401);

  jwt.verify(token, secretKey, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Signup
app.post('/signup', (req, res) => {
  const { first_name, last_name, userName, password, email, phone_number, role } = req.body;

  db.query('SELECT username FROM golang_stud WHERE username = ?', [userName], (err, result) => {
    if (err) return res.status(500).send(err);
    if (result.length > 0) return res.status(400).send('User exists');

    const hashedPassword = bcrypt.hashSync(password, 8);
    db.query('INSERT INTO golang_stud (username, password, first_name, last_name, email, phone_number, role) VALUES (?, ?, ?, ?, ?, ?, ?)', 
      [userName, hashedPassword, first_name, last_name, email, phone_number, role], 
      (err, result) => {
        if (err) return res.status(500).send(err);
        res.status(200).send({ ResponseCode: 200, Respmessage: 'User successfully registered' });
      });
  });
});

// Login
app.post('/login', (req, res) => {
  const { userName, password } = req.body;
  console.log(req.body)

  db.query('SELECT username, password, role FROM golang_stud WHERE username = ?', [userName], (err, results) => {
    if (err) return res.status(500).send(err);
    if (results.length === 0) return res.status(400).send('User does not exist');

    const user = results[0];
    const passwordIsValid = bcrypt.compareSync(password, user.password);

    if (!passwordIsValid) return res.status(400).send({ ResponseCode: 500, Respmessage: 'Please enter correct password' });

    const token = jwt.sign({ userName: user.username }, secretKey, { expiresIn: '30m' });

    res.status(200).send({
      ResponseCode: 200,
      Respmessage: 'User login successful',
      Data: {
        JwtToken: token,
        Role: user.role
      }
    });
  });
});

// Authorization check
app.get('/isAuthorized', authenticateToken, (req, res) => {
  const { userName } = req.user;

  db.query('SELECT username, role, first_name, last_name, email, phone_number FROM golang_stud WHERE username = ?', [userName], (err, results) => {
    if (err) return res.status(500).send(err);
    if (results.length === 0) return res.status(401).send('Unauthorized');

    const user = results[0];
    res.status(200).send({
      ResponseCode: 200,
      Respmessage: 'Authorized',
      Data: {
        UserName: user.username,
        FirstName: user.first_name,
        LastName: user.last_name,
        Email: user.email,
        PhoneNumber: user.phone_number,
        Role: user.role
      }
    });
  });
});

// Add Job
app.post('/addJobDetails', (req, res) => {
  const { job_title, job_description, experience_required, company_name, location, bond_years, posted_by } = req.body;

  db.query('INSERT INTO available_jobs (job_title, job_description, experience_required, company_name, location, bond_years, posted_by) VALUES (?, ?, ?, ?, ?, ?, ?)', 
    [job_title, job_description, experience_required, company_name, location, bond_years, posted_by], 
    (err, result) => {
      if (err) return res.status(500).send(err);
      res.status(200).send({ ResponseCode: 200, Respmessage: 'Job details added successfully' });
    });
});

// Get All Jobs
app.get('/getAllJobsList', (req, res) => {
  db.query('SELECT job_title, job_description, experience_required, company_name, location, bond_years, posted_by FROM available_jobs', 
    (err, results) => {
      if (err) return res.status(500).send(err);
      res.status(200).send({
        ResponseCode: 200,
        Respmessage: 'Jobs list',
        Data: { JobsList: results }
      });
    });
});

// Get all applied jobs per recruiter
app.post('/appliedApplicants', (req, res) => {
  const { userName } = req.body;

  db.query(`SELECT gs.first_name, gs.last_name, gs.email, gs.phone_number, aj.company_name, aj.job_title, aj.resume 
    FROM golang_stud gs 
    INNER JOIN applied_jobs1 aj 
    ON gs.username = aj.username 
    WHERE aj.posted_by = ?`, [userName], (err, results) => {
      if (err) return res.status(500).send(err);
      res.status(200).send({
        ResponseCode: 200,
        Respmessage: 'All jobs applied by candidates',
        Data: { AppliedJoblist: results }
      });
    });
});

// Apply for a job
app.post('/applyJob', (req, res) => {
  const { job_title, company_name, resume, userName, posted_by } = req.body;

  db.query('SELECT username FROM applied_jobs1 WHERE username = ? AND company_name = ? AND job_title = ?', 
    [userName, company_name, job_title], (err, results) => {
      if (err) return res.status(500).send(err);

      if (results.length > 0) {
        return res.status(200).send({ ResponseCode: 201, Respmessage: 'User already applied for the job' });
      }

      db.query('INSERT INTO applied_jobs1 (username, job_title, company_name, resume, posted_by) VALUES (?, ?, ?, ?, ?)', 
        [userName, job_title, company_name, resume, posted_by], 
        (err, result) => {
          if (err) return res.status(500).send(err);
          res.status(200).send({ ResponseCode: 200, Respmessage: 'Job application successful' });
        });
    });
});

// Get jobs applied by user
app.post('/getJobsAppliedByUser', (req, res) => {
  const { userName } = req.body;

  db.query('SELECT job_title, company_name, resume FROM applied_jobs1 WHERE username = ?', [userName], (err, results) => {
    if (err) return res.status(500).send(err);
    res.status(200).send({
      ResponseCode: 200,
      Respmessage: 'Applied jobs list',
      Data: { ApplieJobsByUserList: results }
    });
  });
});

// Get jobs posted by recruiter
app.post('/getJobPostedByRecruiter', (req, res) => {
  const { userName } = req.body;

  db.query('SELECT job_title, job_description, experience_required, company_name, location, bond_years, posted_by FROM available_jobs WHERE posted_by = ?', [userName], (err, results) => {
    if (err) return res.status(500).send(err);
    res.status(200).send({
      ResponseCode: 200,
      Respmessage: 'Jobs posted by recruiter',
      Data: { JobDetailsList: results }
    });
  });
});

// Test endpoint
app.get('/hi', (req, res) => {
  res.sendStatus(200);
});

// Start the server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
