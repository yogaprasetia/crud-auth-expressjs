const bcrypt = require('bcrypt');
const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql');
const crypto = require('crypto');

const app = express();
const port = 3000;

// Database connection
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'surat',
});

db.connect((err) => {
  if (err) throw err;
  console.log('Connected to MySQL database');
});

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));
app.set('view engine', 'ejs');

// Routes
app.get('/', (req, res) => {
  res.render('login');
});

app.get('/register', (req, res) => {
  res.render('register');
});

app.post('/register', (req, res) => {
  const { username, password } = req.body;

  // Generate a salt
  const salt = bcrypt.genSaltSync(10);

  // Encrypt the password using bcrypt
  const encryptedPassword = bcrypt.hashSync(password, salt);

  const user = { username, password: encryptedPassword };

  db.query("INSERT INTO users SET ?", user, (err) => {
    if (err) throw err;
    res.redirect("/");
  });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;

  // Retrieve the user from the database
  db.query('SELECT * FROM users WHERE username = ?', [username], async (err, results) => {
    if (err) throw err;

    if (results.length > 0) {
      // Compare the entered password with the stored password
      const isMatch = await bcrypt.compare(password, results[0].password);

      if (isMatch) {
        res.render('dashboard', { username });
      } else {
        res.redirect('/');
      }
    } else {
      res.redirect('/');
    }
  });
});

// Server
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
