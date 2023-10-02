const express = require("express");
const bodyParser = require("body-parser");
const mysql = require("mysql2");
const { CONFIG } = require("./config");

const app = express();
const port = 3000;

app.use(bodyParser.json());

const pool = mysql.createPool({
  host: CONFIG.host,
  user: CONFIG.user,
  password: CONFIG.password,
  database: CONFIG.database,
  connectionLimit: 10,
});

// Route to register a new user
app.post("/register", (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ error: "All fields are required." });
  }

  pool.query(
    "INSERT INTO userDetails (username, email, password) VALUES (?, ?, ?)",
    [username, email, password],
    (err, result) => {
      if (err) {
        console.error("Error during registration:", err);
        return res.status(500).json({ error: "Failed to register user." });
      }

      return res
        .status(201)
        .json({ message: `${username} registered successfully.` });
    }
  );
});

// Route to authenticate a user
app.post("/login", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required." });
  }

  pool.query(
    "SELECT * FROM userDetails WHERE email = ? AND password = ?",
    [email, password],
    (err, result) => {
      if (err) {
        console.error("Error during login:", err);
        return res.status(500).json({ error: "Failed to authenticate user." });
      }

      if (result.length === 0) {
        return res.status(401).json({ error: "Invalid credentials." });
      }

      return res
        .status(200)
        .json({ message: "User authenticated successfully." });
    }
  );
});

// Route to get user profile by email
app.get("/profile/:email", (req, res) => {
  const { email } = req.params;
  pool.query(
    "SELECT id, username, email FROM userDetails WHERE email = ?",
    [email],
    (err, result) => {
      if (err) {
        console.error("Error fetching user profile:", err);
        return res.status(500).json({ error: "Failed to fetch user profile." });
      }

      if (result.length === 0) {
        return res
          .status(404)
          .json({ error: `User with email - ${email} not found.` });
      }

      return res.status(200).json(result[0]);
    }
  );
});

app.listen(port, () => {
  console.log(`User Service listening at http://localhost:${port}`);
});
