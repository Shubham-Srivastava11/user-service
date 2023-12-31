const express = require("express");
const bodyParser = require("body-parser");
const mysql = require("mysql2");
const bcrypt = require("bcryptjs");

const app = express();
const port = 3002;

app.use(bodyParser.json());

const pool = mysql.createPool({
  host: "localhost",
  user: "root",
  password: "test",
  database: "products",
  connectionLimit: 10,
});

// Route to register a new user
app.post("/register", (req, res) => {
  const { username, firstName, lastName, email, password } = req.body;

  if (!username || !email || !password || !firstName || !lastName) {
    return res
      .status(400)
      .json({ status: 400, message: "All fields are required." });
  }

  pool.query(
    "SELECT * FROM userDetails WHERE email = ?",
    [email],
    (err, result) => {
      if (err) {
        return res
          .status(500)
          .json({ status: 500, message: "Failed to register user." });
      }
      if (result.length === 0) {
        bcrypt.hash(password, 10, function (err, hash) {
          pool.query(
            "INSERT INTO userDetails (username, firstName, lastName, email, password) VALUES (?, ?, ?, ?, ?)",
            [username, firstName, lastName, email, hash],
            (err, result) => {
              if (err) {
                console.error("Error during registration:", err);
                return res
                  .status(500)
                  .json({ status: 500, message: "Failed to register user." });
              }

              return res.status(201).json({
                status: 201,
                message: `${username} registered successfully.`,
              });
            }
          );
        });
      } else {
        return res
          .status(400)
          .json({ status: 400, message: `${email} already registered.` });
      }
    }
  );
});

// Route to authenticate a user
app.post("/login", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res
      .status(400)
      .json({ status: 400, message: "Email and password are required." });
  }

  pool.query(
    "SELECT password FROM userDetails WHERE email = ?",
    [email],
    (err, result) => {
      if (err) {
        console.error("Error during login:", err);
        return res
          .status(500)
          .json({ status: 500, message: "Failed to authenticate user." });
      }

      if (result.length === 0) {
        return res
          .status(401)
          .json({ status: 401, message: "Email not registered" });
      }

      bcrypt.compare(
        password,
        result[0].password,
        async function (err, isMatch) {
          if (isMatch) {
            return res
              .status(200)
              .json({ message: "User authenticated successfully." });
          }

          if (!isMatch) {
            return res
              .status(402)
              .json({ status: 402, message: "Invalid credentials." });
          }
        }
      );
    }
  );
});

// Route to get user profile by email
app.get("/profile/:email", (req, res) => {
  const { email } = req.params;
  pool.query(
    "SELECT userId, username, firstName, lastName, email FROM userDetails WHERE email = ?",
    [email],
    (err, result) => {
      if (err) {
        console.error("Error fetching user profile:", err);
        return res
          .status(500)
          .json({ status: 500, message: "Failed to fetch user profile." });
      }

      if (result.length === 0) {
        return res.status(404).json({
          status: 404,
          message: `User with email - ${email} not found.`,
        });
      }

      return res.status(200).json(result[0]);
    }
  );
});

app.listen(port, () => {
  console.log(`User Service listening at http://localhost:${port}`);
});
