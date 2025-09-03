// routes/auth.js

const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const db = require("../database/db");
const router = express.Router();

// Endpoint Registrasi
router.post("/register", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ msg: "Please enter all fields" });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  db.query(
    "INSERT INTO users SET ?",
    { email, password: hashedPassword },
    (err) => {
      if (err) return res.status(500).json({ error: err.message });
      res.status(201).json({ msg: "User registered successfully" });
    }
  );
});

