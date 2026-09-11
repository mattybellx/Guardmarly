const express = require("express");
const app = express();

app.get("/user", function (req, res) {
  const name = req.query.name;
  db.query("SELECT * FROM users WHERE name = '" + name + "'", function (err, rows) {
    res.json(rows);
  });
});
