const express = require("express");
const app = express();

app.get("/user", async function (req, res) {
  const name = req.query.name;
  const rows = await db.query("SELECT * FROM users WHERE name = $1", [name]);
  res.json(rows);
});
