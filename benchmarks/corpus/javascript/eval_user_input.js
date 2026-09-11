const express = require("express");
const app = express();

app.post("/calc", function (req, res) {
  const expr = req.body.expr;
  const value = eval(expr);
  res.json({ value: value });
});
