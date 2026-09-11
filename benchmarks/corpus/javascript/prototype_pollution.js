const express = require("express");
const app = express();

app.post("/merge", function (req, res) {
  const target = {};
  Object.assign(target, req.body);
  res.json(target);
});
