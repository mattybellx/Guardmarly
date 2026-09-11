const express = require("express");
const app = express();

app.get("/hello", function (req, res) {
  const name = req.query.name;
  document.getElementById("out").innerHTML = "Hello " + name;
});
