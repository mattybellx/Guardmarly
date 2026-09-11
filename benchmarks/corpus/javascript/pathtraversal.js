const express = require("express");
const fs = require("fs");
const path = require("path");
const app = express();

app.get("/download", function (req, res) {
  const file = req.query.file;
  res.send(fs.readFileSync(path.join("/srv/files", file)));
});
