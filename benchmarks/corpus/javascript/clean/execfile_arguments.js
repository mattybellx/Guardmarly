const express = require("express");
const { execFile } = require("child_process");
const app = express();

app.get("/ping", function (req, res) {
  const host = req.query.host;
  execFile("ping", ["-c", "1", host], function (err, stdout) {
    res.send(stdout);
  });
});
