const express = require("express");
const axios = require("axios");
const app = express();

app.get("/proxy", async function (req, res) {
  const url = req.query.url;
  const response = await axios.get(url);
  res.send(response.data);
});
