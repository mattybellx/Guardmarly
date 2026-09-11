const express = require("express");
const app = express();

app.get("/api/invoice/:invoiceId", async function (req, res) {
  const invoice = await Invoice.findById(req.params.invoiceId);
  res.json(invoice);
});
