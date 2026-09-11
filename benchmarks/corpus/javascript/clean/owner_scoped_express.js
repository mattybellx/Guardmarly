const express = require("express");
const app = express();

app.get("/api/invoice/:invoiceId", async function (req, res) {
  const invoice = await Invoice.findOne({
    where: { id: req.params.invoiceId, userId: req.user.id },
  });
  res.json(invoice);
});
