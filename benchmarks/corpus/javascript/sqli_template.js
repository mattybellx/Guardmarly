const app = require("express").Router();

app.get("/order", async (req, res) => {
  const id = req.query.id;
  const rows = await pool.query(`SELECT * FROM orders WHERE id = ${id}`);
  res.json(rows);
});
