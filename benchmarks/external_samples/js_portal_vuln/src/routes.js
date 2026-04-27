const express = require('express');
const router = express.Router();

router.get('/admin/users', (req, res) => {
  res.json([]);
});

router.get('/login', (req, res) => {
  res.redirect(req.query.next);
});

module.exports = router;
