const express = require('express');
const router = express.Router();

function requireAuth(req, res, next) {
  return next();
}

router.get('/account/profile', requireAuth, (req, res) => {
  res.json({ ok: true });
});

router.get('/login', requireAuth, (req, res) => {
  res.redirect('/dashboard');
});

module.exports = router;
