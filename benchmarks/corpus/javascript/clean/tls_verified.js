const https = require("https");

const agent = new https.Agent({ rejectUnauthorized: true });
module.exports = { agent: agent };
