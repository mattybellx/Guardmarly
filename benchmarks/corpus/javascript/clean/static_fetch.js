const axios = require("axios");

async function health() {
  const response = await axios.get("https://example.com/health");
  return response.data;
}

module.exports = { health: health };
