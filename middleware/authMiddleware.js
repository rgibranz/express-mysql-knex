const jwt = require("jsonwebtoken");
const knex = require("../knex");

function authenticateToken(req, res, next) {
  const token = req.header("Authorization");

  if (!token) {
    return res.status(401).json({ error: "Token tidak ada." });
  }

  jwt.verify(token, "rahasia", async (err, payload) => {
    if (err) {
      return res.status(403).json({ error: "Token tidak valid." });
    }

    // Periksa apakah token masih ada di tabel "jwt_tokens"
    const tokenExists = await knex("jwt_tokens")
      .where({ user_id: payload.userId, token })
      .first();

    if (!tokenExists) {
      return res.status(403).json({ error: "Token tidak valid." });
    }

    req.user = payload;
    next();
  });
}

module.exports = { authenticateToken };
