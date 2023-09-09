const jwt = require("jsonwebtoken");
const knex = require("../knex");

require("dotenv").config();

function authenticateToken(req, res, next) {
  const token = req.header("Authorization");

  if (!token) {
    return res.status(401).json({ error: "Token tidak ada." });
  }

  jwt.verify(token, process.env.JWT_SECRET, async (err, payload) => {
    if (err) {
      // Jika token akses kedaluwarsa, coba gunakan token penyegar untuk mendapatkan token akses baru
      const refreshToken = req.header("Refresh-Token");
      if (refreshToken) {
        const validRefreshToken = await knex("refresh_tokens")
          .where({ token: refreshToken })
          .first();

        if (validRefreshToken) {
          // Buat token akses baru dan kirimkan kembali kepada pengguna
          const newAccessToken = jwt.sign(
            { userId: validRefreshToken.user_id },
            process.env.JWT_SECRET,
            { expiresIn: "15m" }
          );
          req.user = { userId: validRefreshToken.user_id };
          req.accessToken = newAccessToken;
          return next();
        }
      }

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
