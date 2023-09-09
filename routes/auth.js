let express = require("express");
let router = express.Router();

let knex = require("../knex");
let jwt = require("jsonwebtoken");
let bcrypt = require("bcrypt");
let uuid = require("uuid");
const { authenticateToken } = require("../middleware/authMiddleware");

require("dotenv").config();

router.post("/login", async (req, res) => {
  const { username, password } = req.body;

  // Temukan pengguna berdasarkan username
  const user = await knex("users").where("username", username).first();

  if (!user) {
    return res.status(401).json({ error: "Username tidak ditemukan." });
  }

  // Verifikasi password menggunakan bcrypt
  if (!bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ error: "Password salah." });
  }

  // Buat token JWT
  const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, {
    expiresIn: "10m",
  });

  // Simpan token dalam tabel "jwt_tokens"
  await knex("jwt_tokens").insert({ user_id: user.id, token });

  const refreshToken = uuid.v4(); // Buat token penyegar baru
  await knex("refresh_tokens").insert({
    user_id: user.id,
    token: refreshToken,
  });

  res.json({ token, refreshToken });
});

router.post("/logout", authenticateToken, async (req, res) => {
  const token = req.header("Authorization");

  // Hapus token JWT dari tabel "jwt_tokens"
  await knex("jwt_tokens").where({ user_id: req.user.userId, token }).delete();

  res.json({ message: "Logout berhasil." });
});

// Endpoint untuk mendapatkan token penyegar setelah login
router.post("/refresh-token", async (req, res) => {
  const refreshToken = req.body.refreshToken;

  // Periksa apakah token penyegar valid
  const validRefreshToken = await knex("refresh_tokens")
    .where({ token: refreshToken })
    .first();

  if (!validRefreshToken) {
    return res.status(403).json({ error: "Token penyegar tidak valid." });
  }

  // Buat token akses baru untuk pengguna
  const accessToken = jwt.sign(
    { userId: validRefreshToken.user_id },
    process.env.JWT_SECRET,
    { expiresIn: "15m" }
  );

  res.json({ accessToken });
});

module.exports = router;
