let express = require("express");
let router = express.Router();

let knex = require("../knex");
let jwt = require("jsonwebtoken");
let bcrypt = require("bcrypt");

const { authenticateToken } = require("../middleware/authMiddleware");

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
  const token = jwt.sign({ userId: user.id }, "rahasia", { expiresIn: "1h" });

  // Simpan token dalam tabel "jwt_tokens"
  await knex("jwt_tokens").insert({ user_id: user.id, token });

  res.json({ token });
});

router.post("/logout", authenticateToken, async (req, res) => {
  const token = req.header("Authorization");

  // Hapus token JWT dari tabel "jwt_tokens"
  await knex("jwt_tokens").where({ user_id: req.user.userId, token }).delete();

  res.json({ message: "Logout berhasil." });
});

module.exports = router;
