var express = require("express");
var router = express.Router();

var bcrypt = require("bcrypt");

const knex = require("../knex");
const saltRounds = 10;

const { body, validationResult } = require("express-validator");
const validator = require("validator");

const { authenticateToken } = require("../middleware/authMiddleware");

// READ (Mengambil Daftar Data Pengguna)
router.get("/", authenticateToken, async (req, res) => {
  try {
    const users = await knex("users").select("*"); // Memilih semua kolom dari tabel "users"
    res.json(users);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Gagal mengambil daftar pengguna." });
  }
});

// CREATE (Tambah Data Pengguna)
router.post(
  "/",
  authenticateToken,
  [
    // Validasi data input
    body("username").notEmpty().withMessage("Username tidak boleh kosong."),
    body("email").isEmail().withMessage("Email tidak valid."),
    body("password")
      .isLength({ min: 6 })
      .withMessage("Password harus memiliki setidaknya 6 karakter.")
      .custom((value, { req }) => {
        if (value !== req.body.confirm_password) {
          throw new Error("Password tidak cocok dengan konfirmasi password.");
        }
        return true;
      }),
  ],
  async (req, res) => {
    try {
      // Periksa hasil validasi
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }

      delete req.body.confirm_password; // menghapus properti konfirmasi password

      // Lanjutkan dengan pembuatan pengguna jika data input valid
      const newUser = req.body;
      const hashedPassword = await bcrypt.hash(newUser.password, saltRounds);
      newUser.password = hashedPassword; // Mengganti password dengan hash
      const [userId] = await knex("users").insert(newUser);
      res.status(201).json({ id: userId });
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: "Gagal menambahkan pengguna." });
    }
  }
);

// READ (Mengambil Data Pengguna berdasarkan ID)
router.get("/:id", authenticateToken, async (req, res) => {
  try {
    const userId = req.params.id;
    const user = await knex("users").where("id", userId).first();
    if (user) {
      res.json(user);
    } else {
      res.status(404).json({ error: "Pengguna tidak ditemukan." });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Gagal mengambil data pengguna." });
  }
});

// UPDATE (Perbarui Data Pengguna berdasarkan ID)
router.put("/:id", authenticateToken, async (req, res) => {
  try {
    const userId = req.params.id;
    const { new_password, ...otherData } = req.body;

    // Validasi data yang akan diperbarui (misalnya, pastikan email valid, dll.)
    if (otherData.email && !validator.isEmail(otherData.email)) {
      return res.status(400).json({ error: "Email tidak valid." });
    }

    // Validasi password baru jika ada
    if (new_password) {
      if (new_password.length < 6) {
        return res.status(400).json({
          error: "Password baru harus memiliki setidaknya 6 karakter.",
        });
      }
      // Hash password baru dan lanjutkan dengan pembaruan
      const hashedPassword = await bcrypt.hash(new_password, saltRounds);
      otherData.password = hashedPassword;
    }

    // Lanjutkan dengan pembaruan data pengguna
    await knex("users").where("id", userId).update(otherData);
    res.json({ message: "Data pengguna diperbarui." });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Gagal memperbarui data pengguna." });
  }
});

// DELETE (Hapus Data Pengguna berdasarkan ID)
router.delete("/:id", authenticateToken, async (req, res) => {
  try {
    const userId = req.params.id;
    await knex("users").where("id", userId).del();
    res.json({ message: "Data pengguna dihapus." });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Gagal menghapus data pengguna." });
  }
});

module.exports = router;
