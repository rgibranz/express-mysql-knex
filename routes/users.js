var express = require("express");
var router = express.Router();

var bcrypt = require("bcrypt");

const knex = require("../knex");
const saltRounds = 10;

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
router.post("/", authenticateToken, async (req, res) => {
  try {
    const newUser = req.body;
    const hashedPassword = await bcrypt.hash(newUser.password, saltRounds);
    newUser.password = hashedPassword; // Mengganti password dengan hash
    const [userId] = await knex("users").insert(newUser);
    res.status(201).json({ id: userId });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Gagal menambahkan pengguna." });
  }
});

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

    if (new_password) {
      // Hash password baru jika new_password terisi
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
