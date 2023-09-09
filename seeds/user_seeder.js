/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
const bcrypt = require("bcrypt");
exports.seed = async function (knex) {
  // Hapus semua data dari tabel "users" sebelum menyisipkan data baru (opsional)
  return knex("users")
    .del()
    .then(async function () {
      // Menyisipkan beberapa data pengguna baru
      return knex("users").insert([
        {
          username: "user1",
          email: "user1@example.com",
          password: await bcrypt.hash("ada", 10), // Hashed password
        },
        {
          username: "user2",
          email: "user2@example.com",
          password: await bcrypt.hash("ada", 10), // Hashed password
        },
        // Tambahkan data pengguna lainnya jika diperlukan
      ]);
    });
};
