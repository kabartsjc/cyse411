// vuln-boolean.js (Express + naive DB.query)
app.get('/product', async (req, res) => {
  const id = req.query.id; // attacker-controlled
  // vulnerable: concatenation leads to blind SQLi
  const sql = "SELECT name FROM products WHERE id = " + id;
  const [rows] = await db.query(sql); // db.query executes raw SQL
  if (rows.length) res.json({ found: true, rows });
  else res.json({ found: false });
});


// 