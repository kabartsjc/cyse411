// vuln-union.js
app.get('/post', async (req, res) => {
  const id = req.query.id; // attacker-controlled
  // vulnerable: direct concatenation
  const sql = "SELECT title, body FROM posts WHERE id = " + id;
  const rows = await db.query(sql); // assume db.query executes raw SQL
  res.json(rows);
});
