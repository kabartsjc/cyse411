// vuln-time.js
app.get('/order', async (req, res) => {
  const id = req.query.id;
  const sql = "SELECT order_number FROM orders WHERE id = " + id;
  const [rows] = await db.query(sql);
  res.json({ rows });
});

