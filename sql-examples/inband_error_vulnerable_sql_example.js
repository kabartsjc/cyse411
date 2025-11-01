// vuln-error.js
app.get('/customer', async (req, res) => {
  const id = req.query.id;
  const sql = "SELECT email FROM customers WHERE id = " + id;
  db.query(sql, (err, rows) => {
    if (err) return res.status(500).send(err.message); // dangerous: leaks DB errors
    res.json(rows);
  });
});


