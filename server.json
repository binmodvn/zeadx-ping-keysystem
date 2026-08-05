require('dotenv').config();
const express = require('express');
const keysRouter = require('./routes/keys');

const app = express();
app.use(express.json());

app.get('/', (req, res) => {
  res.json({ service: 'Zeadx Ping Key System', status: 'online' });
});

app.use('/api/keys', keysRouter);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Zeadx Ping Key System đang chạy tại http://localhost:${PORT}`);
});
