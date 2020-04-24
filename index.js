const express = require('express')
// express.static(root, [options])
const app = express();
const path = require('path');

app.use(express.static('public'))

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname + '/index.html'));
});

app.get('/decrypt', (req, res) => {
  var json = {
    "data": "yWRxwgj//uxzqbmG--9nYpx5FOh5f12JzK--7h5q0i+CElwDMc5xBxKuHg=="
  }
  res.set({
    'Encrypt': 'true'
  })
  res.json(json)
})

app.listen(8000, () => {
  console.log('Example app listening on port 8000!')
});