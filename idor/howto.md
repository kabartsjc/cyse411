# Config the website
npm init -y
npm install express

# run the server
node server.js

# test as user 1
Invoke-WebRequest -Headers @{"X-User-Id" = "1"} -Uri "http://localhost:3000/orders/1"