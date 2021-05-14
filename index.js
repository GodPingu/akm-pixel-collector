const express = require("express");
const bodyParser = require("body-parser");
const fs = require("fs");
const app = express();
const port = 3000;

app.get("/", (req, res) => {
  //   res.send("Hello World!");
  res.sendFile(require("path").join(__dirname, "collector.html"));
});

app.use(express.json());
app.post("/collect", (req, res) => {
  console.log(req.body);
  res.send("ty");
});

app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`);
});

const datas = [];
function saveToFile() {
  try {
    fs.writeFileSync("data.json", JSON.stringify(datas));
  } catch (err) {}
}

setInterval(() => {
  saveToFile();
}, 15000);
