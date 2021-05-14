const fs = require("fs");

const file = fs.readFileSync("./sensor.js", "utf-8");

const acRegex = /_ac=(\[\S+?\])/;

console.log(file.match(acRegex)[1]);
