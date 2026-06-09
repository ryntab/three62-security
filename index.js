import SecurityScanner from "./scanners/index.js";

console.log('\x1B[2J\x1B[3J\x1B[H');
process.stdout.write('\x1Bc');

const scanner = new SecurityScanner();

scanner.scan("https://www.iroquois.com/").then((result) => {
    console.log(JSON.stringify(result, null, 2));
});