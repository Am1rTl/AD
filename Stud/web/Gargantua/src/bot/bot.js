`use strict`;

const HOST = "http://nginx:8181/profile?uuid="
const FLAG = process.env.FLAG || "MCTF{example_flag}"
const TIMEOUT = process.env.TIMEOUT || 300 * 1000;

const puppeteer = require("puppeteer-core");
const readline = require('readline').createInterface({
    input: process.stdin,
    output: process.stdout,
    terminal: false,
});

readline.ask = str => new Promise(resolve => readline.question(str, resolve));
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

async function postFlag(uuid) {
  const browser = await puppeteer.launch({
    headless: true,
    executablePath: "/usr/bin/chromium-browser",
    ignoreHTTPSErrors: true,
    defaultViewport: {
      width: 1200,
      height: 1080,
    },
    args: ["--no-sandbox", "--disable-gpu", "--disabled-setupid-sandbox", "--disable-extensions", "--js-flags=--jitless"],
  });
  const page = await browser.newPage();
  await page.setCookie({
    name: 'Flag',
    value: FLAG,
    domain: 'nginx',
    path: '/',
    expires: Date.now() + 1000 * 60 * 60 * 24 * 7, // Expires in one week
  });


  await page.goto(HOST + uuid);
  await browser.close();
}

async function main() {
    console.log('Enter your uuid: ');
    const uuid = await readline.ask('> ');

    await postFlag(uuid);
    console.log('Flag posted!');

    readline.close()
    process.stdin.end();
    process.stdout.end();

    await sleep(TIMEOUT);
}

main();
