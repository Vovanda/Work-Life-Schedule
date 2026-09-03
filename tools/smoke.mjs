/* Смок страницы: открывает сайт настоящим браузером и проверяет то, что глазами
   проверяется долго, — что скрипт не упал, дни на месте, отметки считаются,
   виды и обе темы рисуются. Вёрстку по-прежнему смотрят глазами; этот скрипт
   ловит другое: поломку после правки данных или кода.

   Запуск (playwright ставится разово, в репозиторий не уезжает):

       npm i playwright && npx playwright install chromium
       python -m http.server 8742 &
       SCHEDULE_PASSWORD=... node tools/smoke.mjs

   Ширины взяты из правил проекта: телефон, планшет, ноутбук, широкий экран. */

import { chromium } from "playwright";

const URL = process.env.SMOKE_URL || "http://localhost:8742/index.html";
const PASSWORD = process.env.SCHEDULE_PASSWORD;
const AT = process.env.SMOKE_AT || "2026-09-05T11:40:00";   // середина дня хозяйства
const WIDTHS = [390, 768, 1200, 1700];

if (!PASSWORD) {
  console.error("нужен SCHEDULE_PASSWORD: смок входит на страницу, как человек");
  process.exit(2);
}

const problems = [];
const check = (ok, what) => { if (!ok) problems.push(what); return ok; };

const browser = await chromium.launch(process.env.SMOKE_CHROME?{executablePath:process.env.SMOKE_CHROME,args:['--no-sandbox']}:{});
const page = await (await browser.newContext({ viewport: { width: 1200, height: 900 } })).newPage();
page.on("pageerror", e => problems.push("ошибка скрипта: " + e.message));

// Время фиксируем: «сейчас» и «ближайшее» иначе зависят от того, когда запустили.
await page.addInitScript(fixed => {
  const Real = Date, stamp = new Real(fixed).getTime();
  class Fixed extends Real {
    constructor(...args) { args.length ? super(...args) : super(stamp); }
    static now() { return stamp; }
  }
  window.Date = Fixed;
}, AT);

await page.goto(URL, { waitUntil: "domcontentloaded" });
await page.fill("#gateInput", PASSWORD);
await page.click("#gateForm button[type=submit]");
await page.waitForSelector(".day, .emptystate", { timeout: 10000 });

const list = await page.evaluate(() => ({
  days: document.querySelectorAll(".day").length,
  rows: document.querySelectorAll(".entry").length,
  now: document.querySelectorAll(".badge-now").length,
  next: document.querySelectorAll(".badge-next").length,
  counter: document.querySelector(".day-count")?.textContent || "",
}));
console.log("список:", JSON.stringify(list));
check(list.days > 0, "в списке нет ни одного дня");
check(list.rows > 0, "в списке нет дел");
check(list.now === 1, "метка «сейчас» не одна: " + list.now);
check(list.next === 1, "метка «ближайшее» не одна: " + list.next);

for (const view of ["week", "month", "goals"]) {
  await page.click(`.seg-bar button[data-view="${view}"]`);
  await page.waitForTimeout(500);
  const filled = await page.evaluate(() =>
    document.querySelectorAll(".wk td.c, .mcell, .goal").length);
  console.log(view + ":", filled);
  check(filled > 0, "вид «" + view + "» пустой");
}

await page.click('.seg-bar button[data-view="list"]');
for (const theme of ["cupcake", "dracula"]) {
  while (await page.getAttribute("html", "data-theme") !== theme) {
    await page.click("#theme");
    await page.waitForTimeout(150);
  }
  const painted = await page.evaluate(() =>
    getComputedStyle(document.body).backgroundColor);
  console.log("тема " + theme + ":", painted);
  check(painted !== "rgba(0, 0, 0, 0)", "тема " + theme + " не покрасила фон");
}

for (const width of WIDTHS) {
  await page.setViewportSize({ width, height: 900 });
  await page.waitForTimeout(300);
  const overflow = await page.evaluate(() =>
    document.documentElement.scrollWidth - document.documentElement.clientWidth);
  console.log("ширина " + width + ": горизонтальный вылет " + overflow + "px");
  check(overflow <= 1, "на " + width + "px страница уезжает вбок на " + overflow + "px");
}

await browser.close();
if (problems.length) {
  console.error("\nсломано:\n- " + problems.join("\n- "));
  process.exit(1);
}
console.log("\nвсё на месте");
