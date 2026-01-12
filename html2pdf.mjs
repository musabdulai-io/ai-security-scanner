import puppeteer from 'puppeteer';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const htmlPath = process.argv[2] || 'sample-audit-report.html';
const pdfPath = process.argv[3] || 'sample-audit-report.pdf';

const fullHtmlPath = path.resolve(__dirname, htmlPath);
const fullPdfPath = path.resolve(__dirname, pdfPath);

console.log(`Converting ${fullHtmlPath} to ${fullPdfPath}...`);

const browser = await puppeteer.launch({ headless: true });
const page = await browser.newPage();
await page.goto(`file://${fullHtmlPath}`, { waitUntil: 'networkidle0' });
// Wait extra time for Tailwind CDN to compile all styles
await new Promise(r => setTimeout(r, 3000));
await page.pdf({
    path: fullPdfPath,
    format: 'A4',
    printBackground: true,
    margin: { top: '10mm', bottom: '10mm', left: '10mm', right: '10mm' }
});
await browser.close();
console.log(`PDF saved to: ${fullPdfPath}`);
