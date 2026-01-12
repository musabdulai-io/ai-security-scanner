#!/usr/bin/env node
import puppeteer from 'puppeteer';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const htmlPath = path.resolve(__dirname, process.argv[2] || 'sample-audit-report.html');
const pdfPath = path.resolve(__dirname, process.argv[3] || 'sample-audit-report.pdf');

console.log(`Converting ${htmlPath} to pageless PDF...`);

const browser = await puppeteer.launch({ headless: true });
const page = await browser.newPage();

// Set viewport to match PDF width (1200px is good for max-w-6xl content)
await page.setViewport({ width: 1200, height: 800, deviceScaleFactor: 2 });

await page.goto(`file://${htmlPath}`, { waitUntil: 'networkidle0' });

// Wait for Tailwind CDN to compile all styles
await new Promise(r => setTimeout(r, 4000));

// Get accurate full document height
const dimensions = await page.evaluate(() => {
    const body = document.body;
    const html = document.documentElement;
    return {
        scrollHeight: Math.max(body.scrollHeight, html.scrollHeight),
        offsetHeight: Math.max(body.offsetHeight, html.offsetHeight),
        clientHeight: Math.max(body.clientHeight, html.clientHeight)
    };
});

const fullHeight = Math.max(dimensions.scrollHeight, dimensions.offsetHeight, dimensions.clientHeight);
// Add 200px buffer to ensure no second page
const pdfHeight = fullHeight + 200;

await page.pdf({
    path: pdfPath,
    width: '1200px',   // Match viewport width for no reflow
    height: `${pdfHeight}px`,
    printBackground: true,
    margin: { top: '0', bottom: '0', left: '0', right: '0' }  // No margins - content has its own padding
});

await browser.close();
console.log(`Pageless PDF saved: ${pdfPath} (${pdfHeight}px tall, content: ${fullHeight}px)`);
