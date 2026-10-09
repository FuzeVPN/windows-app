// SPDX-License-Identifier: MPL-2.0
// Run with Node.js and sharp installed, or pass the absolute sharp module path.
// Generates raster packaging assets from the retained vector brand sources.
const fs = require('node:fs');
const path = require('node:path');
const desktopOnly = process.argv.includes('--desktop-only');
const sharp = require(process.argv.slice(2).find(argument => argument !== '--desktop-only') || 'sharp');

const projectRoot = path.resolve(__dirname, '..');
const brandingRoot = path.join(projectRoot, 'assets', 'branding');
const iconPath = path.join(projectRoot, 'windows', 'runner', 'resources', 'app_icon.ico');
const trayIconPath = path.join(projectRoot, 'windows', 'runner', 'resources', 'tray_icon.ico');
const sizes = [16, 20, 24, 32, 40, 48, 64, 96, 128, 256];

async function renderSvg(source, size) {
  return sharp(source, { density: (72 * size * 4) / 100 })
    .resize(size, size, { kernel: 'lanczos2' })
    .ensureAlpha()
    .png()
    .toBuffer();
}

async function generateIcon(iconSource, destination) {
  // Fit the complete original shield into each Windows size.
  // Measure alpha instead of colour so the transparent cut-outs stay intact.
  const renderedIcon = await renderSvg(iconSource, 1024);
  const { data: iconPixels, info: iconInfo } = await sharp(renderedIcon)
    .raw().toBuffer({ resolveWithObject: true });
  let left = iconInfo.width, top = iconInfo.height, right = -1, bottom = -1;
  for (let y = 0; y < iconInfo.height; y++) {
    for (let x = 0; x < iconInfo.width; x++) {
      if (iconPixels[(y * iconInfo.width + x) * iconInfo.channels + 3] !== 0) {
        left = Math.min(left, x); top = Math.min(top, y);
        right = Math.max(right, x); bottom = Math.max(bottom, y);
      }
    }
  }
  if (right < left || bottom < top) throw new Error('The desktop emblem is empty.');
  if (left === 0 || top === 0 || right === iconInfo.width - 1 || bottom === iconInfo.height - 1) {
    throw new Error('The desktop vector viewport clips the emblem.');
  }
  const croppedIcon = await sharp(renderedIcon)
    .extract({ left, top, width: right - left + 1, height: bottom - top + 1 })
    .png().toBuffer();

  const entries = [];
  for (const size of sizes) {
    // Place the artwork at a fractional coordinate before downsampling. Integer
    // padding shifts odd-width shields half a pixel to the left on small icons.
    const width = right - left + 1;
    const height = bottom - top + 1;
    const scale = size / Math.max(width, height);
    const fittedWidth = width * scale;
    const fittedHeight = height * scale;
    const centered = Buffer.from(`<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="0 0 ${size} ${size}"><image href="data:image/png;base64,${croppedIcon.toString('base64')}" x="${(size - fittedWidth) / 2}" y="${(size - fittedHeight) / 2}" width="${fittedWidth}" height="${fittedHeight}"/></svg>`);
    const png = await sharp(centered, { density: 72 * 8 })
      .resize(size, size, { kernel: 'lanczos2' })
      .png().toBuffer();
    entries.push({ size, png });
  }

  // The Windows ICO directory addresses a lossless RGBA PNG for each size.
  const directory = Buffer.alloc(6 + entries.length * 16);
  directory.writeUInt16LE(1, 2);
  directory.writeUInt16LE(entries.length, 4);
  let dataOffset = directory.length;
  for (const [index, entry] of entries.entries()) {
    const offset = 6 + index * 16;
    directory.writeUInt8(entry.size === 256 ? 0 : entry.size, offset);
    directory.writeUInt8(entry.size === 256 ? 0 : entry.size, offset + 1);
    directory.writeUInt16LE(1, offset + 4);
    directory.writeUInt16LE(32, offset + 6);
    directory.writeUInt32LE(entry.png.length, offset + 8);
    directory.writeUInt32LE(dataOffset, offset + 12);
    dataOffset += entry.png.length;
  }
  fs.writeFileSync(destination, Buffer.concat([directory, ...entries.map(entry => entry.png)]));
}

async function main() {
  const iconSource = fs.readFileSync(path.join(brandingRoot, 'fuzevpn-desktop-icon.svg'));
  if (!desktopOnly) {
    const emblemSource = fs.readFileSync(path.join(brandingRoot, 'fuzevpn-emblem.svg'));
    fs.writeFileSync(
      path.join(brandingRoot, 'fuzevpn-emblem-512.png'),
      await renderSvg(emblemSource, 512),
    );
  }

  // Preserve the owner's black-and-white artwork without an added outline.
  // Use the full available height and the same centre on both Windows surfaces.
  await generateIcon(iconSource, iconPath);
  await generateIcon(iconSource, trayIconPath);
  console.log(`Generated transparent Windows icon sizes: ${sizes.join(', ')} px.`);
}

main().catch(error => {
  console.error(error.message);
  process.exitCode = 1;
});
