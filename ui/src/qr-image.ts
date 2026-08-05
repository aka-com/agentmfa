import jsQR from 'jsqr';

/** A decoded image ready to draw, plus how to release what backs it. */
interface Drawable {
  width: number;
  height: number;
  source: CanvasImageSource;
  release(): void;
}

async function loadDrawable(file: Blob): Promise<Drawable> {
  if (typeof createImageBitmap === 'function') {
    const bitmap = await createImageBitmap(file);
    return {
      width: bitmap.width,
      height: bitmap.height,
      source: bitmap,
      release: () => bitmap.close(),
    };
  }
  // Older WebKit: decode through an <img> backed by an object URL.
  if (typeof URL.createObjectURL !== 'function') {
    throw new Error('image decoding is unavailable here');
  }
  const url = URL.createObjectURL(file);
  try {
    const image = await new Promise<HTMLImageElement>((resolve, reject) => {
      const element = new Image();
      element.onload = () => resolve(element);
      element.onerror = () => reject(new Error('not a decodable image'));
      element.src = url;
    });
    return {
      width: image.naturalWidth,
      height: image.naturalHeight,
      source: image,
      release: () => URL.revokeObjectURL(url),
    };
  } catch (error) {
    URL.revokeObjectURL(url);
    throw error;
  }
}

/** The sizes to attempt a decode at, largest first. Huge screenshots are
 * capped for speed, and a downscaled retry smooths the anti-aliasing that
 * can defeat the binarizer on screen-captured codes. Never upscaled: a
 * small crisp code only blurs. */
function decodeDimensions(width: number, height: number): number[] {
  const largest = Math.max(width, height);
  const capped = [Math.min(largest, 2048), 1024, 512].filter((d) => d <= largest);
  return [...new Set(capped.length ? capped : [largest])];
}

/**
 * Find and decode a QR code in an image file, entirely in the webview —
 * the image is never uploaded anywhere. Returns the code's text, or null
 * when the image is readable but contains no QR code; throws when the file
 * cannot be decoded as an image at all. `attemptBoth` also reads the
 * light-on-dark codes that dark-mode setup pages produce.
 */
export async function decodeQrImage(file: Blob): Promise<string | null> {
  const drawable = await loadDrawable(file);
  try {
    if (!drawable.width || !drawable.height) throw new Error('empty image');
    const canvas = document.createElement('canvas');
    const context = canvas.getContext('2d', { willReadFrequently: true });
    if (!context) throw new Error('canvas is unavailable here');
    for (const dimension of decodeDimensions(drawable.width, drawable.height)) {
      const scale = Math.min(1, dimension / Math.max(drawable.width, drawable.height));
      canvas.width = Math.max(1, Math.round(drawable.width * scale));
      canvas.height = Math.max(1, Math.round(drawable.height * scale));
      context.drawImage(drawable.source, 0, 0, canvas.width, canvas.height);
      const pixels = context.getImageData(0, 0, canvas.width, canvas.height);
      const code = jsQR(pixels.data, pixels.width, pixels.height, {
        inversionAttempts: 'attemptBoth',
      });
      if (code?.data) return code.data;
    }
    return null;
  } finally {
    drawable.release();
  }
}
