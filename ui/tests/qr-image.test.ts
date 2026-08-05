import assert from 'node:assert/strict';
import test from 'node:test';
import { decodeQrImage } from '../src/qr-image';

test('QR decoding composites transparent images onto white', async () => {
  const calls: string[] = [];
  let bitmapClosed = false;
  const pixels = new Uint8ClampedArray(40 * 40 * 4);
  const context = {
    fillStyle: '',
    fillRect() {
      calls.push(`fill:${this.fillStyle}`);
      // Model an opaque canvas backdrop. The QR library ignores alpha, so
      // these RGB values are the behavior this regression test protects.
      for (let i = 0; i < pixels.length; i += 4) {
        pixels[i] = 255;
        pixels[i + 1] = 255;
        pixels[i + 2] = 255;
        pixels[i + 3] = 255;
      }
    },
    drawImage() { calls.push('draw'); },
    getImageData() {
      calls.push('pixels');
      return { data: pixels, width: 40, height: 40 };
    },
  };
  const canvas = {
    width: 0,
    height: 0,
    getContext: () => context,
  };
  const documentDescriptor = Object.getOwnPropertyDescriptor(globalThis, 'document');
  const createImageBitmapDescriptor = Object.getOwnPropertyDescriptor(
    globalThis, 'createImageBitmap',
  );

  try {
    Object.defineProperty(globalThis, 'document', {
      configurable: true,
      value: { createElement: () => canvas },
    });
    Object.defineProperty(globalThis, 'createImageBitmap', {
      configurable: true,
      value: async () => ({
        width: 40,
        height: 40,
        close: () => { bitmapClosed = true; },
      }),
    });

    assert.equal(await decodeQrImage(new Blob(['image'])), null);
    assert.deepEqual(calls, ['fill:#fff', 'draw', 'pixels']);
    assert.equal(bitmapClosed, true, 'the decoded bitmap is released');
  } finally {
    if (documentDescriptor) Object.defineProperty(globalThis, 'document', documentDescriptor);
    else Reflect.deleteProperty(globalThis, 'document');
    if (createImageBitmapDescriptor) {
      Object.defineProperty(globalThis, 'createImageBitmap', createImageBitmapDescriptor);
    } else {
      Reflect.deleteProperty(globalThis, 'createImageBitmap');
    }
  }
});
