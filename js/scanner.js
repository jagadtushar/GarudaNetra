/* ===========================================================
   scanner.js — QR decoding from image files and live camera.
   Uses jsQR. Exposes Scanner.decodeFile / startCamera / stopCamera.
   =========================================================== */
const Scanner = (() => {
  let stream = null;
  let rafId = null;

  /** Decode a QR code from an image File. Returns Promise<string payload>. */
  function decodeFile(file) {
    return new Promise((resolve, reject) => {
      if (!file || !file.type.startsWith('image/')) {
        return reject(new Error('Please choose an image file.'));
      }
      const img = new Image();
      const reader = new FileReader();
      reader.onload = () => { img.src = reader.result; };
      reader.onerror = () => reject(new Error('Could not read the file.'));
      img.onload = () => {
        const data = scanImage(img);
        if (data) resolve({ payload: data, dataUrl: reader.result });
        else reject(new Error('No QR code found in this image.'));
      };
      img.onerror = () => reject(new Error('That file is not a valid image.'));
      reader.readAsDataURL(file);
    });
  }

  /** Run jsQR over an <img> at a sensible resolution. */
  function scanImage(img) {
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d', { willReadFrequently: true });
    // Cap dimensions for performance while keeping detail.
    const max = 1000;
    let { naturalWidth: w, naturalHeight: h } = img;
    const scale = Math.min(1, max / Math.max(w, h));
    w = Math.round(w * scale); h = Math.round(h * scale);
    canvas.width = w; canvas.height = h;
    ctx.drawImage(img, 0, 0, w, h);
    const imageData = ctx.getImageData(0, 0, w, h);
    const code = window.jsQR(imageData.data, w, h, { inversionAttempts: 'attemptBoth' });
    return code ? code.data : null;
  }

  /** Start camera and continuously scan. onResult(payload) fires once on hit. */
  async function startCamera(video, onResult, onError) {
    try {
      stream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: 'environment' }, audio: false,
      });
      video.srcObject = stream;
      await video.play();

      const canvas = document.createElement('canvas');
      const ctx = canvas.getContext('2d', { willReadFrequently: true });

      const tick = () => {
        if (!stream) return;
        if (video.readyState === video.HAVE_ENOUGH_DATA) {
          canvas.width = video.videoWidth;
          canvas.height = video.videoHeight;
          ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
          const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
          const code = window.jsQR(imageData.data, canvas.width, canvas.height, {
            inversionAttempts: 'dontInvert',
          });
          if (code && code.data) {
            stopCamera(video);
            onResult(code.data);
            return;
          }
        }
        rafId = requestAnimationFrame(tick);
      };
      rafId = requestAnimationFrame(tick);
      return true;
    } catch (err) {
      let msg = 'Could not access the camera.';
      if (err.name === 'NotAllowedError') msg = 'Camera permission was denied.';
      else if (err.name === 'NotFoundError') msg = 'No camera was found on this device.';
      else if (location.protocol === 'file:') msg = 'Camera needs HTTPS or localhost — serve the app over a local server.';
      if (onError) onError(msg);
      return false;
    }
  }

  function stopCamera(video) {
    if (rafId) cancelAnimationFrame(rafId);
    rafId = null;
    if (stream) {
      stream.getTracks().forEach((t) => t.stop());
      stream = null;
    }
    if (video) video.srcObject = null;
  }

  return { decodeFile, startCamera, stopCamera };
})();
