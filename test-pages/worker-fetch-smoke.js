self.onmessage = async () => {
  try {
    const response = await fetch("/fingerprint-smoke.html?worker-fetch=1", {
      headers: {"X-XTrace-Smoke": "worker-fetch"}
    });
    const text = await response.text();
    self.postMessage({status: response.status, length: text.length});
  } catch (error) {
    self.postMessage({
      error: error && (error.stack || error.message) || String(error)
    });
  }
};
