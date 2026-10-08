const loginView = document.querySelector("#login-view");
const appView = document.querySelector("#app-view");
const loginForm = document.querySelector("#login-form");
const loginMessage = document.querySelector("#login-message");
const deploymentNotice = document.querySelector("#deployment-notice");
const demoHint = document.querySelector("#demo-hint");
const attendeeView = document.querySelector("#attendee-view");
const scannerView = document.querySelector("#scanner-view");
const welcomeTitle = document.querySelector("#welcome-title");
const qrImage = document.querySelector("#qr-image");
const expiryLabel = document.querySelector("#expiry-label");
const qrMessage = document.querySelector("#qr-message");
const tokenForm = document.querySelector("#token-form");
const tokenInput = document.querySelector("#token-input");
const scanResult = document.querySelector("#scan-result");
const attendanceList = document.querySelector("#attendance-list");
const cameraVideo = document.querySelector("#camera-video");
const cameraPlaceholder = document.querySelector("#camera-placeholder");
const cameraButton = document.querySelector("#camera-button");
const stopCameraButton = document.querySelector("#stop-camera-button");

let qrRefreshTimer;
let countdownTimer;
let cameraStream;
let scanning = false;

async function api(url, options = {}) {
  const response = await fetch(url, {
    credentials: "same-origin",
    ...options,
    headers: {
      ...(options.body ? { "Content-Type": "application/json" } : {}),
      ...options.headers,
    },
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || "The request could not be completed.");
  return result;
}

function stopTimers() {
  clearTimeout(qrRefreshTimer);
  clearInterval(countdownTimer);
  qrRefreshTimer = undefined;
  countdownTimer = undefined;
}

function stopCamera() {
  scanning = false;
  if (cameraStream) {
    for (const track of cameraStream.getTracks()) track.stop();
    cameraStream = undefined;
  }
  cameraVideo.pause();
  cameraVideo.srcObject = null;
  cameraVideo.hidden = true;
  cameraPlaceholder.hidden = false;
  cameraButton.hidden = false;
  stopCameraButton.hidden = true;
}

function showUser(user) {
  stopTimers();
  stopCamera();
  loginView.hidden = true;
  appView.hidden = false;
  attendeeView.hidden = user.role !== "attendee";
  scannerView.hidden = user.role !== "scanner";
  welcomeTitle.textContent = user.role === "attendee" ? "Your event pass" : "Staff check-in";
  if (user.role === "attendee") {
    loadQr();
  } else {
    loadAttendance();
  }
}

function showLogin() {
  stopTimers();
  stopCamera();
  appView.hidden = true;
  loginView.hidden = false;
}

async function loadQr() {
  try {
    const result = await api("/api/qr");
    qrImage.src = result.qrCode;
    qrMessage.textContent = "";
    const expiration = result.expiresAt * 1000;
    clearInterval(countdownTimer);
    const updateCountdown = () => {
      const remaining = Math.max(0, Math.ceil((expiration - Date.now()) / 1000));
      expiryLabel.textContent = remaining > 0 ? `Refreshes in ${remaining} seconds` : "Refreshing secure pass…";
    };
    updateCountdown();
    countdownTimer = setInterval(updateCountdown, 1000);
    qrRefreshTimer = setTimeout(loadQr, 30_000);
  } catch (error) {
    qrMessage.textContent = error.message;
    qrRefreshTimer = setTimeout(loadQr, 5000);
  }
}

async function loadAttendance() {
  try {
    const { records } = await api("/api/attendance");
    attendanceList.replaceChildren();
    if (records.length === 0) {
      const empty = document.createElement("li");
      empty.className = "empty-state";
      empty.textContent = "No check-ins yet.";
      attendanceList.append(empty);
      return;
    }
    for (const record of records.slice().reverse()) {
      const item = document.createElement("li");
      const name = document.createElement("span");
      const time = document.createElement("small");
      name.textContent = record.attendee;
      time.textContent = new Date(record.scannedAt).toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
      });
      item.append(name, time);
      attendanceList.append(item);
    }
  } catch (error) {
    attendanceList.replaceChildren();
    const item = document.createElement("li");
    item.className = "empty-state";
    item.textContent = error.message;
    attendanceList.append(item);
  }
}

async function checkIn(token) {
  scanResult.hidden = false;
  scanResult.className = "scan-result";
  scanResult.textContent = "Verifying the signed QR code…";
  try {
    const result = await api("/api/check-in", {
      method: "POST",
      body: JSON.stringify({ token: token.trim() }),
    });
    scanResult.className = "scan-result success";
    scanResult.textContent = `Verified: ${result.attendee} checked in to ${result.event}.`;
    tokenInput.value = "";
  } catch (error) {
    scanResult.className = "scan-result error";
    scanResult.textContent = error.message;
  }
  await loadAttendance();
}

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = loginForm.querySelector("button[type=submit]");
  button.disabled = true;
  loginMessage.textContent = "";
  try {
    const values = new FormData(loginForm);
    const result = await api("/api/login", {
      method: "POST",
      body: JSON.stringify({
        username: values.get("username"),
        password: values.get("password"),
      }),
    });
    deploymentNotice.hidden = !result.demoMode;
    demoHint.hidden = result.demoMode;
    loginForm.reset();
    showUser(result.user);
  } catch (error) {
    loginMessage.textContent = error.message;
  } finally {
    button.disabled = false;
  }
});

document.querySelector("#logout-button").addEventListener("click", async () => {
  try {
    await api("/api/logout", { method: "POST" });
  } finally {
    showLogin();
  }
});

tokenForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  await checkIn(tokenInput.value);
});

cameraButton.addEventListener("click", async () => {
  if (!("BarcodeDetector" in window)) {
    scanResult.hidden = false;
    scanResult.className = "scan-result error";
    scanResult.textContent = "Live scanning is not supported in this browser. Paste the QR token instead.";
    return;
  }
  if (!navigator.mediaDevices?.getUserMedia) {
    scanResult.hidden = false;
    scanResult.className = "scan-result error";
    scanResult.textContent = "Camera access requires HTTPS or localhost. Paste the QR token instead.";
    return;
  }

  try {
    const detector = new BarcodeDetector({ formats: ["qr_code"] });
    cameraStream = await navigator.mediaDevices.getUserMedia({
      video: { facingMode: { ideal: "environment" } },
      audio: false,
    });
    cameraVideo.srcObject = cameraStream;
    cameraVideo.hidden = false;
    cameraPlaceholder.hidden = true;
    cameraButton.hidden = true;
    stopCameraButton.hidden = false;
    await cameraVideo.play();
    scanning = true;
    scanResult.hidden = true;
    const scanFrame = async () => {
      if (!scanning) return;
      try {
        const [barcode] = await detector.detect(cameraVideo);
        if (barcode?.rawValue) {
          stopCamera();
          await checkIn(barcode.rawValue);
          return;
        }
      } catch {
        stopCamera();
        scanResult.hidden = false;
        scanResult.className = "scan-result error";
        scanResult.textContent = "Unable to read a QR code. Check camera permissions or paste the token instead.";
        return;
      }
      if (scanning) setTimeout(scanFrame, 180);
    };
    scanFrame();
  } catch {
    stopCamera();
    scanResult.hidden = false;
    scanResult.className = "scan-result error";
    scanResult.textContent = "Camera access was unavailable. Check permissions or paste the QR token instead.";
  }
});

stopCameraButton.addEventListener("click", stopCamera);
window.addEventListener("pagehide", stopCamera);

api("/api/me")
  .then((result) => {
    deploymentNotice.hidden = !result.demoMode;
    demoHint.hidden = result.demoMode;
    if (result.user) showUser(result.user);
  })
  .catch(() => {
    loginMessage.textContent = "Unable to connect to the authentication server.";
  });
