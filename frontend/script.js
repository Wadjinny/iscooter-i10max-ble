// --- Crypto dependencies for PM challenge/response ---
const KEY = '9883222CD5B257133F3AC675A7132B44';
const INV = '9E716E81E1A71CB524884953B2275BBD';
const S_BOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
];
function hexToBytes(hex) {
    const arr = [];
    for (let i = 0; i < hex.length; i += 2) arr.push(parseInt(hex.substr(i, 2), 16));
    return arr;
}
function subBytes(arr, length) {
    for (let i = 0; i < length; i++) arr[i] = S_BOX[arr[i] & 0xFF];
}
function generateHash(nonceHex) {
    const nonce = [];
    for (let i = 0; i < 12; i += 2) nonce.push(parseInt(nonceHex.substr(i, 2), 16));
    const cArr = new Array(32).fill(0);
    for (let i = 0; i < 6; i++) cArr[i] = nonce[i];
    for (let i = 0; i < 6; i++) cArr[i + 6] = nonce[i];
    for (let i = 0; i < 4; i++) cArr[i + 12] = nonce[i];
    for (let i = 0; i < 15; i++) cArr[i + 16] = cArr[i + 1];
    cArr[31] = cArr[0];
    let keyTmp = Array.from(hexToBytes(KEY));
    subBytes(keyTmp, 16);
    const tempKey = keyTmp.slice(0, 4);
    for (let c = 0; c < 12; c++) keyTmp[c] = keyTmp[c + 4];
    for (let i = 0; i < 4; i++) keyTmp[12 + i] = tempKey[i];
    const inv = Array.from(hexToBytes(INV));
    for (let c = 0; c < 16; c++) {
        let val = cArr[c];
        let i = val ^ keyTmp[c];
        cArr[c] = i ^ inv[c];
        cArr[c + 16] = (keyTmp[c] ^ cArr[c + 16]) ^ inv[c];
    }
    for (let c = 1; c < 16; c++) {
        cArr[c] = cArr[c] ^ cArr[c - 1];
        cArr[c + 16] = cArr[c + 16] ^ cArr[c + 16 - 1];
    }
    let bondingHash = [];
    for (let c = 0; c < 4; c++) {
        bondingHash[c] = (
            cArr[c] ^ cArr[c + 4] ^ cArr[c + 8] ^
            (cArr[c + 12] + cArr[c + 16]) ^
            cArr[c + 20] ^ cArr[c + 24] ^ cArr[c + 28]
        ) & 0xFF;
    }
    return bondingHash.map(x => x.toString(16).padStart(2, '0').toUpperCase()).join('');
}

// BLE UUIDs (replace with your device's values if needed)
const SERVICE_UUID = '6d581e70-15c6-11ec-82a8-0002a5d5c51b';
const WRITE_UUID = '6d581e71-15c6-11ec-82a8-0002a5d5c51b';
const READ_UUID = '6d581e74-15c6-11ec-82a8-0002a5d5c51b';
const LEGACY_PASSWORD = '000000';

let device = null;
let server = null;
let writeChar = null;
let readChar = null;
let toastTimer = null;

const MODE_CYCLE = [1, 2, 3]; // Eco → Drive → Sport
const MODE_LABELS = { 0: 'Lock/Limit', 1: 'Eco', 2: 'Drive', 3: 'Sport' };

/** Lucide-style inline SVGs (no CDN — works offline / file://) */
function svgIcon(paths) {
    return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${paths}</svg>`;
}

const ICONS = {
    lock: svgIcon('<rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>'),
    unlock: svgIcon('<rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 9.9-1"/>'),
    leaf: svgIcon('<path d="M11 20A7 7 0 0 1 9.8 6.1C15.5 5 17 4.48 19 2c1 2 2 4.18 2 8 0 5.5-4.78 10-10 10Z"/><path d="M2 21c0-3 1.85-5.36 5.08-6C9.5 14.52 12 13 13 12"/>'),
    gauge: svgIcon('<path d="m12 14 4-4"/><path d="M3.34 19a10 10 0 1 1 17.32 0"/>'),
    zap: svgIcon('<path d="M4 14a1 1 0 0 1-.78-1.63l9.9-10.2a.5.5 0 0 1 .86.46l-1.92 6.02A1 1 0 0 0 13 10h7a1 1 0 0 1 .78 1.63l-9.9 10.2a.5.5 0 0 1-.86-.46l1.92-6.02A1 1 0 0 0 11 14z"/>'),
    shield: svgIcon('<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/>'),
    route: svgIcon('<circle cx="6" cy="19" r="3"/><path d="M9 19h8.5a3.5 3.5 0 0 0 0-7h-11a3.5 3.5 0 0 1 0-7H15"/><circle cx="18" cy="5" r="3"/>'),
    circleOff: svgIcon('<path d="m2 2 20 20"/><path d="M8.35 2.69A10 10 0 0 1 21.3 15.65"/><path d="M19.08 19.08A10 10 0 1 1 4.92 4.92"/>'),
    footprints: svgIcon('<path d="M4 16v-2.38C4 11.5 2.97 10.5 3 8c.03-2.72 1.49-6 4.5-6C9.37 2 10 3.8 10 5.5c0 3.11-2 5.66-2 8.68V16a2 2 0 1 1-4 0Z"/><path d="M20 20v-2.38c0-2.12 1.03-3.12 1-5.62-.03-2.72-1.49-6-4.5-6C14.63 6 14 7.8 14 9.5c0 3.11 2 5.66 2 8.68V20a2 2 0 1 0 4 0Z"/>'),
    circlePlay: svgIcon('<path d="M9 9.003a1 1 0 0 1 1.517-.859l4.997 2.997a1 1 0 0 1 0 1.718l-4.997 2.997A1 1 0 0 1 9 14.996z"/><circle cx="12" cy="12" r="10"/>'),
    gaugeKm: svgIcon('<path d="m12 14 4-4"/><path d="M3.34 19a10 10 0 1 1 17.32 0"/>'),
    flag: svgIcon('<path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z"/><line x1="4" x2="4" y1="22" y2="15"/>'),
};

const statusActions = {
    lock: {
        btnId: 'lock-toggle-btn',
        valueId: 'status-lock',
        iconId: 'lock-icon',
        spinnerId: 'lock-spinner',
        current: null,
        pending: null,
        next: (state) => !state,
        matches: (state, target) => state === target,
        isReady: (state) => state !== null,
        command: (target) => sendCommand(0x04, target ? 0x01 : 0x00),
        render: (state) => state ? {
            text: 'LOCKED',
            icon: ICONS.lock,
            tone: 'tone-danger',
            title: 'Tap to unlock',
            aria: 'Unlock scooter',
        } : {
            text: 'UNLOCKED',
            icon: ICONS.unlock,
            tone: 'tone-ok',
            title: 'Tap to lock',
            aria: 'Lock scooter',
        },
        failMsg: 'Lock switch failed — status did not update',
        unknownMsg: 'Lock status unknown — wait for telemetry',
        sendFailMsg: 'Failed to send lock command',
    },
    unit: {
        btnId: 'unit-toggle-btn',
        valueId: 'status-unit',
        iconId: 'unit-icon',
        spinnerId: 'unit-spinner',
        current: null,
        pending: null,
        next: (state) => !state,
        matches: (state, target) => state === target,
        isReady: (state) => state !== null,
        command: (target) => sendCommand(0x03, target ? 0x01 : 0x00),
        render: (state) => state ? {
            text: 'MPH',
            icon: ICONS.flag,
            tone: 'tone-warn',
            title: 'Tap to switch to km/h',
            aria: 'Switch unit to km/h',
        } : {
            text: 'KM/H',
            icon: ICONS.gaugeKm,
            tone: 'tone-active',
            title: 'Tap to switch to mph',
            aria: 'Switch unit to mph',
        },
        failMsg: 'Unit switch failed — status did not update',
        unknownMsg: 'Unit status unknown — wait for telemetry',
        sendFailMsg: 'Failed to send unit command',
    },
    cruise: {
        btnId: 'cruise-toggle-btn',
        valueId: 'status-cruise',
        iconId: 'cruise-icon',
        spinnerId: 'cruise-spinner',
        current: null,
        pending: null,
        next: (state) => !state,
        matches: (state, target) => state === target,
        isReady: (state) => state !== null,
        command: (target) => sendCommand(0x05, target ? 0x01 : 0x00),
        render: (state) => state ? {
            text: 'ON',
            icon: ICONS.route,
            tone: 'tone-active',
            title: 'Tap to turn cruise off',
            aria: 'Turn cruise off',
        } : {
            text: 'OFF',
            icon: ICONS.circleOff,
            tone: 'tone-muted',
            title: 'Tap to turn cruise on',
            aria: 'Turn cruise on',
        },
        failMsg: 'Cruise switch failed — status did not update',
        unknownMsg: 'Cruise status unknown — wait for telemetry',
        sendFailMsg: 'Failed to send cruise command',
    },
    start: {
        btnId: 'start-toggle-btn',
        valueId: 'status-start',
        iconId: 'start-icon',
        spinnerId: 'start-spinner',
        current: null,
        pending: null,
        next: (state) => !state,
        matches: (state, target) => state === target,
        isReady: (state) => state !== null,
        command: (target) => sendCommand(0x06, target ? 0x01 : 0x00),
        render: (state) => state ? {
            text: 'KICK',
            icon: ICONS.footprints,
            tone: 'tone-warn',
            title: 'Tap to switch to zero start',
            aria: 'Switch to zero start',
        } : {
            text: 'ZERO',
            icon: ICONS.circlePlay,
            tone: 'tone-active',
            title: 'Tap to switch to kick start',
            aria: 'Switch to kick start',
        },
        failMsg: 'Start mode switch failed — status did not update',
        unknownMsg: 'Start mode unknown — wait for telemetry',
        sendFailMsg: 'Failed to send start mode command',
    },
    mode: {
        btnId: 'mode-toggle-btn',
        valueId: 'status-mode',
        iconId: 'mode-icon',
        spinnerId: 'mode-spinner',
        current: null,
        pending: null,
        next: (state) => {
            const idx = MODE_CYCLE.indexOf(state);
            return MODE_CYCLE[(idx + 1) % MODE_CYCLE.length];
        },
        matches: (state, target) => state === target,
        isReady: (state) => state !== null,
        command: (target) => sendCommand(0x01, target),
        render: (state) => {
            const views = {
                0: { text: 'Lock/Limit', icon: ICONS.shield, tone: 'tone-danger' },
                1: { text: 'Eco', icon: ICONS.leaf, tone: 'tone-ok' },
                2: { text: 'Drive', icon: ICONS.gauge, tone: 'tone-active' },
                3: { text: 'Sport', icon: ICONS.zap, tone: 'tone-warn' },
            };
            const view = views[state] || { text: 'Unknown', icon: ICONS.gauge, tone: 'tone-muted' };
            return {
                ...view,
                title: 'Tap to cycle ride mode',
                aria: 'Cycle ride mode',
            };
        },
        failMsg: 'Mode switch failed — status did not update',
        unknownMsg: 'Mode unknown — wait for telemetry',
        sendFailMsg: 'Failed to send mode command',
    },
};

const messages = document.getElementById('messages');
const deviceInfo = document.getElementById('device-info');
const logRecordChk = document.getElementById('log-record-chk');
const authPasswordInput = document.getElementById('auth-password');
const authPasswordEdit = document.getElementById('auth-password-edit');
const savePwdBtn = document.getElementById('save-pwd-btn');
const newPasswordInput = document.getElementById('new-password');
const changePwdBtn = document.getElementById('change-pwd-btn');
const welcomeView = document.getElementById('welcome-view');
const sessionView = document.getElementById('session-view');
const sessionDeviceName = document.getElementById('session-device-name');
const navConnection = document.getElementById('nav-connection');

function syncAuthPassword(value) {
    if (value != null) authPasswordInput.value = value;
    if (authPasswordEdit) authPasswordEdit.value = authPasswordInput.value;
}

function setSessionUi(connected) {
    if (welcomeView) welcomeView.hidden = connected;
    if (sessionView) sessionView.hidden = !connected;
    if (navConnection) navConnection.hidden = !connected;
    if (connected && sessionDeviceName) {
        sessionDeviceName.textContent = (device && (device.name || device.id)) || 'Scooter';
    }
    if (!connected) {
        const scanBtn = document.getElementById('scan-btn');
        if (scanBtn) scanBtn.disabled = false;
    }
}

// Load saved password
const savedPwd = localStorage.getItem('scooter_password');
if (savedPwd) {
    syncAuthPassword(savedPwd);
}

savePwdBtn.onclick = () => {
    syncAuthPassword(authPasswordEdit ? authPasswordEdit.value : authPasswordInput.value);
    localStorage.setItem('scooter_password', authPasswordInput.value);
    log('Password saved as default.');
};

changePwdBtn.onclick = async () => {
    const newPwd = newPasswordInput.value;
    if (!/^\d{6,}$/.test(newPwd)) {
        alert('Error: Password must be at least 6 digits.');
        log('Error: Password must be at least 6 digits.');
        return;
    }
    if (!writeChar) {
        log('Error: Not connected.');
        return;
    }
    try {
        await writeChar.writeValue(new TextEncoder().encode('SC+' + newPwd));
        log('Sent Change Password command: SC+' + newPwd);

        // Auto-save the new password as the default auth password
        syncAuthPassword(newPwd);
        localStorage.setItem('scooter_password', newPwd);
        log('New password saved as default for future connections.');
        alert('Password change command sent. New password saved to settings.');
    } catch (e) {
        log('Error sending password change: ' + e);
    }
};

const authErrorModal = document.getElementById('auth-error-modal');
const authRetryForm = document.getElementById('auth-retry-form');
const cancelAuthBtn = document.getElementById('cancel-auth-btn');
const retryPasswordInput = document.getElementById('retry-password');

async function retryAuth() {
    const newPwd = retryPasswordInput.value;
    if (newPwd) {
        syncAuthPassword(newPwd);
        localStorage.setItem('scooter_password', newPwd);
    }
    authErrorModal.style.display = 'none';
    const ok = await authenticate();
    if (ok) setSessionUi(true);
}

if (authRetryForm) {
    authRetryForm.addEventListener('submit', (e) => {
        e.preventDefault();
        retryAuth();
    });
}

cancelAuthBtn.onclick = () => {
    authErrorModal.style.display = 'none';
    disconnectBLE();
};

function log(msg) {
    if (logRecordChk && !logRecordChk.checked) return;

    // Check if user is near the bottom before adding content (50px threshold)
    const isScrolledToBottom = messages.scrollHeight - messages.scrollTop <= messages.clientHeight + 50;

    const text = messages.textContent + msg + '\n';
    const lines = text.split('\n');
    if (lines.length > 100) {
        messages.textContent = lines.slice(lines.length - 100).join('\n');
    } else {
        messages.textContent = text;
    }

    // Only auto-scroll if we were already at the bottom
    if (isScrolledToBottom) {
        messages.scrollTop = messages.scrollHeight;
    }
}

async function connectBLE() {
    const scanBtn = document.getElementById('scan-btn');
    if (scanBtn) scanBtn.disabled = true;
    try {
        device = await navigator.bluetooth.requestDevice({
            filters: [{ services: [SERVICE_UUID] }],
            optionalServices: [SERVICE_UUID]
        });
        deviceInfo.textContent = `Connecting to ${device.name || device.id}…`;
        server = await device.gatt.connect();
        const service = await server.getPrimaryService(SERVICE_UUID);
        writeChar = await service.getCharacteristic(WRITE_UUID);
        readChar = await service.getCharacteristic(READ_UUID);
        await readChar.startNotifications();
        readChar.addEventListener('characteristicvaluechanged', handleNotification);
        deviceInfo.textContent = 'Authenticating…';
        log('Connected to device!');
        const ok = await authenticate();
        if (ok) {
            setSessionUi(true);
        } else {
            deviceInfo.textContent = 'Waiting for password…';
        }
    } catch (e) {
        deviceInfo.textContent = e.name === 'NotFoundError' ? '' : 'Connection failed.';
        log('Error: ' + e);
        setSessionUi(false);
    } finally {
        if (scanBtn && welcomeView && !welcomeView.hidden) scanBtn.disabled = false;
    }
}

// --- Authentication helpers ---
let authResolve = null;
let authMsgQueue = [];

function waitForAuthMsg(timeout = 2000) {
    return new Promise((resolve, reject) => {
        // Check queue first
        if (authMsgQueue.length > 0) {
            resolve(authMsgQueue.shift());
            return;
        }

        authResolve = resolve;
        setTimeout(() => {
            if (authResolve === resolve) {
                authResolve = null;
                reject('Timeout waiting for auth msg');
            }
        }, timeout);
    });
}


async function authenticate() {
    log('Authenticating...');
    authMsgQueue = []; // Clear queue start
    await writeChar.writeValue(new TextEncoder().encode('+VER?'));
    let pmAuthSuccess = false;
    for (let i = 0; i < 3; i++) {
        log(`Sending +PM? (Attempt ${i + 1}/3)`);
        await writeChar.writeValue(new TextEncoder().encode('+PM?'));
        try {
            while (true) {
                const msg = await waitForAuthMsg(2000);
                if (msg.startsWith('+PM>')) {
                    const challenge = msg.slice(4).trim();
                    if (challenge === 'OK') {
                        log('PM Authentication Successful');
                        pmAuthSuccess = true;
                        break;
                    } else {
                        const responseHash = generateHash(challenge);
                        await writeChar.writeValue(new TextEncoder().encode(`+PM<${responseHash}`));
                    }
                } else if (msg.includes('CODE')) {
                    // ignore
                }
            }
            if (pmAuthSuccess) break;
        } catch (e) {
            log('Timeout waiting for PM response, retrying...');
        }
    }
    if (!pmAuthSuccess) {
        log('Warning: PM Authentication did not complete.');
    }
    // Send +PA<randomcode>
    let myRandomCode = Array.from({ length: 6 }, () => Math.floor(Math.random() * 256).toString(16).padStart(2, '0')).join('').toUpperCase();
    await writeChar.writeValue(new TextEncoder().encode(`+PA<${myRandomCode}`));
    await new Promise(r => setTimeout(r, 100));
    const pwd = document.getElementById('auth-password').value || LEGACY_PASSWORD;
    await writeChar.writeValue(new TextEncoder().encode(`CODE=${pwd}`));

    // Check for Password Response (Handle potential intervening messages like +PA)
    const authStart = Date.now();
    while (Date.now() - authStart < 2000) {
        try {
            const msg = await waitForAuthMsg(500);
            if (msg.includes('CODE_NG')) {
                log('Error: Incorrect Password (CODE_NG received)');
                retryPasswordInput.value = authPasswordInput.value;
                authErrorModal.style.display = 'flex';
                retryPasswordInput.focus();
                retryPasswordInput.select();
                return false;
            }
        } catch (e) {
            // Check if overall time exceeded
            if (Date.now() - authStart >= 2000) break;
        }
    }

    await new Promise(r => setTimeout(r, 1000));
    await writeChar.writeValue(new TextEncoder().encode('GETDEVID'));
    await new Promise(r => setTimeout(r, 1000));
    log('Authentication done.');
    return true;
}

function handleNotification(event) {
    const value = event.target.value;
    const arr = [];
    for (let i = 0; i < value.byteLength; i++) arr.push(value.getUint8(i));
    log('[Received] ' + arr.map(x => x.toString(16).padStart(2, '0')).join(' '));

    // --- Packet Parsing (Adapted from main.py) ---
    // Header AA ... Footer BB
    if (arr.length >= 6 && arr[0] === 0xAA && arr[arr.length - 1] === 0xBB) {
        const cmdType = arr[1];

        // 0xA1: Status (Speed, Battery, Mode)
        if (cmdType === 0xA1 && arr.length >= 10) {
            const battery = arr[3];
            const speedRaw = (arr[4] << 8) | arr[5];
            const speed = speedRaw / 10.0;
            const mode = arr[7] & 0x0F;
            const isLightOn = (arr[7] & 0x40) !== 0;
            const isCruiseOn = (arr[7] & 0x20) !== 0;
            const isKickStart = (arr[6] & 0x04) !== 0; // Bit 2 of Byte 6
            const isMph = (arr[6] & 0x02) !== 0; // Bit 1 of Byte 6
            const isLocked = (arr[6] & 0x01) !== 0; // Bit 0 of Byte 6

            // Update UI
            document.getElementById('status-speed').textContent = speed.toFixed(1);
            document.getElementById('status-battery').textContent = battery;

            const lightEl = document.getElementById('status-light');
            if (lightEl) {
                lightEl.textContent = isLightOn ? 'ON' : 'OFF';
                lightEl.className = 'value ' + (isLightOn ? 'on' : 'off');
            }

            updateStatusAction('mode', mode);
            updateStatusAction('cruise', isCruiseOn);
            updateStatusAction('start', isKickStart);
            updateStatusAction('unit', isMph);
            updateStatusAction('lock', isLocked);
        }

        // 0xA2: Trip/Odometer
        else if (cmdType === 0xA2 && arr.length >= 10) {
            // Trip: High=data[4], Low=data[3]
            const tripRaw = (arr[4] << 8) | arr[3];
            const trip = tripRaw / 10.0;

            // ODO: High=data[5], Mid=data[6], Low=data[7]
            const odoRaw = (arr[5] << 16) | (arr[6] << 8) | arr[7];
            const odo = odoRaw / 10.0;

            document.getElementById('status-trip').textContent = trip.toFixed(1);
            document.getElementById('status-odo').textContent = odo.toFixed(1);
        }

        // 0xA3: Version Info
        else if (cmdType === 0xA3 && arr.length >= 6) {
            const swVer = arr[4] / 10.0;
            const hwVer = arr[5] / 10.0;
            document.getElementById('status-version').textContent = `S:${swVer.toFixed(1)} H:${hwVer.toFixed(1)}`;
        }

        // 0x04: Speed Limit Response
        else if (cmdType === 0x04 && arr.length >= 9) {
            const gear = arr[3];
            const limitRaw = (arr[5] << 8) | arr[6];
            const limit = limitRaw / 10.0;
            log(`[SpeedLimit] Gear ${gear}: ${limit.toFixed(1)} km/h`);
        }
    }

    // Try to decode as string
    let text = '';
    try {
        text = new TextDecoder('utf-8').decode(value);
    } catch { }
    if (text && text.trim().length > 1) {
        const msgStr = text.trim();
        log('[Received Str] ' + msgStr);

        // Push to queue
        authMsgQueue.push(msgStr);

        if (authResolve) {
            authResolve(authMsgQueue.shift());
            authResolve = null;
        }
    }
}

async function sendRawPacket(payload) {
    let xor = 0xAA;
    for (const b of payload) xor ^= b;
    const finalCmd = new Uint8Array([0xAA, ...payload, xor, 0xBB]);
    log('[Send] ' + Array.from(finalCmd).map(x => x.toString(16).padStart(2, '0')).join(' '));
    await writeChar.writeValue(finalCmd);
}

async function sendCommand(subCmd, value) {
    await sendRawPacket([0x03, 0x04, subCmd, 0x88, value, 0x00]);
}

async function setSpeedLimit(gear, limitKmh) {
    const val = Math.round(limitKmh * 10);
    const valH = (val >> 8) & 0xFF;
    const valL = val & 0xFF;
    await sendRawPacket([0x04, 0x04, gear, 0x88, valH, valL]);
}

async function getSpeedLimit(gear) {
    await sendRawPacket([0x04, 0x04, gear, 0x00, 0x00, 0x00]);
}



function showToast(message, kind) {
    const toast = document.getElementById('toast');
    if (!toast) return;
    toast.textContent = message;
    toast.className = 'toast show' + (kind ? ' ' + kind : '');
    toast.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => { toast.hidden = true; }, 200);
    }, 2800);
}

function setStatusBusy(key, busy) {
    const action = statusActions[key];
    const btn = document.getElementById(action.btnId);
    const spinner = document.getElementById(action.spinnerId);
    if (!btn || !spinner) return;
    btn.classList.toggle('busy', busy);
    spinner.hidden = !busy;
    if (busy) {
        btn.disabled = true;
    } else if (action.isReady(action.current) && writeChar) {
        btn.disabled = false;
    }
}

function updateStatusAction(key, state) {
    const action = statusActions[key];
    action.current = state;
    const btn = document.getElementById(action.btnId);
    const valueEl = document.getElementById(action.valueId);
    const iconEl = document.getElementById(action.iconId);
    if (!btn || !valueEl) return;

    const view = action.render(state);
    valueEl.textContent = view.text;
    valueEl.className = 'value';
    if (iconEl && view.icon) iconEl.innerHTML = view.icon;
    btn.classList.remove('tone-danger', 'tone-ok', 'tone-active', 'tone-warn', 'tone-muted');
    if (view.tone) btn.classList.add(view.tone);
    btn.title = view.title;
    btn.setAttribute('aria-label', view.aria);

    if (!action.pending) {
        btn.disabled = !writeChar;
    }

    if (action.pending && action.matches(state, action.pending.target)) {
        finishStatusSwitch(key, true);
    }
}

function finishStatusSwitch(key, success) {
    const action = statusActions[key];
    if (!action.pending) return;
    clearTimeout(action.pending.timer);
    action.pending = null;
    setStatusBusy(key, false);
    if (action.current !== null) updateStatusAction(key, action.current);

    if (!success) {
        showToast(action.failMsg, 'err');
    }
}

async function triggerStatusAction(key) {
    const action = statusActions[key];
    if (action.pending) return;
    if (!writeChar) {
        showToast('Not connected', 'err');
        return;
    }
    if (!action.isReady(action.current)) {
        showToast(action.unknownMsg, 'err');
        return;
    }

    const target = action.next(action.current);
    setStatusBusy(key, true);
    action.pending = {
        target,
        timer: setTimeout(() => finishStatusSwitch(key, false), 5000),
    };

    try {
        await action.command(target);
    } catch (e) {
        if (action.pending) {
            clearTimeout(action.pending.timer);
            action.pending = null;
        }
        setStatusBusy(key, false);
        if (action.current !== null) updateStatusAction(key, action.current);
        showToast(action.sendFailMsg, 'err');
        log(`Error sending ${key} command: ` + e);
    }
}

function resetStatusActions() {
    for (const key of Object.keys(statusActions)) {
        const action = statusActions[key];
        if (action.pending) {
            clearTimeout(action.pending.timer);
            action.pending = null;
        }
        action.current = null;
        const btn = document.getElementById(action.btnId);
        const valueEl = document.getElementById(action.valueId);
        const spinner = document.getElementById(action.spinnerId);
        if (valueEl) {
            valueEl.textContent = '--';
            valueEl.className = 'value';
        }
        if (btn) {
            btn.classList.remove('tone-danger', 'tone-ok', 'tone-active', 'tone-warn', 'tone-muted', 'busy');
            btn.disabled = true;
            btn.title = '';
            btn.setAttribute('aria-label', key);
        }
        const iconEl = document.getElementById(action.iconId);
        if (iconEl) iconEl.innerHTML = '';
        if (spinner) spinner.hidden = true;
    }
}

// Disconnect logic
async function disconnectBLE() {
    resetStatusActions();

    if (device && device.gatt && device.gatt.connected) {
        await device.gatt.disconnect();
        log('Disconnected from device.');
    } else {
        log('No device to disconnect.');
    }
    writeChar = null;
    readChar = null;
    server = null;
    setSessionUi(false);
    if (deviceInfo) deviceInfo.textContent = '';
}

document.getElementById('disconnect-btn').onclick = disconnectBLE;

document.getElementById('scan-btn').onclick = connectBLE;
document.getElementById('lock-toggle-btn').onclick = () => triggerStatusAction('lock');
document.getElementById('unit-toggle-btn').onclick = () => triggerStatusAction('unit');
document.getElementById('cruise-toggle-btn').onclick = () => triggerStatusAction('cruise');
document.getElementById('start-toggle-btn').onclick = () => triggerStatusAction('start');
document.getElementById('mode-toggle-btn').onclick = () => triggerStatusAction('mode');
document.getElementById('light-on-btn').onclick = () => sendCommand(0x02, 0x01);
document.getElementById('light-off-btn').onclick = () => sendCommand(0x02, 0x00);
document.getElementById('set-speed-limit-btn').onclick = () => {
    const gear = parseInt(document.getElementById('gear').value);
    const limit = parseFloat(document.getElementById('speed-limit').value);
    setSpeedLimit(gear, limit);
};
document.getElementById('get-speed-limit-btn').onclick = () => {
    const gear = parseInt(document.getElementById('gear').value);
    getSpeedLimit(gear);
};

document.getElementById('log-clear-btn').onclick = () => {
    messages.textContent = '';
};

const messagesPanel = document.getElementById('messages-panel');
const messagesCollapseBtn = document.getElementById('messages-collapse-btn');
if (messagesPanel && messagesCollapseBtn) {
    messagesCollapseBtn.onclick = () => {
        const collapsed = messagesPanel.classList.toggle('collapsed');
        messagesCollapseBtn.setAttribute('aria-expanded', String(!collapsed));
        messagesCollapseBtn.title = collapsed ? 'Expand' : 'Collapse';
    };
}

const themeToggle = document.getElementById('theme-toggle');
if (themeToggle) {
    themeToggle.onclick = () => {
        const root = document.documentElement;
        const next = root.classList.toggle('dark') ? 'dark' : 'light';
        localStorage.setItem('theme', next);
    };
}
