// Encodes an ArrayBuffer into a Base64URL string.
function bufferToBase64URL(buffer) {
    const bytes = new Uint8Array(buffer);
    let str = "";
    for (const charCode of bytes) {
        str += String.fromCharCode(charCode);
    }
    const base64 = btoa(str);
    return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

// Decodes a Base64URL string into an ArrayBuffer.
function base64URLToBuffer(base64URL) {
    const base64 = base64URL.replace(/-/g, "+").replace(/_/g, "/");
    const padLen = (4 - (base64.length % 4)) % 4;
    const padded = base64.padEnd(base64.length + padLen, "=");
    const binary = atob(padded);
    const buffer = new ArrayBuffer(binary.length);
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return buffer;
}

async function registerUser(email) {
    // 1. Get Challenge from Backend
    const beginURL = email ? `/auth/register/begin?email=${encodeURIComponent(email)}` : `/auth/register/begin`;
    const beginRes = await fetch(beginURL);
    if (!beginRes.ok) throw new Error("Failed to start registration: " + await beginRes.text());

    const options = await beginRes.json();

    // Fix binary fields for navigator.credentials.create
    options.publicKey.challenge = base64URLToBuffer(options.publicKey.challenge);
    options.publicKey.user.id = base64URLToBuffer(options.publicKey.user.id);
    if (options.publicKey.excludeCredentials) {
        options.publicKey.excludeCredentials.forEach(cred => {
            cred.id = base64URLToBuffer(cred.id);
        });
    }

    // 2. Create Credential (Bio/Key Prompt)
    const credential = await navigator.credentials.create(options);

    // 3. Send to Backend
    const finishBody = {
        id: credential.id,
        rawId: bufferToBase64URL(credential.rawId),
        type: credential.type,
        response: {
            attestationObject: bufferToBase64URL(credential.response.attestationObject),
            clientDataJSON: bufferToBase64URL(credential.response.clientDataJSON),
        },
    };

    const finishRes = await fetch(`/auth/register/finish`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(finishBody),
    });

    if (!finishRes.ok) throw new Error("Verification failed: " + await finishRes.text());
    return await finishRes.json();
}

async function finishLoginWithCredential(credential, authRequestID) {
    const finishBody = {
        id: credential.id,
        rawId: bufferToBase64URL(credential.rawId),
        type: credential.type,
        response: {
            authenticatorData: bufferToBase64URL(credential.response.authenticatorData),
            clientDataJSON: bufferToBase64URL(credential.response.clientDataJSON),
            signature: bufferToBase64URL(credential.response.signature),
            userHandle: credential.response.userHandle ? bufferToBase64URL(credential.response.userHandle) : null,
        },
    };

    const finishURL = authRequestID ? `/auth/login/finish?auth_request_id=${encodeURIComponent(authRequestID)}` : `/auth/login/finish`;
    const finishRes = await fetch(finishURL, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(finishBody),
    });

    if (!finishRes.ok) throw new Error("Login failed: " + await finishRes.text());
    return await finishRes.json();
}

async function loginUser(email, authRequestID) {
    // 1. Get Challenge (Assertion Options)
    // If email is empty, this triggers "Discoverable Credential" flow
    const url = email ? `/auth/login/begin?email=${encodeURIComponent(email)}` : `/auth/login/begin`;

    const beginRes = await fetch(url);
    if (!beginRes.ok) throw new Error("Failed to start login: " + await beginRes.text());

    const options = await beginRes.json();

    // Fix binary fields
    options.publicKey.challenge = base64URLToBuffer(options.publicKey.challenge);
    if (options.publicKey.allowCredentials) {
        options.publicKey.allowCredentials.forEach(cred => {
            cred.id = base64URLToBuffer(cred.id);
        });
    }

    // 2. Get Assertion (Bio/Key Prompt)
    // For discoverable keys, user selects account from browser UI
    const credential = await navigator.credentials.get(options);

    // 3. Send to Backend
    return await finishLoginWithCredential(credential, authRequestID);
}

async function requestRecovery(payload) {
    const params = new URLSearchParams();
    const email = (payload && payload.email ? payload.email : "").trim();
    const phone = (payload && payload.phone ? payload.phone : "").trim();
    if (email) params.set('email', email);
    if (phone) params.set('phone', phone);

    const res = await fetch('/auth/recovery/request', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: params.toString()
    });

    const contentType = (res.headers.get('content-type') || "").toLowerCase();
    let message = "";
    if (contentType.includes('application/json')) {
        const data = await res.json();
        message = data.message || "";
    } else {
        message = await res.text();
    }

    if (!res.ok) throw new Error(message || ("HTTP " + res.status));
    return message;
}

async function verifyRecoveryCode(payload) {
    const params = new URLSearchParams();
    const phone = (payload && payload.phone ? payload.phone : "").trim();
    const code = (payload && payload.code ? payload.code : "").trim();
    if (phone) params.set('phone', phone);
    if (code) params.set('code', code);

    const res = await fetch('/auth/recovery/verify-code', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: params.toString()
    });

    const contentType = (res.headers.get('content-type') || "").toLowerCase();
    let data = null;
    let message = "";
    if (contentType.includes('application/json')) {
        data = await res.json();
        message = data.message || "";
    } else {
        message = await res.text();
    }

    if (!res.ok) throw new Error(message || ("HTTP " + res.status));
    return data || { message };
}

async function generateQRLogin(payload) {
    const purpose = (payload && payload.purpose ? payload.purpose : "").trim();
    const params = new URLSearchParams();
    if (purpose) {
        params.set('purpose', purpose);
    }
    const url = params.toString() ? ('/auth/qr/generate?' + params.toString()) : '/auth/qr/generate';
    const res = await fetch(url);

    const contentType = (res.headers.get('content-type') || "").toLowerCase();
    let data = null;
    let message = "";
    if (contentType.includes('application/json')) {
        data = await res.json();
        message = data.message || "";
    } else {
        message = await res.text();
    }

    if (!res.ok) throw new Error(message || ("HTTP " + res.status));
    if (!data || !data.token) throw new Error("Invalid QR response");
    return data;
}

async function approveQRLogin(payload) {
    const token = (payload && payload.token ? payload.token : "").trim();
    const res = await fetch('/auth/qr/approve', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token })
    });

    const contentType = (res.headers.get('content-type') || "").toLowerCase();
    let data = null;
    let message = "";
    if (contentType.includes('application/json')) {
        data = await res.json();
        message = data.message || "";
    } else {
        message = await res.text();
    }

    if (!res.ok) throw new Error(message || ("HTTP " + res.status));
    return data || { message };
}

async function getQRLoginStatus(token, authRequestID) {
    const params = new URLSearchParams();
    params.set('token', (token || "").trim());
    if ((authRequestID || "").trim()) {
        params.set('auth_request_id', authRequestID.trim());
    }

    const res = await fetch('/auth/qr/status?' + params.toString());
    const contentType = (res.headers.get('content-type') || "").toLowerCase();
    let data = null;
    let message = "";
    if (contentType.includes('application/json')) {
        data = await res.json();
        message = data.message || "";
    } else {
        message = await res.text();
    }

    if (!res.ok) throw new Error(message || ("HTTP " + res.status));
    return data || { status: "expired" };
}

async function getDeviceSessions() {
    const res = await fetch('/auth/devices');
    const contentType = (res.headers.get('content-type') || "").toLowerCase();
    let data = null;
    let message = "";
    if (contentType.includes('application/json')) {
        data = await res.json();
        message = data.message || "";
    } else {
        message = await res.text();
    }

    if (!res.ok) throw new Error(message || ("HTTP " + res.status));
    return data || { devices: [] };
}

async function logoutDeviceSession(payload) {
    const sessionID = (payload && payload.session_id ? payload.session_id : "").trim();
    const res = await fetch('/auth/devices/logout', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ session_id: sessionID })
    });

    const contentType = (res.headers.get('content-type') || "").toLowerCase();
    let data = null;
    let message = "";
    if (contentType.includes('application/json')) {
        data = await res.json();
        message = data.message || "";
    } else {
        message = await res.text();
    }

    if (!res.ok) throw new Error(message || ("HTTP " + res.status));
    return data || { status: "ok", current_logged_out: false };
}

async function removeDeviceSession(payload) {
    const sessionID = (payload && payload.session_id ? payload.session_id : "").trim();
    const res = await fetch('/auth/devices/remove', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ session_id: sessionID })
    });

    const contentType = (res.headers.get('content-type') || "").toLowerCase();
    let data = null;
    let message = "";
    if (contentType.includes('application/json')) {
        data = await res.json();
        message = data.message || "";
    } else {
        message = await res.text();
    }

    if (!res.ok) throw new Error(message || ("HTTP " + res.status));
    return data || { status: "removed", current_removed: false, credential_revoked: false };
}

async function getPasskeys() {
    const res = await fetch('/auth/passkeys');
    const contentType = (res.headers.get('content-type') || "").toLowerCase();
    let data = null;
    let message = "";
    if (contentType.includes('application/json')) {
        data = await res.json();
        message = data.message || "";
    } else {
        message = await res.text();
    }

    if (!res.ok) throw new Error(message || ("HTTP " + res.status));
    return data || { passkeys: [] };
}

async function deletePasskey(payload) {
    const credentialID = (payload && payload.credential_id ? payload.credential_id : "").trim();
    const res = await fetch('/auth/passkeys/delete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ credential_id: credentialID })
    });

    const contentType = (res.headers.get('content-type') || "").toLowerCase();
    let data = null;
    let message = "";
    if (contentType.includes('application/json')) {
        data = await res.json();
        message = data.message || "";
    } else {
        message = await res.text();
    }

    if (!res.ok) throw new Error(message || ("HTTP " + res.status));
    return data || { status: "deleted", current_logged_out: false };
}

async function getDeleteAccountImpact() {
    const res = await fetch('/auth/delete-impact');
    const contentType = (res.headers.get('content-type') || "").toLowerCase();
    let data = null;
    let message = "";
    if (contentType.includes('application/json')) {
        data = await res.json();
        message = data.message || "";
    } else {
        message = await res.text();
    }

    if (!res.ok) throw new Error(message || ("HTTP " + res.status));
    return data || { clients: [] };
}
