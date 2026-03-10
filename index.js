require('dotenv').config();
const express = require('express');
const multer = require('multer');
const axios = require('axios');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const pdfParse = require('pdf-parse');

const app = express();
const upload = multer({ dest: 'uploads/' });
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// CONFIGURAÇÕES (Devem ser iguais às da VPS)
const VPS_API_URL = process.env.VPS_API_URL || 'http://151.244.242.151:81/api/client.php';
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || '+6K2QrhC3JW+Zxny3TZQhUxcq7Op2E9gm7398srg9uw=';
const HMAC_SECRET = process.env.HMAC_SECRET || 'kanga_secret_2025';
const ENCRYPTION_KEY_BUFFER = Buffer.from(ENCRYPTION_KEY, 'base64');

// --- FUNÇÕES DE SEGURANÇA ---
function encryptRequest(text) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY_BUFFER, iv);
    let encrypted = cipher.update(text, 'utf8', 'binary');
    encrypted += cipher.final('binary');
    return Buffer.concat([iv, Buffer.from(encrypted, 'binary')]).toString('base64');
}

function signRequest(data) {
    const sortedKeys = Object.keys(data).sort();
    const baseString = sortedKeys.map(k => `${k}=${data[k]}`).join('&');
    return crypto.createHmac('sha256', HMAC_SECRET).update(baseString).digest('hex');
}

async function callVPSAPI(action, data) {
    const payload = { 
        action, 
        timestamp: Math.floor(Date.now() / 1000), 
        client_id: 'render_client',
        ...data 
    };
    payload.signature = signRequest(payload);
    const encrypted = encryptRequest(JSON.stringify(payload));

    const response = await axios.post(VPS_API_URL, { data: encrypted });
    // Nota: O client.php retorna dados criptografados também no seu código original
    return response.data; 
}

// --- ROTAS DA API ---

app.post('/api/comprar', async (req, res) => {
    try {
        const result = await callVPSAPI('comprar', { provider: req.body.provider, plan: req.body.plan });
        res.json(result);
    } catch (error) { res.status(500).json({ success: false, error: error.message }); }
});

app.post('/api/enviar-pdf', upload.single('pdf'), async (req, res) => {
    try {
        const dataBuffer = fs.readFileSync(req.file.path);
        const pdfData = await pdfParse(dataBuffer);
        
        // Extrai o token do texto do PDF usando Regex
        const tokenMatch = pdfData.text.match(/Token:\s*([A-Za-z0-9+\/=]+)/i);
        if (!tokenMatch) throw new Error('Token não encontrado no PDF');

        const result = await callVPSAPI('criar_cdn', { token: tokenMatch[1], ip: req.body.ip });
        fs.unlinkSync(req.file.path); // Limpa arquivo temporário
        res.json(result);
    } catch (error) { res.status(500).json({ success: false, error: error.message }); }
});

app.post('/api/renovar', async (req, res) => {
    try {
        const result = await callVPSAPI('renovar', { dominio: req.body.dominio });
        res.json(result);
    } catch (error) { res.status(500).json({ success: false, error: error.message }); }
});

app.get('/api/status', async (req, res) => {
    try {
        const result = await callVPSAPI('status', {});
        res.json({ success: true, vps: result });
    } catch (error) { res.json({ success: false }); }
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`Servidor Render rodando na porta ${PORT}`));