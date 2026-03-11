require('dotenv').config();
const express = require('express');
const multer = require('multer');
const axios = require('axios');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
// pdf-parse removido - usando leitura direta de arquivo

const app = express();
const upload = multer({ dest: 'uploads/' });
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const VPS_API_URL = process.env.VPS_API_URL || 'http://151.244.242.151:81/api/client.php';
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || '+6K2QrhC3JW+Zxny3TZQhUxcq7Op2E9gm7398srg9uw=';
const HMAC_SECRET = process.env.HMAC_SECRET || 'kanga_secret_2025';
const ENCRYPTION_KEY_BUFFER = Buffer.from(ENCRYPTION_KEY, 'base64');

// --- SEGURANÇA ---

/**
 * Criptografa dados para envio à VPS
 * @param {string} text - Texto a ser criptografado
 * @returns {string} Dados criptografados em base64
 */
function encryptRequest(text) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY_BUFFER, iv);
    let encrypted = cipher.update(text, 'utf8', 'binary');
    encrypted += cipher.final('binary');
    return Buffer.concat([iv, Buffer.from(encrypted, 'binary')]).toString('base64');
}

/**
 * Descriptografa resposta da VPS
 * @param {string} encryptedBase64 - Dados criptografados em base64
 * @returns {object} Dados descriptografados
 */
function decryptResponse(encryptedBase64) {
    try {
        const data = Buffer.from(encryptedBase64, 'base64');
        const iv = data.slice(0, 16);
        const ciphertext = data.slice(16);
        const decipher = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY_BUFFER, iv);
        let decrypted = decipher.update(ciphertext, 'binary', 'utf8');
        decrypted += decipher.final('utf8');
        return JSON.parse(decrypted);
    } catch (e) {
        console.error('Erro na descriptografia:', e.message);
        return { success: false, error: "Falha na descriptografia da VPS" };
    }
}

/**
 * Chama a API da VPS com criptografia
 * @param {string} endpoint - Endpoint a ser chamado
 * @param {object} data - Dados a serem enviados
 * @returns {Promise<object>} Resposta da VPS
 */
async function callVPSAPI(endpoint, data) {
    const payload = { 
        endpoint: endpoint, 
        timestamp: Math.floor(Date.now() / 1000), 
        client_id: 'render_client',
        data: data 
    };

    const payloadStr = JSON.stringify(payload);
    const signature = crypto.createHmac('sha256', HMAC_SECRET).update(payloadStr).digest('hex');
    const encrypted = encryptRequest(payloadStr);

    try {
        const response = await axios.post(VPS_API_URL, { 
            encrypted: encrypted, 
            signature: signature 
        });

        if (response.data && response.data.encrypted) {
            return decryptResponse(response.data.encrypted);
        }
        return response.data;
    } catch (error) {
        console.error('Erro na chamada VPS:', error.message);
        throw error;
    }
}

/**
 * Extrai token do arquivo enviado (leitura direta)
 * @param {string} filePath - Caminho do arquivo
 * @returns {string|null} Token extraído ou null
 */
function extractTokenFromFile(filePath) {
    try {
        const content = fs.readFileSync(filePath, 'utf8');
        
        // Padrão principal: Token: [CÓDIGO]
        const tokenMatch = content.match(/Token:\s*([A-Za-z0-9+\/=]+)/i);
        if (tokenMatch && tokenMatch[1]) {
            return tokenMatch[1].trim();
        }
        
        // Fallback: qualquer string longa que pareça um token
        const fallbackMatch = content.match(/([A-Za-z0-9+\/=]{30,})/);
        if (fallbackMatch && fallbackMatch[1]) {
            return fallbackMatch[1].trim();
        }
        
        return null;
    } catch (error) {
        console.error('Erro ao ler arquivo:', error.message);
        return null;
    }
}

// --- ROTAS ---

/**
 * GET /api/status
 * Verifica conectividade com a VPS
 */
app.get('/api/status', async (req, res) => {
    try {
        const result = await callVPSAPI('status', {});
        res.json(result);
    } catch (error) {
        console.error('Status error:', error.message);
        res.json({ success: false, error: "Conexão com VPS falhou" });
    }
});

/**
 * POST /api/comprar
 * Inicia processo de compra de token
 */
app.post('/api/comprar', async (req, res) => {
    try {
        const { provider, plan } = req.body;
        
        if (!provider || !plan) {
            return res.status(400).json({ 
                success: false, 
                error: "Provider e plan são obrigatórios" 
            });
        }
        
        const result = await callVPSAPI('comprar', { 
            provedor: provider, 
            plano: plan 
        });
        
        res.json(result);
    } catch (error) { 
        console.error('Comprar error:', error.message);
        res.status(500).json({ 
            success: false, 
            error: "Erro ao processar compra: " + error.message 
        }); 
    }
});

/**
 * POST /api/enviar-pdf
 * Processa arquivo de token e ativa CDN
 */
app.post('/api/enviar-pdf', upload.single('pdf'), async (req, res) => {
    try {
        const file = req.file;
        const ip = req.body.ip;
        
        if (!file) {
            return res.status(400).json({ 
                success: false, 
                error: "Arquivo PDF não enviado" 
            });
        }
        
        if (!ip) {
            // Limpar arquivo se IP não fornecido
            if (fs.existsSync(file.path)) fs.unlinkSync(file.path);
            return res.status(400).json({ 
                success: false, 
                error: "IP da VPS é obrigatório" 
            });
        }

        // Extrair token do arquivo (leitura direta)
        const token = extractTokenFromFile(file.path);
        
        // Limpar arquivo após leitura
        if (fs.existsSync(file.path)) fs.unlinkSync(file.path);
        
        if (!token) {
            return res.status(400).json({ 
                success: false, 
                error: 'Este arquivo não parece ser um token válido' 
            });
        }

        const result = await callVPSAPI('criar_cdn', { 
            token: token, 
            ip: ip 
        });
        
        res.json(result);
    } catch (error) { 
        console.error('Enviar-pdf error:', error.message);
        
        // Tentar limpar arquivo em caso de erro
        if (req.file && req.file.path && fs.existsSync(req.file.path)) {
            fs.unlinkSync(req.file.path);
        }
        
        res.status(500).json({ 
            success: false, 
            error: error.message 
        }); 
    }
});

/**
 * POST /api/renovar
 * Solicita renovação de domínio
 */
app.post('/api/renovar', async (req, res) => {
    try {
        const { dominio } = req.body;
        
        if (!dominio) {
            return res.status(400).json({ 
                success: false, 
                error: "Domínio é obrigatório" 
            });
        }
        
        const result = await callVPSAPI('renovar', { 
            dominio: dominio 
        });
        
        res.json(result);
    } catch (error) { 
        console.error('Renovar error:', error.message);
        res.status(500).json({ 
            success: false, 
            error: error.message 
        }); 
    }
});

/**
 * GET /api/provedores
 * Lista provedores disponíveis
 */
app.get('/api/provedores', async (req, res) => {
    try {
        const result = await callVPSAPI('listar_provedores', {});
        res.json(result);
    } catch (error) {
        console.error('Provedores error:', error.message);
        res.status(500).json({ 
            success: false, 
            error: error.message 
        });
    }
});

/**
 * GET /api/planos
 * Lista planos disponíveis
 */
app.get('/api/planos', async (req, res) => {
    try {
        const result = await callVPSAPI('listar_planos', {});
        res.json(result);
    } catch (error) {
        console.error('Planos error:', error.message);
        res.status(500).json({ 
            success: false, 
            error: error.message 
        });
    }
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
    console.log(`🚀 CDN Kanga Bridge rodando na porta ${PORT}`);
    console.log(`📡 VPS API: ${VPS_API_URL}`);
});