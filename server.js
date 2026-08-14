// Relay de mTLS pra API Pix da Efí — versão Fly.io, substituindo o Worker Cloudflare
// (workers/efi-proxy/) depois que a Efí bloqueou (WAF/rede) o IP dos Workers. Mesmo desenho de
// segurança do Worker original: o app Next.js nunca fala direto com a Efí nem manda host/URL — só um
// enum `env` (sandbox/production), path e método, validados contra uma allowlist fechada. Isso
// elimina SSRF por construção, igual antes.
//
// Diferente do Worker, aqui é um processo Node normal — usa https.request nativo com o certificado
// cliente, sem precisar de um binding especial da plataforma.

const http = require('http');
const https = require('https');

const HOSTS = {
  sandbox: 'pix-h.api.efipay.com.br',
  production: 'pix.api.efipay.com.br',
};

const TXID_PATTERN = '[A-Za-z0-9]{26,35}';

const PATH_RULES = [
  { method: 'POST', pattern: /^\/oauth\/token$/ },
  { method: 'PUT', pattern: new RegExp(`^/v2/cob/${TXID_PATTERN}$`) },
  { method: 'GET', pattern: new RegExp(`^/v2/cob/${TXID_PATTERN}$`) },
  { method: 'GET', pattern: /^\/v2\/loc\/\d+\/qrcode$/ },
];

const FORWARDED_HEADER_NAMES = ['authorization', 'content-type'];

function pickAllowedHeaders(headers) {
  const out = {};
  if (!headers || typeof headers !== 'object') return out;
  for (const name of FORWARDED_HEADER_NAMES) {
    const key = Object.keys(headers).find((k) => k.toLowerCase() === name);
    if (key && headers[key]) out[name] = headers[key];
  }
  return out;
}

// Certificados chegam como env var em base64 (Fly secrets não suportam bem multi-linha/arquivo
// direto) — decodificados uma vez na subida do processo.
function loadCertPair(envPrefix) {
  const certB64 = process.env[`${envPrefix}_CERT_B64`];
  const keyB64 = process.env[`${envPrefix}_KEY_B64`];
  if (!certB64 || !keyB64) return null;
  return {
    cert: Buffer.from(certB64, 'base64'),
    key: Buffer.from(keyB64, 'base64'),
  };
}

const CERTS = {
  sandbox: loadCertPair('EFI_SANDBOX'),
  production: loadCertPair('EFI_PRODUCTION'),
};

function jsonResponse(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) });
  res.end(payload);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      // Corta requisição absurdamente grande cedo — mesmo espírito do MAX_FILE_BASE64_CHARS do app.
      if (size > 10_000_000) {
        reject(new Error('payload muito grande'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

// Repassa a chamada pra Efí via https.request nativo, apresentando o certificado cliente da conta
// (sandbox ou produção, conforme `efiEnv`). Equivalente ao `mtlsBinding.fetch` do Worker Cloudflare.
function relayToEfi({ efiEnv, path, method, headers, body }) {
  return new Promise((resolve, reject) => {
    const certPair = CERTS[efiEnv];
    if (!certPair) {
      reject(Object.assign(new Error(`certificado de ${efiEnv} não configurado`), { code: 'NO_CERT' }));
      return;
    }

    const options = {
      hostname: HOSTS[efiEnv],
      port: 443,
      path,
      method,
      headers: pickAllowedHeaders(headers),
      cert: certPair.cert,
      key: certPair.key,
      timeout: 8000,
    };

    const req = https.request(options, (upstreamRes) => {
      const chunks = [];
      upstreamRes.on('data', (c) => chunks.push(c));
      upstreamRes.on('end', () => {
        resolve({
          status: upstreamRes.statusCode,
          contentType: upstreamRes.headers['content-type'] || 'application/json',
          body: Buffer.concat(chunks),
        });
      });
    });

    req.on('timeout', () => req.destroy(new Error('timeout ao chamar a Efí')));
    req.on('error', reject);

    if (method !== 'GET' && body) req.write(body);
    req.end();
  });
}

async function handleRelay(req, res) {
  const proxySecret = process.env.EFI_PROXY_SECRET;
  if (!proxySecret) {
    console.warn('[efi-proxy-fly] EFI_PROXY_SECRET não configurado neste serviço.');
    jsonResponse(res, 500, { error: 'EFI_PROXY_SECRET não configurado' });
    return;
  }
  if (req.headers['x-efi-proxy-secret'] !== proxySecret) {
    jsonResponse(res, 401, { error: 'secret inválido' });
    return;
  }

  let payload;
  try {
    const raw = await readBody(req);
    payload = JSON.parse(raw.toString('utf8') || '{}');
  } catch (e) {
    jsonResponse(res, 400, { error: 'corpo inválido' });
    return;
  }

  const { env: efiEnv, path, method, headers, body } = payload || {};

  if (!HOSTS[efiEnv]) {
    jsonResponse(res, 400, { error: 'env inválido (esperado sandbox ou production)' });
    return;
  }
  if (typeof path !== 'string' || typeof method !== 'string') {
    jsonResponse(res, 400, { error: 'path/method inválidos' });
    return;
  }
  const rule = PATH_RULES.find((r) => r.method === method && r.pattern.test(path));
  if (!rule) {
    jsonResponse(res, 400, { error: 'path/method não permitido' });
    return;
  }

  try {
    const upstream = await relayToEfi({ efiEnv, path, method, headers, body });
    res.writeHead(upstream.status, { 'Content-Type': upstream.contentType });
    res.end(upstream.body);
  } catch (err) {
    console.warn('[efi-proxy-fly] Falha ao chamar a Efí:', err.message);
    // TODO(debug-temp): expõe err.message pra diagnosticar o 502 sem precisar de acesso a log do
    // Fly. Remover depois de confirmado o fluxo funcionando.
    jsonResponse(res, 502, { error: 'falha ao chamar a Efí', debug: err.message, code: err.code });
  }
}

// Reconciliação agendada de pedidos travados — mesmo motivo do Worker Cloudflare original: a
// confirmação de pagamento/música pronta depende do polling no navegador do cliente, então isso
// destrava pedidos cujo cliente fechou a aba cedo demais. Ver src/app/api/orders/reconcile/route.js.
function scheduleReconcile() {
  const appUrl = process.env.APP_URL;
  const secret = process.env.RECONCILE_SECRET;
  if (!appUrl || !secret) {
    console.warn('[efi-proxy-fly] APP_URL/RECONCILE_SECRET não configurados — reconciliação agendada desativada.');
    return;
  }

  const run = async () => {
    try {
      const res = await fetch(`${appUrl}/api/orders/reconcile`, {
        method: 'POST',
        headers: { 'X-Reconcile-Secret': secret },
        signal: AbortSignal.timeout(60000),
      });
      const body = await res.text().catch(() => '');
      if (!res.ok) {
        console.warn(`[efi-proxy-fly] Reconciliação respondeu HTTP ${res.status}: ${body.slice(0, 200)}`);
        return;
      }
      console.log(`[efi-proxy-fly] Reconciliação concluída: ${body.slice(0, 300)}`);
    } catch (err) {
      console.warn('[efi-proxy-fly] Falha na reconciliação agendada:', err.message);
    }
  };

  setInterval(run, 10 * 60 * 1000);
}

const server = http.createServer(async (req, res) => {
  try {
    if (req.method === 'GET' && req.url === '/health') {
      jsonResponse(res, 200, { ok: true });
      return;
    }
    if (req.method === 'POST' && req.url === '/relay') {
      await handleRelay(req, res);
      return;
    }
    jsonResponse(res, 404, { error: 'not found' });
  } catch (err) {
    console.error('[efi-proxy-fly] Exceção não tratada:', err.stack || err.message);
    jsonResponse(res, 500, { error: 'erro interno no proxy' });
  }
});

const port = process.env.PORT || 8080;
server.listen(port, () => {
  console.log(`[efi-proxy-fly] Ouvindo na porta ${port}`);
  scheduleReconcile();
});
