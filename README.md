# efi-proxy-fly

Relay de mTLS para a API Pix da Efí, rodando no Fly.io — substitui o Worker Cloudflare
(`workers/efi-proxy/` no repo `nsmusic`) depois que a Efí passou a bloquear (WAF/rede) o tráfego
vindo da faixa de IP dos Cloudflare Workers.

Mesmo desenho de segurança do Worker original: o app Next.js nunca manda host/URL, só um enum
`env` (sandbox/production) + path + método, validados contra uma allowlist fechada. Elimina SSRF
por construção.

## Configurar os segredos no Fly

```bash
fly secrets set EFI_PROXY_SECRET="mesmo valor configurado no Cloudflare Pages (EFI_PROXY_URL/EFI_PROXY_SECRET)"
fly secrets set RECONCILE_SECRET="mesmo valor configurado no Cloudflare Pages"
fly secrets set APP_URL="https://nsmusic.nsnexus.com.br"

# Certificados em base64 (um par por ambiente)
fly secrets set EFI_PRODUCTION_CERT_B64="$(base64 -w0 cert-producao.pem)"
fly secrets set EFI_PRODUCTION_KEY_B64="$(base64 -w0 key-producao.pem)"
fly secrets set EFI_SANDBOX_CERT_B64="$(base64 -w0 cert-sandbox.pem)"
fly secrets set EFI_SANDBOX_KEY_B64="$(base64 -w0 key-sandbox.pem)"
```

## Deploy

```bash
fly launch --no-deploy   # primeira vez, usa o fly.toml já existente
fly deploy
```

## Depois de deployado

Trocar `EFI_PROXY_URL` no Cloudflare Pages (`nsmusic`) para a URL pública deste app
(`https://nsmusic-efi-proxy.fly.dev` ou domínio customizado, se configurado).
