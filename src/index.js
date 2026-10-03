import express from 'express';
import { OAuth2Client } from 'google-auth-library';
import dotenv from 'dotenv';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

dotenv.config();

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const app = express();
const PORT = process.env.PORT || 3000;

// ---------------------------------------------------------------------------
// Autenticação: cliente OAuth2 do Google
// ---------------------------------------------------------------------------
const client = new OAuth2Client(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  process.env.GOOGLE_REDIRECT_URI
);

// ---------------------------------------------------------------------------
// Autorização: RBAC baseado no domínio do e-mail retornado pelo Google
// ---------------------------------------------------------------------------
const ROLES_BY_DOMAIN = {
  'ufjf.br': 'professor',
  'estudante.ufjf.br': 'aluno',
};

const PERMISSIONS_BY_ROLE = {
  professor: ['ver notas', 'lançar notas', 'criar turma'],
  aluno: ['ver notas'],
};

function getRole(payload) {
  if (!payload?.email || payload.email_verified !== true) return null;
  const domain = payload.email.split('@')[1]?.toLowerCase();
  return ROLES_BY_DOMAIN[domain] ?? null;
}

// ---------------------------------------------------------------------------
// Sessão simples em memória (cookie "sid" -> dados do usuário)
// ---------------------------------------------------------------------------
const sessions = new Map();

function parseCookies(req) {
  return Object.fromEntries(
    (req.headers.cookie || '')
      .split(';')
      .map((c) => c.trim().split('='))
      .filter(([k]) => k)
  );
}

function requireAuth(req, res, next) {
  const { sid } = parseCookies(req);
  const user = sid && sessions.get(sid);
  if (!user) return res.redirect('/');
  req.user = user;
  next();
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).send(page('Acesso negado', `
        <p>Seu papel é <strong>${esc(req.user.role)}</strong>, mas esta área exige: ${roles.map(esc).join(' ou ')}.</p>
        <p><a href="/welcome">Voltar</a></p>`));
    }
    next();
  };
}

// ---------------------------------------------------------------------------
// Utilidades de HTML
// ---------------------------------------------------------------------------
function esc(v) {
  return String(v ?? '')
    .replaceAll('&', '&amp;').replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;').replaceAll('"', '&quot;');
}

function page(title, body) {
  return `<!DOCTYPE html>
<html lang="pt-BR"><head><meta charset="UTF-8"><title>${esc(title)}</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 720px; margin: 40px auto; padding: 0 16px; }
  .ok { color: #1a7f37; } .deny { color: #b42318; }
  img.avatar { width: 96px; height: 96px; border-radius: 50%; }
  table { border-collapse: collapse; } td { padding: 4px 12px 4px 0; vertical-align: top; }
  pre { background: #f4f4f4; padding: 12px; overflow: auto; font-size: 12px; }
  .badge { padding: 2px 8px; border-radius: 10px; background: #e6f4ea; color: #1a7f37; font-size: 12px; }
</style></head><body><h1>${esc(title)}</h1>${body}</body></html>`;
}

// ---------------------------------------------------------------------------
// Rotas
// ---------------------------------------------------------------------------
app.use(express.static(path.join(__dirname, '..', 'public')));

// Inicia o fluxo OAuth2: redireciona para a tela de login do Google
app.get('/login', (req, res) => {
  const url = client.generateAuthUrl({
    access_type: 'offline',
    scope: ['email', 'profile', 'openid'],
  });
  res.redirect(url);
});

// Callback: troca o "code" por tokens, valida o id_token e aplica o RBAC
app.get('/callback', async (req, res) => {
  try {
    const { code } = req.query;
    const { tokens } = await client.getToken(code);
    console.log('Tokens recebidos do Google:', tokens);
    client.setCredentials(tokens);

    const ticket = await client.verifyIdToken({
      idToken: tokens.id_token,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    console.log('Payload do id_token:', payload);

    // ---- Autenticação concluída. Agora a autorização (RBAC): ----
    const role = getRole(payload);
    if (!role) {
      console.warn(`Acesso negado para ${payload.email} (domínio não institucional)`);
      return res.status(403).send(page('Acesso negado', `
        <p class="ok">Autenticação com o Google realizada com sucesso.</p>
        <p class="deny"><strong>Autorização negada:</strong> o e-mail <code>${esc(payload.email)}</code>
        não pertence à instituição (UFJF). Apenas contas <code>@ufjf.br</code> e
        <code>@estudante.ufjf.br</code> possuem acesso.</p>
        <p><a href="/">Voltar ao início</a></p>`));
    }

    const sid = crypto.randomBytes(32).toString('hex');
    sessions.set(sid, { ...payload, role });
    res.setHeader('Set-Cookie', `sid=${sid}; HttpOnly; Path=/; SameSite=Lax`);
    res.redirect('/welcome');
  } catch (error) {
    console.error('Erro na autenticação:', error);
    res.status(500).send(page('Erro', '<p>Erro ao autenticar com o Google.</p><p><a href="/">Voltar</a></p>'));
  }
});

// Página autenticada: exibe os dados do Google e o resultado do RBAC
app.get('/welcome', requireAuth, (req, res) => {
  const u = req.user;
  const perms = PERMISSIONS_BY_ROLE[u.role] || [];
  res.send(page(`Bem-vindo, ${u.given_name || u.name}!`, `
    <p class="ok"><strong>Autenticação com o Google realizada com sucesso.</strong></p>
    ${u.picture ? `<img class="avatar" src="${esc(u.picture)}" alt="Foto de perfil" referrerpolicy="no-referrer">` : ''}

    <h2>Dados recebidos do Google (id_token)</h2>
    <table>
      <tr><td>Nome completo</td><td>${esc(u.name)}</td></tr>
      <tr><td>Primeiro nome</td><td>${esc(u.given_name)}</td></tr>
      <tr><td>Sobrenome</td><td>${esc(u.family_name)}</td></tr>
      <tr><td>E-mail</td><td>${esc(u.email)} ${u.email_verified ? '<span class="badge">verificado</span>' : '(não verificado)'}</td></tr>
      <tr><td>Domínio (hd)</td><td>${esc(u.hd ?? '—')}</td></tr>
      <tr><td>ID Google (sub)</td><td><code>${esc(u.sub)}</code></td></tr>
      <tr><td>Locale</td><td>${esc(u.locale ?? '—')}</td></tr>
    </table>

    <h2>Controle de acesso (RBAC)</h2>
    <p>Atributo avaliado: domínio do e-mail <code>${esc(u.email.split('@')[1])}</code></p>
    <p>Papel atribuído: <strong>${esc(u.role)}</strong></p>
    <p class="ok">Acesso: <strong>permitido</strong></p>
    <p>Permissões deste papel: ${perms.map((p) => `<code>${esc(p)}</code>`).join(', ')}</p>
    <p>Áreas protegidas:
      <a href="/area/aluno">área do aluno</a> |
      <a href="/area/professor">área do professor</a>
    </p>

    <details><summary>Payload completo do id_token</summary>
      <pre>${esc(JSON.stringify(u, null, 2))}</pre>
    </details>

    <p><a href="/logout">Sair</a></p>
  `));
});

// Rotas protegidas por papel, para demonstrar a autorização na prática
app.get('/area/aluno', requireAuth, requireRole('aluno', 'professor'), (req, res) => {
  res.send(page('Área do aluno', `<p>Olá, ${esc(req.user.name)} (${esc(req.user.role)}). Aqui você pode <em>ver notas</em>.</p><p><a href="/welcome">Voltar</a></p>`));
});

app.get('/area/professor', requireAuth, requireRole('professor'), (req, res) => {
  res.send(page('Área do professor', `<p>Olá, ${esc(req.user.name)} (${esc(req.user.role)}). Aqui você pode <em>lançar notas</em> e <em>criar turmas</em>.</p><p><a href="/welcome">Voltar</a></p>`));
});

app.get('/logout', (req, res) => {
  const { sid } = parseCookies(req);
  if (sid) sessions.delete(sid);
  res.setHeader('Set-Cookie', 'sid=; HttpOnly; Path=/; Max-Age=0');
  res.redirect('/');
});

app.listen(PORT, () => {
  console.log(`Servidor rodando em http://localhost:${PORT}`);
});
