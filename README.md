# 02-OAuth2

Mini projeto que une **autenticação** via Google OAuth 2.0 e **autorização** com RBAC (Role-Based Access Control), em JavaScript com Bun + Express.

Cenário: o usuário entra com a conta Google e o sistema atribui um papel a partir do **domínio do e-mail** retornado no `id_token`. Quem não pertence à instituição é autenticado, mas tem o acesso negado.

## Como rodar

Pré-requisito: [Bun](https://bun.sh) 1.x.

```bash
curl -fsSL https://bun.sh/install | bash   # se ainda não tiver o Bun
source ~/.bashrc

bun install
bun start        # equivale a: bun --env-file=process.env src/index.js
```

Abra http://localhost:3000 e clique em "Login com Google".

## Estrutura necessária

```
02-OAuth2/
├── public/
│   └── index.html      # página inicial com o botão de login
├── src/
│   └── index.js        # servidor Express: OAuth2 + RBAC
├── process.env         # credenciais do Google (não versionado)
├── package.json        # script "start"
└── bun.lock
```

### `process.env`

Crie o arquivo na raiz com o ID e a chave secreta do cliente OAuth gerados no Google Cloud Console (APIs e serviços > Credenciais > ID do cliente OAuth > Aplicativo da Web):

```env
GOOGLE_CLIENT_ID=seu_client_id
GOOGLE_CLIENT_SECRET=seu_client_secret
GOOGLE_REDIRECT_URI=http://localhost:3000/callback
PORT=3000
```

No Google Cloud, o cliente OAuth precisa ter:

- Origem JavaScript autorizada: `http://localhost:3000`
- URI de redirecionamento autorizado: `http://localhost:3000/callback`

Se a tela de consentimento estiver em modo "Teste", apenas contas listadas em "Usuários de teste" conseguem logar.

## Fluxo

1. `/login` redireciona para o Google com os escopos `openid`, `email` e `profile`.
2. `/callback` troca o `code` por tokens e valida o `id_token` (`verifyIdToken`). Autenticação concluída.
3. O RBAC lê `email` e `email_verified` do payload e atribui o papel pelo domínio.
4. Usuário autorizado recebe um cookie de sessão e vai para `/welcome`, que exibe os dados recebidos do Google (foto, nome, e-mail, `sub`, `hd`, payload completo) e o resultado do controle de acesso.

## Papéis

| Domínio do e-mail | Papel | Resultado |
| --- | --- | --- |
| `@ufjf.br` | PROFESSOR | acesso permitido |
| `@estudante.ufjf.br` | ALUNO | acesso permitido |
| qualquer outro | — | **403**: e-mail não pertence à instituição |

### Matriz de permissões

| Permissão / rota | ALUNO | PROFESSOR |
| --- | :-: | :-: |
| `ver notas` — `/area/aluno` | x | x |
| `lançar notas` — `/area/professor` |  | x |
| `criar turma` — `/area/professor` |  | x |

A sessão fica **em memória**: reiniciar o servidor desloga todos os usuários. `/logout` encerra a sessão.
