# secret-guard

Mod para o Claude Code que oculta chaves, tokens e senhas antes de chegarem ao modelo.

- **Prompt**: segredos colados no prompt são trocados por `[REDACTED...]` antes do envio.
- **Ferramentas**: saídas de ferramentas, MCP e subagentes passam pelo mesmo filtro. Arquivos como `.env`, `.npmrc` e `.aws/credentials` têm todos os valores ocultados.
- **Detecção**: formatos conhecidos (Anthropic, OpenAI, AWS, GitHub, Stripe, Slack, JWT, chaves privadas e outros), atribuições como `password = "..."` e tokens soltos de alta entropia.
- **Exceção**: comece o prompt com `!allow-secret ` para enviá-lo sem filtro.

## Instalação

No terminal do Claude Code:

```
/plugin install secret-guard --marketplace nicolas-fer/secret-guard
```

Responda `y` para adicionar o marketplace e escolha o escopo **user**. O mod passa a valer em todas as sessões, inclusive as do app desktop.

## Atualização

```
claude plugin update secret-guard
```

Depois, `/reload-plugins` numa sessão aberta.

## Exceções

Valores que nunca devem ser tratados como segredo vão no `ALLOWLIST` em `hooks/register.ts`.
