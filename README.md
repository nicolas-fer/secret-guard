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

## Ligar e desligar

| Comando | O que faz |
| --- | --- |
| `/secret-guard` | Mostra o estado e as opções |
| `/secret-guard off [30m\|2h\|1h30m]` | Desliga nesta sessão; sem tempo, até religar ou fechar a sessão |
| `/secret-guard on` | Religa nesta sessão |
| `/secret-guard pasta off [path]` | Desliga sempre nesta pasta (ou na indicada) e nas subpastas |
| `/secret-guard pasta on [path]` | Volta a proteger a pasta |
| `/secret-guard pastas` | Lista as pastas desligadas |

Só o usuário pode ligar ou desligar: o comando recusa chamadas do modelo e de outros plugins. Desligado, a barra de status mostra `SECRET-GUARD OFF`. Qualquer erro ao checar o estado deixa a proteção ligada, e uma pausa termina se a sessão reiniciar.

## Exceções

Valores que nunca devem ser tratados como segredo vão no `ALLOWLIST` em `hooks/register.ts`.

## Limitações

A detecção é por padrões e heurísticas: um segredo num formato desconhecido (senha curta, token de sistema interno, chave sem nome de variável) pode passar. Trate o mod como rede de segurança, não como motivo para colar segredos. Se um vazar, rotacione.

## Testes

```
claude plugin test .
```
