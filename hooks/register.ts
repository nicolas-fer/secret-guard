import type { Register } from 'claude-code'

// Prefixo que libera um prompt de propósito: "!allow-secret <texto>"
const BYPASS = '!allow-secret'

// --- detect:start (funções puras, testáveis fora do Claude Code)

// ===== Lista de exceções: valores que nunca são tratados como segredo =====
// Adicione aqui valores exatos que você quer liberar.
const ALLOWLIST = new Set<string>([
  'AKIAIOSFODNN7EXAMPLE', // chave de exemplo oficial da AWS
  'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
])
const PLACEHOLDER =
  /example|placeholder|changeme|change_me|your[_-]|<[^>]*>|xxx|\*\*\*|\.\.\.|dummy|redacted|^\$\{.*\}$|^\$[A-Za-z_]\w*$|process\.env|os\.environ|getenv|^(true|false|null|none|undefined|nil)$|^[\d.]+$/i

function isAllowed(value: string): boolean {
  const v = value.replace(/^["'`]|["'`]$/g, '')
  return v === '' || ALLOWLIST.has(v) || PLACEHOLDER.test(v)
}

// ===== Entropia: o quão "aleatório" um valor parece =====
function entropy(s: string): number {
  const freq = new Map<string, number>()
  for (const c of s) freq.set(c, (freq.get(c) ?? 0) + 1)
  let h = 0
  for (const n of freq.values()) {
    const p = n / s.length
    h -= p * Math.log2(p)
  }
  return h
}

// ===== Formatos conhecidos (prefixo + tamanho) =====
const KNOWN: readonly (readonly [string, RegExp])[] = [
  ['Anthropic API key', /sk-ant-[A-Za-z0-9_-]{20,}/g],
  ['API key sk-', /\bsk-(?!ant-)(?:proj-|or-v1-)?[A-Za-z0-9_-]{32,}/g],
  ['AWS access key', /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g],
  ['GitHub token', /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b/g],
  ['GitLab token', /\bglpat-[A-Za-z0-9_-]{20,}\b/g],
  ['Slack token', /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g],
  ['Slack webhook', /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9_\/]+/g],
  ['Discord token', /\b[MNO][A-Za-z\d_-]{23,27}\.[A-Za-z\d_-]{6}\.[A-Za-z\d_-]{27,40}\b/g],
  ['Discord webhook', /https:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]+/g],
  ['Telegram bot token', /\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b/g],
  ['Google API key', /\bAIza[0-9A-Za-z_-]{35}\b/g],
  ['Stripe key', /\b(?:[sr]k|whsec)_(?:live_|test_)?[0-9A-Za-z]{24,}\b/g],
  ['Twilio API key', /\bSK[0-9a-fA-F]{32}\b/g],
  ['SendGrid key', /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g],
  ['Mailgun key', /\bkey-[0-9a-f]{32}\b/g],
  ['npm token', /\bnpm_[A-Za-z0-9]{36}\b/g],
  ['PyPI token', /\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}/g],
  ['Hugging Face token', /\bhf_[A-Za-z0-9]{34,}\b/g],
  ['DigitalOcean token', /\bdo[por]_v1_[a-f0-9]{64}\b/g],
  ['Shopify token', /\bshp(?:at|ss|ca|pa)_[a-fA-F0-9]{32}\b/g],
  ['Square token', /\bsq0(?:atp|csp)-[A-Za-z0-9_-]{22,43}\b/g],
  ['Groq key', /\bgsk_[A-Za-z0-9]{48,}\b/g],
  ['Replicate token', /\br8_[A-Za-z0-9]{37}\b/g],
  ['Linear key', /\blin_api_[A-Za-z0-9]{40}\b/g],
  ['Notion token', /\b(?:secret_|ntn_)[A-Za-z0-9]{43,}\b/g],
  ['Postman key', /\bPMAK-[a-f0-9]{24}-[a-f0-9]{34}\b/g],
  ['Atlassian token', /\bATATT3[A-Za-z0-9_=-]{150,}/g],
  ['Doppler token', /\bdp\.(?:pt|st|sa|ct|scim)\.[A-Za-z0-9]{40,}\b/g],
  ['Sentry token', /\bsntrys_[A-Za-z0-9_=-]{30,}/g],
  ['Supabase key', /\b(?:sbp_[a-f0-9]{40}|sb_secret_[A-Za-z0-9_-]{20,})\b/g],
  [
    'Private key',
    /-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----[\s\S]*?(?:-----END (?:[A-Z]+ )?PRIVATE KEY-----|$)/g,
  ],
  ['JWT', /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g],
]

// ===== Heurísticas (só o valor é trocado) =====
const PASSWORD_IN_URL = /\b([a-z][a-z0-9+.-]*:\/\/[^\s:@\/]+:)([^\s@\/]+)(@)/gi
const URL_QUERY_SECRET =
  /([?&](?:sig|signature|token|key|api_?key|access_token|secret|password|pwd|auth)=)([^&\s"'`#]{8,})/gi
const AZURE_KEY = /((?:AccountKey|SharedAccessKey|SharedAccessSignature)=)([^;\s"'`]{20,})/g

const NAME = String.raw`[A-Za-z0-9_.-]*(?:api[_-]?key|apikey|secret|token|passw(?:or)?d|passwd|pwd|pass|senha|credential|credencial|private[_-]?key|access[_-]?key|auth|chave)[A-Za-z0-9_.-]*`
const PASSWORDISH = /passw|passwd|pwd|pass|senha/i
// "nome": "valor" / nome = 'valor' (código, JSON, YAML com aspas)
const ASSIGNED_QUOTED = new RegExp(String.raw`(["'\x60]?(${NAME})["'\x60]?\s*(?::=|=>|[:=])\s*)(["'\x60])([^"'\x60\n]+)\3`, 'gi')
// NOME=valor sozinho na linha (.env, YAML, ini), com prefixo opcional do Read/Grep
const ASSIGNED_LINE = new RegExp(
  String.raw`^((?:[ \t]*\d+\t|\S+?:\d+[:-])?[ \t]*(?:export[ \t]+)?(${NAME})[ \t]*[:=][ \t]*)([^\s"'\x60(){}\[\],;]+)[ \t]*$`,
  'gim',
)

function looksSecret(name: string, value: string): boolean {
  if (isAllowed(value) || value.startsWith('[REDACTED')) return false
  if (PASSWORDISH.test(name)) return value.length >= 6
  return value.length >= 12 && entropy(value) >= 3
}

// Token solto de alta entropia (sem prefixo e sem nome de variável)
const STANDALONE = /(?<![A-Za-z0-9_+\/=.-])[A-Za-z0-9_+\/=-]{32,128}(?![A-Za-z0-9_+\/=.-])/g

function looksRandom(t: string, before: string): boolean {
  if (/sha\d+-$/.test(before) || /^sha\d+-/.test(t) || isAllowed(t)) return false
  if (!/[A-Z]/.test(t) || !/[a-z]/.test(t)) return false
  if ((t.match(/\d/g) ?? []).length < 3) return false
  if ((t.match(/\//g) ?? []).length > 2) return false // caminhos de arquivo
  // Nomes compostos de palavras (branches, slugs): carreiraTech/fixes/CS_BS123-ajuste-tela
  const segments = t.split(/[-_\/=]+/).filter(Boolean)
  const words = segments.filter(s => /^[A-Za-z]{3,}$/.test(s) || /^[A-Z]{2}\d*$/.test(s))
  if (segments.length >= 3 && words.length * 2 >= segments.length) return false
  return entropy(t) >= 4.3
}

// ===== Arquivos de segredo (.env etc.): todo valor é tratado como segredo =====
export const SECRET_FILE =
  /(?:^|[\s'"`\/\\=])(?:\.env(?:\.(?!example\b|sample\b|template\b|dist\b|defaults\b)[\w.-]+)?|\.npmrc|\.pypirc|\.netrc|\.git-credentials|\.aws[\/\\]+credentials)(?=$|[\s'"`;|&)\\])/
const SAFE_ENV_VALUE =
  /^(?:development|production|staging|local|test|debug|info|warn|warning|error|localhost|[\d.:]+|https?:\/\/[^\s@?]+)$/i
const ENV_LINE = /^((?:[ \t]*\d+\t|\S+?:\d+[:-])?[ \t]*(?:export[ \t]+)?[^\s=#]+[ \t]*=[ \t]*)(.*?)[ \t]*$/gm
// Linhas de .env vindas do Grep/rg: ".env:3:CHAVE=valor"
const GREP_ENV_LINE =
  /^(\S*?\.env(?:\.(?!example\b|sample\b|template\b)[\w.-]+)?[:-]\d+[:-]\s*(?:export[ \t]+)?[^\s=#]+[ \t]*=[ \t]*)(.+?)[ \t]*$/gm

function redactEnvValue(value: string): string | null {
  const v = value.replace(/^["'`]|["'`]$/g, '')
  if (isAllowed(v) || SAFE_ENV_VALUE.test(v) || v.startsWith('[REDACTED')) return null
  return '[REDACTED]'
}

export type Scan = { text: string; hits: string[] }

export function redact(input: string, isSecretFile = false): Scan {
  const hits: string[] = []
  let text = input

  for (const [label, re] of KNOWN) {
    text = text.replace(re, m => {
      if (isAllowed(m)) return m
      hits.push(label)
      return `[REDACTED:${label}]`
    })
  }

  text = text.replace(PASSWORD_IN_URL, (whole: string, head: string, pw: string, at: string) => {
    if (isAllowed(pw) || pw.startsWith('[REDACTED')) return whole
    hits.push('Senha em URL')
    return `${head}[REDACTED]${at}`
  })
  text = text.replace(URL_QUERY_SECRET, (whole: string, head: string, v: string) => {
    if (isAllowed(v) || v.startsWith('[REDACTED')) return whole
    hits.push('Segredo em URL')
    return `${head}[REDACTED]`
  })
  text = text.replace(AZURE_KEY, (whole: string, head: string, v: string) => {
    if (isAllowed(v)) return whole
    hits.push('Azure key')
    return `${head}[REDACTED]`
  })

  if (isSecretFile) {
    text = text.replace(ENV_LINE, (whole: string, head: string, v: string) => {
      const r = redactEnvValue(v)
      if (r === null) return whole
      hits.push('Valor de arquivo de segredos')
      return head + r
    })
  }
  text = text.replace(GREP_ENV_LINE, (whole: string, head: string, v: string) => {
    const r = redactEnvValue(v)
    if (r === null) return whole
    hits.push('Valor de arquivo de segredos')
    return head + r
  })

  text = text.replace(
    ASSIGNED_QUOTED,
    (whole: string, head: string, name: string, q: string, v: string) => {
      if (!looksSecret(name, v)) return whole
      hits.push('Segredo atribuído')
      return `${head}${q}[REDACTED]${q}`
    },
  )
  text = text.replace(ASSIGNED_LINE, (whole: string, head: string, name: string, v: string) => {
    if (!looksSecret(name, v)) return whole
    hits.push('Segredo atribuído')
    return `${head}[REDACTED]`
  })

  text = text.replace(STANDALONE, (t: string, offset: number, all: string) => {
    if (!looksRandom(t, all.slice(Math.max(0, offset - 8), offset))) return t
    hits.push('Token de alta entropia')
    return '[REDACTED:alta entropia]'
  })

  return { text, hits }
}

// --- detect:end

// Respostas de quando um hook falha: nada passa sem verificação.
const PROMPT_FAILED =
  'secret-guard: erro ao verificar o prompt, então ele não foi enviado. Tente de novo.'
const UNVERIFIED = '[REDACTED: secret-guard não conseguiu verificar este conteúdo]'

function maskAll<B extends Block>(content: readonly B[]): B[] {
  return content.map(b => {
    if (b.type === 'text') return { ...b, text: UNVERIFIED }
    if (b.type === 'tool_result') return { ...b, content: UNVERIFIED }
    return b
  })
}

type Block = { type: string; [field: string]: unknown }

function redactBlock(block: Block, hits: string[], secretIds: Set<string>): Block {
  if (block.type === 'text' && typeof block.text === 'string') {
    const r = redact(block.text)
    hits.push(...r.hits)
    return r.hits.length ? { ...block, text: r.text } : block
  }
  if (block.type === 'tool_result') {
    const id = typeof block.tool_use_id === 'string' ? block.tool_use_id : ''
    const isSecretFile = secretIds.delete(id)
    const c = block.content
    if (typeof c === 'string') {
      const r = redact(c, isSecretFile)
      hits.push(...r.hits)
      return r.hits.length ? { ...block, content: r.text } : block
    }
    if (Array.isArray(c)) {
      const before = hits.length
      const content = (c as Block[]).map(b => {
        if (b.type !== 'text' || typeof b.text !== 'string') return b
        const r = redact(b.text, isSecretFile)
        hits.push(...r.hits)
        return r.hits.length ? { ...b, text: r.text } : b
      })
      return hits.length > before ? { ...block, content } : block
    }
  }
  return block
}

export const register: Register = on => {
  let allowNextPrompt = false
  // tool_use_ids de chamadas que leram um arquivo de segredos (.env etc.)
  const secretFileCalls = new Set<string>()

  // Camada 1: o prompt digitado. Troca o segredo por [REDACTED...] e envia o resto.
  on('prompt.submit', ($, e, next) => {
    if (e.text.trimStart().startsWith(BYPASS)) {
      allowNextPrompt = true
      return next({ ...e, text: e.text.trimStart().slice(BYPASS.length).trimStart() })
    }
    const { text, hits } = redact(e.text)
    if (hits.length === 0) return next(e)

    const kinds = [...new Set(hits)].join(', ')
    try {
      $.ui.toast(`secret-guard: ${hits.length} segredo(s) ocultado(s) do prompt (${kinds})`)
    } catch {}
    const note =
      `secret-guard: o usuário colou segredo(s) (${kinds}) que foram trocados por [REDACTED] ` +
      `antes de chegar a você. Não peça o valor; se o código precisar dele, sugira usar uma ` +
      `variável de ambiente ou um arquivo .env.`
    return next({ ...e, text, context: [...(e.context ?? []), note] })
  }).catch(($, e, next) => {
    if (next.called) return next(e)
    // Re-entrada: o hook não rodou e não dá para reescrever, só barrar ou deixar passar.
    if (next.error.kind === 're-entry') return redact(e.text).hits.length ? { drop: PROMPT_FAILED } : next(e)
    return { drop: PROMPT_FAILED }
  })

  // Marca as chamadas de ferramenta que tocam arquivos de segredos.
  on('tool.call', ($, e, next) => {
    if (e.tool_use_id) {
      const { tool, tool_use_id, consent, ...args } = e as Record<string, unknown>
      if (SECRET_FILE.test(JSON.stringify(args))) secretFileCalls.add(e.tool_use_id)
    }
    return next(e)
  }).catch(($, e, next) => {
    // Na dúvida, trata a saída da chamada como vinda de um arquivo de segredos.
    if (e.tool_use_id) secretFileCalls.add(e.tool_use_id)
    return next(e)
  })

  // Camada 2: tudo o que entra na conversa (resultados de ferramentas, MCP,
  // subagentes, contexto injetado). Troca só o segredo por [REDACTED...].
  on('session.append', ($, e, next) => {
    if (e.door === 'response') return next(e)
    if (e.door === 'prompt' && allowNextPrompt) {
      allowNextPrompt = false
      return next(e)
    }

    const hits: string[] = []
    const content = e.message.content.map(b => redactBlock(b, hits, secretFileCalls))
    if (hits.length === 0) return next(e)

    if (e.door === 'tool-result') {
      try {
        $.ui.toast(`secret-guard: ${hits.length} segredo(s) ocultado(s) da saída de uma ferramenta`)
      } catch {}
    }
    return next({ ...e, message: { ...e.message, content } })
  }).catch(($, e, next) => {
    if (next.called) return next(e)
    if (next.error.kind === 're-entry') {
      if (e.door === 'response') return next(e)
      const hits: string[] = []
      e.message.content.forEach(b => redactBlock(b, hits, new Set()))
      return hits.length ? { deny: 'secret-guard: conteúdo com segredo barrado' } : next(e)
    }
    // O filtro falhou: oculta o conteúdo inteiro em vez de deixá-lo passar sem verificação.
    if (e.door === 'response') return next(e)
    return next({ ...e, message: { ...e.message, content: maskAll(e.message.content) } })
  })
}
