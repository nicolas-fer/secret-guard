import { test, expect, mock } from 'claude-code/testing'

// Token falso no formato do GitHub, montado em tempo de execução
const FAKE = 'ghp_' + 'A1b2'.repeat(9)

test('oculta segredo no prompt e avisa o modelo', async ($, on) => {
  let seen: { text: string; context?: readonly string[] } | undefined
  on('prompt.submit', ($, e) => {
    seen = { text: e.text, context: e.context }
    return { text: e.text, context: e.context }
  })
  await $.prompt.submit({ text: `minha chave é ${FAKE}`, asUser: true })
  expect(seen?.text).not.toContain(FAKE)
  expect(seen?.text).toContain('[REDACTED:GitHub token]')
  expect(seen?.context?.join('\n')).toContain('secret-guard')
})

test('oculta segredo em linhas que entram na conversa', async ($, on) => {
  const session = mock.session(on)
  await $.session.append({ message: { type: 'user', content: [{ type: 'text', text: `token=${FAKE}` }] } })
  const rows = JSON.stringify(session.appended())
  expect(rows).not.toContain(FAKE)
  expect(rows).toContain('[REDACTED')
})

test('prompt sem segredo passa intacto', async ($, on) => {
  let seen = ''
  on('prompt.submit', ($, e) => { seen = e.text; return { text: e.text } })
  await $.prompt.submit({ text: 'liste os arquivos do projeto', asUser: true })
  expect(seen).toBe('liste os arquivos do projeto')
})

test('falha no hook de prompt bloqueia em vez de deixar passar', async ($, on) => {
  let reached = false
  on('prompt.submit', ($, e) => { reached = true; return { text: e.text } })
  const r = await $.prompt.submit({ text: undefined as unknown as string, asUser: true }).catch(err => ({ rejected: String(err) }))
  expect(reached).toBe(false)
  expect(r).toEqual({ drop: expect.stringContaining("secret-guard: erro ao verificar") })
})
