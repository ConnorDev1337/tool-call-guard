# Closing policy gaps: design note

Written before measuring any of the changes below. It states what changes, why the threat model
asks for it, and the rule used to adopt or reject each candidate, so that the results cannot
quietly steer the design. The numbers before and after are reported in the README and in the
pinned regression tests, whichever way they move.

## Starting point

On `main` (aa48e29) the bundled benchmark has two documented misses (a calendar invitation that is
not a source; a payload hidden in a file's content), and the AgentDojo run (see
`benchmarks/agentdojo/README.md`) shows five classes of gaps:

1. `extends` resolved one level only (fixed separately: a policy extending `strict` lost every
   source, the self-protection rules and the default actions).
2. `balanced` lets a tainted session browse to an attacker's link when no private data is in
   context.
3. Benign tasks break when a critical value legitimately comes from untrusted data the user asked
   the agent to use (the IBAN on a bill, an address on a web page the user named).
4. Granting access (sharing, invitations, membership) and changing credentials have no preset
   category, so they either match no sink at all (the presets) or fall back to `default`, whose
   `trifecta = block` is stricter than `send` for what is the same disclosure.
5. The coarse `tainted` rule sends every side effect after reading third-party listings to a
   human.

## Principles

- **Trusted input is the user's prompt, and only that.** No change lets a tool result endorse a
  value, raise its own trust or mark another source as trusted.
- **Classify by what a tool does, not by which benchmark uses it.** New patterns follow common MCP
  verbs and nouns (`list_events`, `get_ticket`, `share_*`, `update_password`) and generic file
  semantics. No AgentDojo tool name enters a preset; the AgentDojo toolset may only change to map
  a tool onto a category introduced here, justified by the tool's docstring.
- **Over-classifying a source costs usefulness; under-classifying costs safety.** When in doubt a
  third-party reader is a source, and the cost shows up as benign tasks that need a human.
- **Downgrades go to a human, never to autonomy.** Any new endorsement can lower `block` to
  `confirm` at most, except where the value demonstrably came from the user.

## Changes

| Gap | Change | Why (threat model) |
|---|---|---|
| Unclassified third-party content | New preset sources, by verb/noun: calendar events and invitations, tickets and their comments, issues and pull/merge requests on any forge, comments and reviews, chat messages and posts on any chat server, shared documents and pages | All are written by parties other than the user (anyone can send an invitation, open a ticket or comment), i.e. the adversary of the threat model. Calendars and chats are also private |
| Payload in a file's content | New sink category `autoexec` for writes to paths the system runs or trusts automatically (shell start-up files, git hooks, CI workflows, build and package scripts, test configuration such as `conftest.py`, editor tasks, cron and autostart entries, `authorized_keys`), with **every** argument critical, ahead of the generic `write` sink | Writing untrusted content there is deferred code execution or persistence, so it gets the `shell` posture. Ordinary files keep `write` (path-only) |
| No category for access or account changes | New sink categories `access` (share, invite, add member/collaborator, grant or set permissions) and `account` (passwords, credentials, API keys and tokens, SSH/GPG keys, MFA, recovery and profile details), both before `publish` | Granting a party access discloses data like `send` does, so `access` mirrors `send`. An account change hands over control; an attacker-chosen value must block, like `payment` |
| Data-driven values the user pointed at | **Directed sources.** A source call is *directed* when one of its arguments is, in full, a specific resource name the user typed (a URL, domain, e-mail address, file name or path). An `untrusted_flow` whose evidence comes only from directed observations is reported as `directed_flow`, with its own action (default: same as `untrusted_flow`). `balanced` sets it to `confirm` where `untrusted_flow` blocks; `strict` keeps `block` | "Pay the bill in `bill.txt`" makes the bill's IBAN the user's choice, but the guard cannot tell it from an IBAN injected into the same bill, so a human decides. Injections in sources the user did not name keep blocking |
| User asked to send X | `private_flow` evidence is endorsed (not reported) when the matched private text also appears in the user's prompt; secret-shaped tokens are never endorsed | The value came from the user, not from a private source. Endorsing the *recipient* instead was rejected: the user-named recipient can be the author of the injected content (a compromised colleague), so `trifecta` stays |
| Links in untrusted content | **Candidate, measured before adoption**: `web.untrusted_flow = confirm` in `balanced` | See the adoption rule below; the expected cost is every research task that follows a link from search results |
| Coarse taint on side effects | **No change.** `tainted` is the backstop for paraphrased steering that flow evidence cannot see; it stays | Lowering it needs a signal the guard does not have |

## Adoption rule

A candidate is adopted in a preset only if, on the new held-out scenarios
(`benchmarks/heldout/`, written before the preset and engine changes):

- no attack becomes *missed* that was prevented or flagged before; and
- it improves the class it targets.

A change that moves an attack from *prevented* to *flagged* is acceptable only when the guard
cannot, by construction, tell the attack from the benign task (a directed source carrying both the
legitimate and the injected value), and it is reported. For the web candidate the bar is that
following links from search results and documentation stays autonomous in `balanced`; if it does
not, `balanced` keeps `untrusted_flow = allow` and the misses stay documented (`strict` already
confirms).

The bundled and AgentDojo results are then reported per policy without further tuning: a change
that helps one benchmark and hurts another is reported, not adjusted.
