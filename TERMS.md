# Engra CLI Terms of Use

> **DRAFT for owner and legal review. Not yet in force. Not legal advice.**
> Placeholders in [brackets] must be completed by Arenberg AG before release.

Version: draft 2026-10-19

These Terms of Use ("Terms") govern your use of the Engra command-line
interface, including its executable files, documentation and updates (the
"Software"). The Software is provided by Arenberg AG, [registered address],
Switzerland ("Arenberg", "we", "us").

By installing or using the Software you agree to these Terms. If you use the
Software on behalf of an organisation, you confirm you may bind it. If you
have a separate written agreement with Arenberg for Engra (for example an
Enterprise agreement), that agreement takes precedence where it conflicts
with these Terms.

## 1. License grant

Subject to these Terms, Arenberg grants you a limited, non-exclusive,
non-transferable, non-sublicensable, revocable license to install and run the
Software on devices you own or control, solely to access Engra services under
an Engra account you are authorised to use.

## 2. Restrictions

You may not, and may not allow anyone else to:

- copy the Software, except for installation and reasonable backup copies;
- modify, translate or create derivative works of the Software;
- reverse engineer, decompile, disassemble or otherwise try to derive its
  source code, except to the extent applicable law expressly permits this
  despite this restriction;
- distribute, sell, rent, lease, lend, sublicense or otherwise make the
  Software available to third parties, including by hosting it as a service;
- remove or alter any proprietary notices, labels or license files;
- circumvent its authentication, usage limits, security or licensing
  controls; or
- use it to build a competing product or service.

Third-party components included with the Software are licensed under their
own terms (section 9). Nothing in these Terms restricts rights you have under
those licenses.

## 3. Acceptable use

You must not use the Software:

- to break any law, or infringe or misappropriate anyone's rights;
- to access systems, repositories, accounts or data you are not authorised
  to access;
- to develop, distribute or run malware, or to attack, probe or overload any
  system, including Engra services;
- to process data you have no right to process, or to send Engra special
  categories of personal data unless your agreement with Arenberg allows it;
- in violation of the Engra service terms and acceptable use policy
  [link], which also apply to your use of Engra services through the
  Software.

You are responsible for the commands, code changes and other actions you
approve the Software to carry out on your devices and in your repositories.

## 4. What the Software does on your device and what it sends to Engra

This is a summary. The Engra Privacy Notice [link] and your agreement with
Arenberg govern how Engra services process data.

**On your device**

- Stores non-secret settings and link state in `~/.config/engra/` (on
  Windows `%USERPROFILE%\.config\engra\`), and remediation records from
  `engra doctor --fix` in `~/.engra/`.
- Stores sign-in tokens and a device key in your operating system's
  credential store (macOS Keychain, Windows Credential Manager or the Linux
  Secret Service) under the service name `engra-cli`. It does not write
  secrets to plain files.
- When you run `engra code`, reads files in the working directory you start
  it in, edits files there when you ask it to, and runs commands there.
  Destructive commands, git writes, and commands that run interpreters or
  other opaque programs require your approval unless you turn approvals off
  (for example with `--no-confirm`).
- If you enable optional features, may run other command-line tools you have
  installed (`engra tools`), serve local search to your own tools
  (`engra mcp`), or copy repository contents to and from Engra cloud
  workspaces (`engra cloud-worktrees`).

**Sent to Engra services**

- Your account and sign-in requests, and the tenant and repository you
  select.
- Your questions and instructions, and the conversation with the coding
  agent, including the file contents, command output and diffs the agent
  reads or produces while working on your request.
- Diagnostic requests made by `engra doctor` (reachability and account
  status checks).
- Technical metadata needed to provide the service, such as the CLI version,
  operating system and request identifiers.

The Software does not upload your repository wholesale. It sends what the
agent reads or produces for your request, and what you explicitly sync with
optional features.

## 5. Updates and availability

Arenberg may release updates. Some updates may be required to keep using
Engra services. Engra services may change, and access may be suspended in
line with the Engra service terms.

## 6. Ownership and feedback

The Software is licensed, not sold. Arenberg and its licensors keep all
rights, title and interest in it. If you send us feedback, we may use it
without obligation to you.

## 7. No warranty

To the maximum extent permitted by applicable law, the Software is provided
"as is" and "as available", without warranties of any kind, whether express,
implied or statutory, including warranties of merchantability, fitness for a
particular purpose, title and non-infringement. Arenberg does not warrant
that the Software or any code or commands it produces will be error-free,
secure or suitable for your purpose. Review its output before relying on it.

## 8. Limitation of liability

To the maximum extent permitted by applicable law, Arenberg is not liable for
indirect, incidental, special, consequential or punitive damages, or for lost
profits, revenue, data or goodwill, arising out of or related to the
Software. Arenberg's total liability arising out of or related to the
Software is limited to [CHF 100 / the fees you paid for Engra in the twelve
months before the claim, whichever is greater].

Nothing in these Terms limits liability that cannot be limited under
applicable law, including liability for unlawful intent or gross negligence
under Article 100 of the Swiss Code of Obligations.

## 9. Third-party components

The Software includes third-party open-source components, listed with their
licenses in `THIRD_PARTY_NOTICES.txt` (shipped with every release and shown
by `engra legal --third-party`). Those components are licensed to you under
their own licenses.

## 10. Termination

These Terms apply until terminated. They end automatically if you breach
them, or when your right to use Engra services ends. Arenberg may also
terminate them by notice. On termination you must stop using the Software
and delete all copies. Sections 2, 4, 6, 7, 8, 10 and 11 survive.

## 11. Governing law and jurisdiction

These Terms are governed by the substantive laws of Switzerland, excluding
its conflict-of-law rules and the United Nations Convention on Contracts for
the International Sale of Goods. The exclusive place of jurisdiction is
[seat of Arenberg AG], Switzerland, subject to any mandatory jurisdiction
that applies to consumers.

## 12. Contact

Arenberg AG, [registered address], Switzerland. [contact email]
