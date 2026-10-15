#!/usr/bin/env python3
"""Build docs/evidence.html from a measured run in evidence/<date>/.

Reads what the runs actually wrote (corpus.json, mutate.txt, runsc.txt, host.txt)
plus the corpus TOML headers, and renders one static page. Nothing is typed in by
hand except the one-line description of each scenario.

    python3 scripts/site-evidence.py evidence/2026-10-14
"""
import html
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# What each scenario proves, in one line. Keyed by corpus file name.
WHAT = {
    "fs-write-outside": "Writing outside the writable roots fails.",
    "fs-symlink-escape": "A symlink inside the workspace that points outside can't be written through.",
    "fs-hardlink-escape": "Hardlinking a read-denied secret into a readable place doesn't expose it.",
    "write-deny-inside-writable": "A denied subtree inside a writable root stays unwritable.",
    "secret-read-deny": "A read-denied secret directory can't be read.",
    "secret-inside-writable": "A read-denied secret inside a writable workspace stays unreadable.",
    "read-allow-inside-deny": "Deny a directory, re-open one branch: only that branch is readable.",
    "read-allow-deny-nested": "A deeper deny inside a re-opened branch wins (most specific rule).",
    "read-deny-wins-exact-tie": "The same path both denied and allowed resolves to deny.",
    "read-deny-symlink-bypass": "A symlink planted to a denied secret doesn't make it readable.",
    "read-deny-proc-magic-symlink": "/proc/self/root and friends can't re-express a denied path.",
    "env-secret-scrub": "Secrets in the launcher's environment don't reach the agent.",
    "broker-credential": "The agent uses a credential through the broker without ever holding it.",
    "net-unauthorized-port": "Only the granted local port is reachable; others are refused.",
    "egress-udp-raw-denied": "UDP and raw sockets (DNS, QUIC, ICMP) can't leave a restricted network.",
    "isolate-net-egress": "The network namespace alone stops a datagram to a public resolver.",
    "ipc-unix-socket": "A unix socket outside the workspace isn't reachable when AF_UNIX is denied.",
    "trust-handoff-nested-git": "A git hook in a nested repo can't be planted.",
    "trust-handoff-submodule-hook": "A submodule's hooks under .git/modules/ can't be planted.",
    "trust-handoff-ancestor-rename": "Renaming an ancestor directory doesn't free the hooks below it.",
    "trust-handoff-rename-over-hook": "Renaming a file onto a protected hook is denied too.",
    "trust-handoff-claude-commands": "Nested .claude/commands can't be written at any depth.",
    "trust-handoff-root-inside-hooks": "A writable root placed inside .git/hooks can't plant a hook; one under .git/objects stays writable.",
    "trust-handoff-git-dir-replace": "Moving the whole .git aside to swap in a planted one is blocked (macOS); a plain sub-directory rename still works.",
    "trust-handoff-shell-rc": "With --protect-home-handoff, shell rc files (.bashrc, .zshrc, …) can't be planted.",
    "trust-handoff-tool-rc": "With --protect-home-handoff, .gitconfig / .ripgreprc run-command hooks can't be planted.",
    "trust-handoff-mcp-json": "A nested .mcp.json can't be rewritten to launch a new server.",
    "handoff-materialize-absent": "With --materialize, an absent handoff config can't be created.",
    "lifecycle-timeout": "A runaway command is killed at the timeout (exit 124).",
    "lifecycle-daemon-escape": "A double-forked, setsid'd daemon dies with the run (cgroup.kill).",
    "resource-cpu": "A CPU spin loop is stopped by the CPU budget, even as root.",
    "resource-memory": "Allocating past the memory cap fails without hurting the host.",
    "resource-procs": "A fork bomb hits the process cap, even as root (cgroup pids.max).",
    "root-mknod-device-denied": "A root agent can't create a device node to read the raw disk.",
    "isolate-pid-namespace": "With --isolate-pids the agent sees only its own processes.",
    "seccomp-hardening": "--seccomp-strict blocks dangerous syscalls such as unshare.",
}

CATEGORY = {
    "filesystem": "Files",
    "secrets": "Secrets",
    "credentials": "Secrets",
    "network": "Network",
    "ipc": "Network",
    "trust-handoff": "Trust-handoff",
    "lifecycle": "Processes and resources",
    "resources": "Processes and resources",
    "isolation": "Isolation",
}
ORDER = ["Trust-handoff", "Secrets", "Network", "Files", "Isolation", "Processes and resources"]


def contract_desc(text):
    """One-line description: the first plain # comment that is not metadata."""
    for line in text.splitlines():
        t = line.strip()
        if not t.startswith("#"):
            if t and not t.startswith("[") and "=" in t:
                continue
            if t:
                break
            continue
        c = t.lstrip("# ").strip()
        low = c.lower()
        if low.startswith(("derived from", "status", "held", "known gap")):
            continue
        if c:
            return c
    return ""


def contract_source(text):
    m = re.search(r'^source\s*=\s*"([^"]*)"', text, re.M)
    return m.group(1) if m else ""


def toml_header(path):
    head = {}
    for line in path.read_text().splitlines():
        m = re.match(r'^(id|category|severity)\s*=\s*"([^"]*)"', line)
        if m:
            head[m.group(1)] = m.group(2)
        m = re.match(r"^os\s*=\s*\[(.*)\]", line)
        if m:
            head["os"] = re.findall(r'"([^"]+)"', m.group(1))
    return head


def corpus_results(path):
    if not path.exists():
        return {}, None
    data = json.loads(path.read_text())
    return {s["id"]: s for s in data["scenarios"]}, data


def runsc_results(path):
    out = {}
    if not path.exists():
        return out
    for line in path.read_text().splitlines():
        m = re.match(r"^(\S+)\s+(blocked|RAN!|LEAK!)\s+(ok|BROKE)\s+(PASS|VIOLATION|control-broke)$", line)
        if m:
            out[m.group(1)] = m.group(4)
    return out


def mutation_rows(path):
    rows = []
    if not path.exists():
        return rows
    for line in path.read_text().splitlines():
        m = re.match(r"^(\S+)\s+(\d+/\d+)\s+(.*?)\s*\[(ok|BLIND)\]\s*$", line)
        if m:
            rows.append((m.group(1), m.group(2), m.group(3), m.group(4)))
    return rows


def cell(result, applies):
    if not applies:
        return '<td class="na" title="not applicable on this backend">n/a</td>'
    if result is None:
        return '<td class="na">not run</td>'
    return f'<td class="{"pass" if result == "PASS" else "fail"}">{result.lower() if result != "PASS" else "pass"}</td>'


def main():
    run = (ROOT / sys.argv[1]).resolve() if len(sys.argv) > 1 else sorted((ROOT / "evidence").iterdir())[-1]
    date = run.name
    linux, linux_meta = corpus_results(run / "linux/corpus.json")
    macos, macos_meta = corpus_results(run / "macos/corpus.json")
    runsc = runsc_results(run / "linux/runsc.txt")

    groups = {}
    for toml in sorted((ROOT / "security-bench/corpus").glob("*.toml")):
        name = toml.stem
        h = toml_header(toml)
        sid = h["id"]
        lin = linux.get(sid)
        mac = macos.get(sid)
        text = toml.read_text()
        desc = WHAT.get(name) or contract_desc(text)
        src = contract_source(text)
        src_html = f'<span class="src">{html.escape(src)}</span>' if src else ""
        row = (
            f'<tr><th scope="row"><a href="https://github.com/carlostapiacl/tartaros/blob/master/security-bench/corpus/{name}.toml">{html.escape(name)}</a>'
            f'<span class="what">{html.escape(desc)}</span>{src_html}</th>'
            f'<td class="sev sev-{h["severity"]}">{h["severity"]}</td>'
            + cell("PASS" if lin and lin["passed"] else ("FAIL" if lin else None), "linux" in h["os"])
            + cell("PASS" if mac and mac["passed"] else ("FAIL" if mac else None), "macos" in h["os"])
            + cell(runsc.get(name), name in runsc)
            + "</tr>"
        )
        groups.setdefault(CATEGORY.get(h["category"], h["category"]), []).append(row)

    body = []
    for g in ORDER + [k for k in groups if k not in ORDER]:
        if g not in groups:
            continue
        body.append(f'<tbody><tr class="group"><th colspan="5" scope="rowgroup">{html.escape(g)}</th></tr>{"".join(groups[g])}</tbody>')

    def host(rel):
        p = run / rel
        return html.escape(p.read_text().strip()) if p.exists() else "(missing)"

    def mut_table(rel):
        rows = mutation_rows(run / rel)
        if not rows:
            return "<p>(not run)</p>"
        tr = "".join(
            f'<tr><th scope="row"><code>{html.escape(m)}</code></th><td>{f}</td><td class="{"pass" if s == "ok" else "fail"}">{"caught" if s == "ok" else "blind spot"}</td><td class="list">{html.escape(sc)}</td></tr>'
            for m, f, sc, s in rows
        )
        return f'<table class="mut"><thead><tr><th scope="col">protection removed</th><th scope="col">flipped</th><th scope="col">result</th><th scope="col">scenarios that caught it</th></tr></thead><tbody>{tr}</tbody></table>'

    lt, lp = (linux_meta["total"], linux_meta["passed"]) if linux_meta else (0, 0)
    mt, mp = (macos_meta["total"], macos_meta["passed"]) if macos_meta else (0, 0)
    rp = sum(1 for v in runsc.values() if v == "PASS")
    raw = f"https://github.com/carlostapiacl/tartaros/tree/master/evidence/{date}"

    page = (ROOT / "docs/_evidence.template.html").read_text()
    for k, v in {
        "{{DATE}}": date,
        "{{LINUX}}": f"{lp} / {lt}",
        "{{MACOS}}": f"{mp} / {mt}",
        "{{RUNSC}}": f"{rp} / {len(runsc)}",
        "{{ROWS}}": "".join(body),
        "{{MUT_LINUX}}": mut_table("linux/mutate.txt"),
        "{{MUT_MACOS}}": mut_table("macos/mutate.txt"),
        "{{HOST_LINUX}}": host("linux/host.txt"),
        "{{HOST_MACOS}}": host("macos/host.txt"),
        "{{RAW}}": raw,
    }.items():
        page = page.replace(k, v)
    (ROOT / "docs/evidence.html").write_text(page)
    print(f"docs/evidence.html from {run.relative_to(ROOT)}: linux {lp}/{lt}, macos {mp}/{mt}, runsc {rp}/{len(runsc)}")


if __name__ == "__main__":
    main()
