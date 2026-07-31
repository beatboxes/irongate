#!/usr/bin/env python3
"""
Keep the extracted source tree and irongate-install.sh in sync.

irongate-install.sh is a standalone installer that carries the whole codebase inside
heredocs. The same code is also committed as ordinary files under src/, web/, config/
and templates/ so it can be reviewed, diffed and opened in an editor.

That means two copies of every file, which can drift. This tool makes drift detectable:

    python3 tools/heredoc_sync.py --check      # exit 1 if any file differs
    python3 tools/heredoc_sync.py --extract    # rewrite the tree from the installer
    python3 tools/heredoc_sync.py --list       # show the heredoc inventory

Quoted heredocs (<< 'MARKER') hold literal content and are extracted verbatim.
Unquoted heredocs (<< MARKER) are shell templates whose $VARIABLES the installer
expands at install time; those land in templates/ with a .template suffix and are
NOT directly usable.
"""
import argparse
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INSTALLER = os.path.join(ROOT, 'irongate-install.sh')

# Some heredocs are opened inside if-blocks and are therefore indented; the closing
# marker is still at column 0 because plain << (not <<-) requires it.
HEREDOC_RE = re.compile(r"^\s*cat\s+>>?\s+(\S+)\s+<<\s+(')?([A-Za-z_][A-Za-z0-9_]*)\2?\s*$")


def repo_path_for(target, quoted):
    """Map an installed path to its location in the repository."""
    base = os.path.basename(target)
    if not quoted:
        # Shell-expanded template: keep the variables, mark it clearly.
        # Specific names first - several basenames collide (override.conf, dnsmasq).
        special = {
            '/etc/nginx/sites-available/irongate': 'nginx-irongate.conf',
            '/etc/systemd/system/dnsmasq.service.d/override.conf': 'dnsmasq-override.conf',
            '/etc/sudoers.d/dnsmasq-web': 'sudoers-dnsmasq-web',
            '/etc/logrotate.d/dnsmasq': 'logrotate-dnsmasq',
        }
        name = special.get(target, base)
        return os.path.join('templates', name + '.template')

    if target.startswith('/opt/irongate/'):
        return os.path.join('src', base)
    if target.startswith('/var/www/irongate/'):
        return os.path.join('web', base)
    if target.startswith('/etc/systemd/system/nginx.service.d/'):
        return os.path.join('config', 'nginx-service-dropin.conf')
    return os.path.join('config', base)


def parse(installer_path):
    """Return [{target, marker, quoted, repo_path, content, start_line}] for every heredoc."""
    with open(installer_path, encoding='utf-8', newline='') as fh:
        lines = fh.read().split('\n')

    blocks, i = [], 0
    while i < len(lines):
        m = HEREDOC_RE.match(lines[i])
        if not m:
            i += 1
            continue
        target, quote, marker = m.group(1), m.group(2), m.group(3)
        start = i
        i += 1
        body = []
        while i < len(lines) and lines[i] != marker:
            body.append(lines[i])
            i += 1
        if i >= len(lines):
            raise SystemExit("unterminated heredoc %s opened at line %d" % (marker, start + 1))
        quoted = quote == "'"
        blocks.append({
            'target': target,
            'marker': marker,
            'quoted': quoted,
            'repo_path': repo_path_for(target, quoted),
            'content': '\n'.join(body) + '\n',
            'start_line': start + 1,
        })
        i += 1
    return blocks


def cmd_list(blocks):
    print("%-4s %-16s %-9s %-46s %s" % ('LINE', 'MARKER', 'KIND', 'INSTALLED PATH', 'REPO PATH'))
    for b in blocks:
        print("%-4d %-16s %-9s %-46s %s" % (
            b['start_line'], b['marker'],
            'literal' if b['quoted'] else 'template',
            b['target'], b['repo_path']))
    print("\n%d heredocs (%d literal, %d template)" % (
        len(blocks), sum(b['quoted'] for b in blocks), sum(not b['quoted'] for b in blocks)))


def cmd_extract(blocks):
    for b in blocks:
        dest = os.path.join(ROOT, b['repo_path'])
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        with open(dest, 'w', encoding='utf-8', newline='') as fh:
            fh.write(b['content'])
        print("  wrote %-44s (%d bytes)" % (b['repo_path'], len(b['content'])))
    print("\nextracted %d files" % len(blocks))


def cmd_check(blocks):
    drift, missing = [], []
    for b in blocks:
        dest = os.path.join(ROOT, b['repo_path'])
        if not os.path.exists(dest):
            missing.append(b['repo_path'])
            continue
        with open(dest, encoding='utf-8', newline='') as fh:
            on_disk = fh.read()
        if on_disk != b['content']:
            drift.append((b['repo_path'], len(b['content']), len(on_disk)))

    for p in missing:
        print("  MISSING  %s" % p)
    for p, want, got in drift:
        print("  DRIFT    %s (installer %d bytes, repo %d bytes)" % (p, want, got))

    if missing or drift:
        print("\nFAIL: %d missing, %d drifted. Run --extract, or update the installer heredoc."
              % (len(missing), len(drift)))
        return 1
    print("  all %d extracted files are byte-identical to their heredoc" % len(blocks))
    print("\nOK")
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument('--check', action='store_true', help='fail if the tree and installer disagree')
    g.add_argument('--extract', action='store_true', help='rewrite the tree from the installer')
    g.add_argument('--list', action='store_true', help='print the heredoc inventory')
    args = ap.parse_args()

    if not os.path.exists(INSTALLER):
        raise SystemExit("installer not found: %s" % INSTALLER)
    blocks = parse(INSTALLER)

    if args.list:
        cmd_list(blocks)
    elif args.extract:
        cmd_extract(blocks)
    else:
        sys.exit(cmd_check(blocks))


if __name__ == '__main__':
    main()
