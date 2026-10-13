"""Table-driven tests for the overseer's bash/git argv validator and the
protected-path rules used by read_file/write_file/list_directory."""
import shutil
import subprocess

import pytest


def _outside(root):
    return str(root.parent / "outside.txt")


# ── git: allowed invocations ──────────────────────────────────────────────────
GIT_ALLOWED = [
    ["git", "status"],
    ["git", "status", "-sb"],
    ["git", "log", "--oneline", "-5"],
    ["git", "log", "--format=%h %s", "--since=2 weeks ago"],
    ["git", "diff"],
    ["git", "diff", "--stat", "HEAD~1"],
    ["git", "diff", "--", "gladius-api/server.py"],
    ["git", "show", "HEAD"],
    ["git", "add", "gladius-api/server.py"],
    ["git", "commit", "-m", "Fix the thing in /etc-style paths"],
    ["git", "commit", "-am", "msg"],
    ["git", "commit", "--message=update readme"],
    ["git", "push"],
    ["git", "push", "origin", "main"],
    ["git", "pull", "origin", "main"],
    ["git", "fetch"],
    ["git", "fetch", "origin"],
    ["git", "checkout", "-b", "feature-x"],
    ["git", "branch", "-vv"],
    ["git", "stash", "list"],
    ["git", "remote"],
    ["git", "remote", "-v"],
]


@pytest.mark.parametrize("argv", GIT_ALLOWED, ids=lambda a: " ".join(a))
def test_git_allowed(app, argv):
    assert app._validate_bash_argv(argv) == argv


# ── git: rejected invocations (option names only) ────────────────────────────
GIT_REJECTED = [
    ["git"],
    ["git", "config", "--list"],
    ["git", "submodule", "update"],
    ["git", "-c", "x=y", "status"],
    ["git", "-C", "/", "status"],
    ["git", "--git-dir=x", "status"],
    ["git", "status", "-c"],
    ["git", "log", "--output=x.txt"],
    ["git", "log", "--outp=x.txt"],          # abbreviation of --output
    ["git", "diff", "--no-index", "a", "b"],
    ["git", "diff", "--ext-diff"],
    ["git", "log", "--textconv"],
    ["git", "fetch", "--upload-pack=x"],
    ["git", "pull", "--upload-pack", "x"],
    ["git", "push", "--receive-pack=x"],
    ["git", "push", "--exec=x"],
    ["git", "push", "--repo=elsewhere"],
    ["git", "fetch", "--multiple", "origin", "other"],
    ["git", "commit", "--file=msg.txt"],
    ["git", "commit", "--template=t.txt"],
    ["git", "add", "--pathspec-from-file=list.txt"],
    ["git", "status", "--work-tree=x"],
    ["git", "remote", "add", "x", "y"],
    ["git", "remote", "set-url", "origin", "y"],
    ["git", "remote", "show", "origin"],
    ["git", "push", "elsewhere", "main"],
    ["git", "push", "https://example.invalid/repo.git"],
    ["git", "pull", "elsewhere"],
    ["git", "fetch", "elsewhere"],
    ["git", "add", ".gitattributes"],
    ["git", "add", ".gitmodules"],
    ["git", "add", ".git/config"],
    ["git", "add", ".GIT/config"],
    ["git", "diff", "gladius-api/.env"],
    ["git", "show", "-F/abs/path"],          # attached short-option value with a path
]


@pytest.mark.parametrize("argv", GIT_REJECTED, ids=lambda a: " ".join(a))
def test_git_rejected(app, argv):
    with pytest.raises(app.BashRejected):
        app._validate_bash_argv(argv)


def test_git_rejects_paths_outside_root(app, root):
    with pytest.raises(app.BashRejected):
        app._validate_bash_argv(["git", "diff", "--", _outside(root)])
    with pytest.raises(app.BashRejected):
        app._validate_bash_argv(["git", "log", "--", "../../outside"])


# ── git: hardened execution ───────────────────────────────────────────────────
def test_git_exec_is_hardened(app, repo):
    argv, cwd, env = app._build_bash_exec(["git", "diff", "--stat"])
    assert argv[0] == "git"
    assert argv[1:1 + len(app.GIT_HARDENING_ARGS)] == app.GIT_HARDENING_ARGS
    rest = argv[1 + len(app.GIT_HARDENING_ARGS):]
    assert rest == ["diff", "--no-ext-diff", "--no-textconv", "--stat"]
    assert "core.hooksPath=/dev/null" in argv
    assert cwd == repo
    assert env["GIT_CONFIG_NOSYSTEM"] == "1"
    assert env["GIT_CONFIG_GLOBAL"] == "/dev/null"


def test_git_status_gets_no_diff_flags(app):
    argv, _, _ = app._build_bash_exec(["git", "status"])
    assert argv[-1] == "status"


def test_subprocess_env_has_no_secrets(app, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "x")
    monkeypatch.setenv("SLACK_BOT_TOKEN", "x")
    monkeypatch.setenv("PATH", "/usr/bin")
    _, _, env = app._build_bash_exec(["ls"])
    assert "ANTHROPIC_API_KEY" not in env and "SLACK_BOT_TOKEN" not in env
    assert env["PATH"] == "/usr/bin"


# ── ls/cat/grep/find: paths are resolved against the root (#102) ─────────────
def test_relative_paths_are_rewritten_to_root(app, root):
    argv = app._validate_bash_argv(["cat", "gladius-api/server.py"])
    assert argv == ["cat", str(root / "gladius-api" / "server.py")]


def test_grep_pattern_and_value_flags_not_rewritten(app, root):
    argv = app._validate_bash_argv(["grep", "-r", "-n", "TODO", "gladius-api"])
    assert argv == ["grep", "-r", "-n", "TODO", str(root / "gladius-api")]
    argv = app._validate_bash_argv(["grep", "-e", "TODO", "gladius-api"])
    assert argv == ["grep", "-e", "TODO", str(root / "gladius-api")]
    argv = app._validate_bash_argv(["find", "gladius-api", "-name", "*.py", "-maxdepth", "2"])
    assert argv == ["find", str(root / "gladius-api"), "-name", "*.py", "-maxdepth", "2"]


def test_grep_without_path_runs_in_root_and_skips_secrets(app, root):
    argv, cwd, _ = app._build_bash_exec(app._validate_bash_argv(["grep", "-r", "TODO"]))
    assert cwd == root
    assert "--exclude=.env" in argv and "--exclude-dir=.git" in argv
    assert argv[-2:] == ["-r", "TODO"]


def test_ls_without_path_runs_in_root(app, root):
    argv, cwd, _ = app._build_bash_exec(app._validate_bash_argv(["ls", "-la"]))
    assert argv == ["ls", "-la"] and cwd == root


BASH_REJECTED = [
    ["rm", "x"],
    ["cat", "gladius-api/.env"],
    ["cat", "gladius-api/.ENV"],
    ["cat", "repo/.git/config"],
    ["ls", "repo/.git"],
    ["cat", "../outside"],
    ["find", ".", "-delete"],
    ["find", ".", "-exec"],
    ["grep", "--include=x", "y"],
    ["find", ".", "-name"],                  # value flag without a value
]


@pytest.mark.parametrize("argv", BASH_REJECTED, ids=lambda a: " ".join(a))
def test_bash_rejected(app, argv):
    with pytest.raises(app.BashRejected):
        app._validate_bash_argv(argv)


# ── read_file / write_file path rules ─────────────────────────────────────────
PATH_CASES = [
    # (path relative to root, allowed for read, allowed for write)
    ("gladius-api/server.py",          True,  True),
    ("repo/gladius-api/server.py",     True,  True),
    ("gladius-api/.env",               False, False),
    ("gladius-api/.env.local",         False, False),
    ("gladius-api/prod.env",           False, False),
    ("gladius-api/server.key",         False, False),
    ("gladius-api/cert.PEM",           False, False),
    ("repo/.git/config",               False, False),
    ("repo/.git/hooks/pre-commit",     False, False),
    ("repo/.Git/config",               False, False),
    ("repo/.gitattributes",            True,  False),
    ("repo/.gitmodules",               True,  False),
    ("repo/.gitignore",                True,  True),
]


@pytest.mark.parametrize("rel,read_ok,write_ok", PATH_CASES, ids=[c[0] for c in PATH_CASES])
def test_protected_paths(app, root, rel, read_ok, write_ok):
    for write, ok in ((False, read_ok), (True, write_ok)):
        for spelled in (rel, str(root / rel)):
            if ok:
                app._resolve_sandboxed(spelled, write=write)
            else:
                with pytest.raises(ValueError):
                    app._resolve_sandboxed(spelled, write=write)


def test_paths_outside_root_rejected(app, root):
    with pytest.raises(ValueError):
        app._resolve_sandboxed(_outside(root))
    with pytest.raises(ValueError):
        app._resolve_sandboxed("../outside.txt", write=True)


def test_write_file_refuses_git_metadata(app, root):
    out = app.exec_tool("write_file", {"path": "repo/.git/config", "content": "x"})
    assert out.startswith("Error:")
    assert not (root / "repo" / ".git" / "config").exists()


def test_read_file_refuses_env(app):
    out = app.exec_tool("read_file", {"path": "gladius-api/.env"})
    assert out.startswith("Error:") and "X=1" not in out


# ── notify_slack target is fixed (#37) ────────────────────────────────────────
def test_notify_slack_has_no_channel_parameter(app):
    tool = next(t for t in app.TOOLS if t["name"] == "notify_slack")
    assert set(tool["input_schema"]["properties"]) == {"message"}


def test_dm_channel_not_overwritten_with_multiple_users(app, monkeypatch):
    monkeypatch.setattr(app, "OVERSEER_NOTIFY_CHANNEL", "")
    monkeypatch.setattr(app, "SLACK_ALLOWED_USERS", {"U1", "U2"})
    monkeypatch.setattr(app, "_dm_channel", None)
    assert app._should_store_dm_channel("D1")
    monkeypatch.setattr(app, "_dm_channel", "D1")
    assert not app._should_store_dm_channel("D2")
    monkeypatch.setattr(app, "SLACK_ALLOWED_USERS", {"U1"})
    assert app._should_store_dm_channel("D2")
    monkeypatch.setattr(app, "OVERSEER_NOTIFY_CHANNEL", "C1")
    assert not app._should_store_dm_channel("D2")


# ── real git through the hardened wrapper ─────────────────────────────────────
@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_hardened_git_still_works(app, monkeypatch):
    repo = app.OVERSEER_ROOT / "gitcheck"
    repo.mkdir(exist_ok=True)
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "t"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "t@t"], check=True)
    (repo / "f.txt").write_text("a\n")
    monkeypatch.setattr(app, "GIT_REPO_DIR", repo)
    assert app.exec_tool("bash", {"command": "git add f.txt"}) == "(no output)"
    assert "first commit" in app.exec_tool("bash", {"command": "git commit -m 'first commit'"})
    (repo / "f.txt").write_text("a\nb\n")
    assert "+b" in app.exec_tool("bash", {"command": "git diff"})
    assert "first commit" in app.exec_tool("bash", {"command": "git log --oneline"})
    assert app.exec_tool("bash", {"command": "git remote -v"}) == "(no output)"
