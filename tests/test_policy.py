import pytest

from toolguard.model import Action
from toolguard.policy import Policy, PolicyError, iter_strings, select_args


@pytest.mark.parametrize("name", ["balanced", "strict"])
def test_presets_load(name):
    policy = Policy.preset(name)
    assert policy.name == name
    assert policy.sources and policy.sinks and policy.protect
    assert len(policy.digest) == 64


def test_strict_extends_balanced():
    balanced, strict = Policy.preset("balanced"), Policy.preset("strict")
    assert strict.sink_for("Bash", {"command": "ls"}).egress is True
    assert balanced.sink_for("Bash", {"command": "ls"}).egress is False
    assert strict.actions_for("shell").untrusted_flow == Action.BLOCK
    assert balanced.actions_for("shell").untrusted_flow == Action.CONFIRM
    # Partially overridden tables keep the preset's other values.
    assert strict.actions_for("publish").private_flow == Action.BLOCK
    assert strict.actions_for("publish").tainted == Action.CONFIRM


def test_extends_resolves_the_whole_preset_chain(tmp_path):
    """A policy extending ``strict`` also inherits what ``strict`` takes from ``balanced``."""
    path = tmp_path / "p.toml"
    path.write_text(
        'extends = "strict"\n[actions.web]\ntainted = "allow"\n'
        '[[sink]]\ntools = ["mcp__crm__export_contacts"]\ncategory = "send"\negress = true\n',
        encoding="utf-8",
    )
    policy, strict = Policy.load(str(path)), Policy.preset("strict")
    assert policy.sources == strict.sources
    assert policy.protect == strict.protect and policy.protect
    assert policy.sinks[1:] == strict.sinks
    assert policy.sink_for("mcp__crm__export_contacts", {}).category == "send"
    assert policy.sink_for("Bash", {"command": "ls"}).egress is True  # From strict
    assert policy.sink_for("Write", {}).category == "write"  # From balanced
    assert policy.actions_for("default") == strict.actions_for("default")
    assert policy.actions_for("web").tainted == Action.ALLOW
    assert policy.actions_for("web").trifecta == Action.BLOCK  # From strict
    assert policy.actions_for("web").private_flow == Action.BLOCK  # From balanced


def test_extends_detects_cycles(monkeypatch):
    presets = {"balanced": {"extends": "strict"}, "strict": {"extends": "balanced"}}
    monkeypatch.setattr("toolguard.policy._preset_dict", presets.__getitem__)
    with pytest.raises(PolicyError, match="cycle between presets"):
        Policy.from_dict({"extends": "strict"})
    presets["balanced"] = {"extends": "balanced"}
    with pytest.raises(PolicyError, match="balanced -> balanced"):
        Policy.preset("balanced")


def test_load_by_name_path_and_default(tmp_path):
    path = tmp_path / "p.toml"
    path.write_text(
        'extends = "balanced"\nmode = "monitor"\n'
        '[[sink]]\ntools = ["mcp__crm__export_contacts"]\ncategory = "send"\negress = true\n',
        encoding="utf-8",
    )
    policy = Policy.load(str(path))
    assert policy.mode == "monitor"
    assert policy.sink_for("mcp__crm__export_contacts", {}).category == "send"
    assert Policy.load(None).name == "balanced"
    assert Policy.load("strict").name == "strict"


def test_user_rules_take_precedence(tmp_path):
    path = tmp_path / "p.toml"
    path.write_text(
        'extends = "balanced"\n'
        '[[sink]]\ntools = ["Bash"]\ncategory = "trusted-shell"\n'
        '[actions.trusted-shell]\ntainted = "allow"\nuntrusted_flow = "allow"\n',
        encoding="utf-8",
    )
    policy = Policy.load(str(path))
    assert policy.sink_for("Bash", {"command": "make"}).category == "trusted-shell"
    assert policy.actions_for("trusted-shell").tainted == Action.ALLOW


def test_unknown_category_uses_default_table():
    policy = Policy.from_dict({"actions": {"default": {"tainted": "block"}}})
    assert policy.actions_for("anything").tainted == Action.BLOCK
    assert Policy.from_dict({}).actions_for("x").untrusted_flow == Action.BLOCK


@pytest.mark.parametrize(
    ("data", "message"),
    [
        ({"bogus": 1}, "unknown top-level key"),
        ({"mode": "yolo"}, "mode must be"),
        ({"extends": "nope"}, "unknown preset"),
        ({"taint_ttl": -1}, "taint_ttl"),
        ({"max_observation_chars": 10}, "max_observation_chars"),
        ({"source": [{"tools": ["x"]}]}, "untrusted, private or both"),
        ({"source": [{"tools": ["x"], "untrusted": True, "colour": "red"}]}, "unknown key"),
        ({"source": [{"untrusted": True}]}, "'tools' is required"),
        ({"sink": [{"tools": ["x"]}]}, "'category' is required"),
        ({"sink": [{"tools": [1], "category": "c"}]}, "list of strings"),
        ({"actions": {"send": {"tainted": "maybe"}}}, "unknown action"),
        ({"actions": {"send": {"sometimes": "allow"}}}, "unknown key"),
        ({"protect": [{"tools": ["x"], "action": "nuke"}]}, "unknown action"),
        ({"source": [{"tools": "x", "untrusted": True, "when": "y"}]}, "table of argument"),
        ({"trust": [{"when": {"uri": "x"}}]}, "'tools' is required"),
        ({"trust": [{"tools": ["x"], "untrusted": False}]}, "unknown key"),
    ],
)
def test_validation_errors(data, message):
    with pytest.raises(PolicyError, match=message):
        Policy.from_dict(data)


def test_unreadable_policy_file(tmp_path):
    bad = tmp_path / "bad.toml"
    bad.write_text("this is = = not toml", encoding="utf-8")
    with pytest.raises(PolicyError, match="cannot read policy"):
        Policy.from_toml(bad)
    with pytest.raises(PolicyError, match="unknown preset"):
        Policy.preset("lax")
    with pytest.raises(PolicyError):
        Policy.preset("balanced").with_mode("yolo")


def test_source_matching_with_conditions_and_union():
    policy = Policy.preset("balanced")
    assert policy.source_for("Read", {"file_path": "/repo/src/app.py"}) is None
    secret = policy.source_for("Read", {"file_path": "C:\\Users\\bob\\.ssh\\id_ed25519"})
    assert secret is not None and secret.private and not secret.untrusted
    web = policy.source_for("WebFetch", {"url": "https://x"})
    assert web.untrusted and web.kind == "web"
    mail = policy.source_for("mcp__gmail__read_email", {})
    assert mail.untrusted and mail.private
    assert policy.source_for("Bash", {"command": "cat ~/.ssh/id_rsa"}).private
    assert policy.source_for("PowerShell", {"command": "Get-Content .env"}).private


def test_sink_matching():
    policy = Policy.preset("balanced")
    assert policy.sink_for("mcp__bank__create_payment", {}).category == "payment"
    assert policy.sink_for("mcp__gmail__send_email", {}).category == "send"
    assert policy.sink_for("mcp__slack__post_message", {}).category == "send"
    assert policy.sink_for("PowerShell", {}).category == "shell"
    assert policy.sink_for("Write", {}).category == "write"
    assert policy.sink_for("mcp__github__create_issue", {}).category == "publish"
    assert policy.sink_for("Read", {}) is None
    assert policy.sink_for("Grep", {}) is None


def test_protect_rules():
    policy = Policy.preset("balanced")
    assert policy.protect_hits("Bash", {"command": "toolguard approve 1234"})
    assert policy.protect_hits("Write", {"file_path": "/home/u/.claude/settings.json"})
    assert policy.protect_hits("Edit", {"file_path": "C:\\Users\\u\\.toolguard\\guard.db"})
    assert not policy.protect_hits("Bash", {"command": "pytest -q"})
    assert not policy.protect_hits("Read", {"file_path": "/home/u/.claude/settings.json"})


def test_iter_strings_and_select_args():
    args = {"to": ["a@x.io", "b@x.io"], "meta": {"iban": "X", "n": 5, "ok": True}, "body": None}
    assert list(iter_strings(args)) == [
        ("to[0]", "a@x.io"),
        ("to[1]", "b@x.io"),
        ("meta.iban", "X"),
        ("meta.n", "5"),
    ]
    assert [p for p, _ in select_args(args, ("to",))] == ["to[0]", "to[1]"]
    assert [p for p, _ in select_args(args, ("meta.iban",))] == ["meta.iban"]
    assert len(select_args(args, ("*",))) == 4
    assert list(iter_strings("plain")) == [("$", "plain")]


def test_with_mode():
    policy = Policy.preset("balanced").with_mode("monitor")
    assert policy.mode == "monitor"
    assert Policy.preset("balanced").mode == "enforce"


def test_mcp_resources_and_prompts_are_third_party_content():
    policy = Policy.preset("balanced")
    resource = policy.source_for("mcp__docs__resources/read", {"uri": "docs://guide.md"})
    assert resource.kind == "resource" and resource.untrusted and not resource.private
    prompt = policy.source_for("mcp__docs__prompts/get", {"name": "review"})
    assert prompt.kind == "prompt" and prompt.untrusted
    claude = policy.source_for("ReadMcpResourceTool", {"server": "docs", "uri": "docs://a"})
    assert claude.untrusted
    secret = policy.source_for("mcp__fs__resources/read", {"uri": "file:///work/app/.env"})
    assert secret.untrusted and secret.private
    # A server whose name marks web content keeps that kind.
    assert policy.source_for("mcp__fetch__prompts/get", {"name": "fetch"}).kind == "web"


def test_trust_rules_clear_untrusted_but_keep_private():
    policy = Policy.from_dict(
        {
            "extends": "balanced",
            "trust": [
                {"tools": ["mcp__docs__resources/read"], "when": {"uri": ["docs://*"]}},
                {"tools": ["mcp__fs__resources/read", "mcp__gmail__*"]},
            ],
        }
    )
    assert len(policy.trust) == 2
    assert policy.source_for("mcp__docs__resources/read", {"uri": "docs://guide.md"}) is None
    other = policy.source_for("mcp__docs__resources/read", {"uri": "https://x.example/"})
    assert other.untrusted  # Outside the trusted URIs
    assert policy.source_for("mcp__docs__prompts/get", {"name": "review"}).untrusted
    secret = policy.source_for("mcp__fs__resources/read", {"uri": "file:///work/.env"})
    assert secret.private and not secret.untrusted
    mail = policy.source_for("mcp__gmail__read_email", {})
    assert mail.private and not mail.untrusted


@pytest.mark.parametrize(
    ("tool", "uri", "category", "egress"),
    [
        ("mcp__fs__resources/read", "file:///work/notes.md", "local-read", False),
        ("mcp__fs__resources/read", "FILE:///C:/work/notes.md", "local-read", False),
        ("mcp__fetch__resources/read", "https://x.example/a", "web", True),
        ("mcp__docs__resources/read", "wss://x.example/feed", "web", True),
        ("ReadMcpResourceTool", "http://127.0.0.1/a", "web", True),
        ("mcp__db__resources/read", "postgres://db/users/schema", "resource", True),
        ("mcp__docs__resources/read", "docs://guide.md", "resource", True),
    ],
)
def test_resource_uris_are_sinks_by_scheme(tool, uri, category, egress):
    for name in ("balanced", "strict"):
        sink = Policy.preset(name).sink_for(tool, {"server": "x", "uri": uri})
        assert (sink.category, sink.egress, sink.critical) == (category, egress, ("uri",))


def test_resource_actions_check_what_the_uri_carries():
    balanced, strict = Policy.preset("balanced"), Policy.preset("strict")
    local = balanced.actions_for("local-read")
    assert {local.tainted, local.untrusted_flow, local.private_flow, local.trifecta} == {
        Action.ALLOW
    }
    resource = balanced.actions_for("resource")
    assert (resource.private_flow, resource.trifecta) == (Action.CONFIRM, Action.ALLOW)
    assert strict.actions_for("resource").private_flow == Action.BLOCK
    assert balanced.actions_for("web").private_flow == Action.BLOCK
