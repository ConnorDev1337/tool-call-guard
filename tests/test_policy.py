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
