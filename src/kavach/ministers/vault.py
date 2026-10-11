"""VAULT: flags direct access to common credential stores and secret material."""
import re

from ..models import ActionEvent, Vote, VoteKind


# Kept explicit and readable; expand only with positive + benign regression tests.
_SECRET_PATTERNS = (
    ("DOTENV_FILE", re.compile(r"(^|[/\\])\.env(\.[\w-]+)?($|\s|['\"])")),
    ("SSH_PRIVATE_KEY", re.compile(r"(^|[/\\])\.ssh[/\\]|\bid_(rsa|dsa|ecdsa|ed25519)\b")),
    ("CLOUD_CREDENTIALS", re.compile(r"\.aws[/\\]credentials|\.docker[/\\]config\.json|application_default_credentials\.json", re.I)),
    ("PRIVATE_KEY_MATERIAL", re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("ACCESS_KEY", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("SECRET_ENV_VAR", re.compile(r"\b(OPENAI_API_KEY|ANTHROPIC_API_KEY|AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN|GH_TOKEN|STRIPE_SECRET_KEY)\b")),
    ("SECRET_FILE", re.compile(r"(^|[/\\])(secrets?|credentials?)\.(json|ya?ml|txt)\b", re.I)),
)


def _strings(value):
    if isinstance(value, dict):
        for item in value.values():
            yield from _strings(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _strings(item)
    elif value is not None:
        yield str(value)


class VaultMinister:
    name = "VAULT"

    def evaluate(self, event: ActionEvent) -> Vote:
        text = " ".join([event.tool_name, event.operation, *_strings(event.arguments)])
        for rule_id, pattern in _SECRET_PATTERNS:
            match = pattern.search(text)
            if match:
                return Vote(self.name, VoteKind.BLOCK, f"{rule_id}:{match.group(0)}")
        return Vote(self.name, VoteKind.ALLOW, "NO_CREDENTIAL_PATTERN")
