import unittest

from kavach.policy import combine_findings, required_fields_available
from kavach.schema import Action, ActionEvent, Decision, PolicyFinding, RuntimeInfo, Visibility


def make_event(visibility=None):
    return ActionEvent(
        schema_version="1.0",
        event_id="evt-1",
        session_id="session-1",
        runtime=RuntimeInfo(name="test", interception_point="before_tool_execution"),
        action=Action(tool_name="shell", operation="execute", arguments={"command": "echo hi"}),
        visibility=visibility if visibility is not None else {"action.arguments": Visibility.PRESENT},
    )


class PolicyContractTests(unittest.TestCase):
    def test_present_required_field_is_available(self):
        self.assertTrue(required_fields_available(make_event(), ["action.arguments"]))

    def test_missing_visibility_is_not_available(self):
        self.assertFalse(required_fields_available(make_event({}), ["action.arguments"]))

    def test_redacted_required_field_is_not_available(self):
        event = make_event({"action.arguments": Visibility.REDACTED})
        self.assertFalse(required_fields_available(event, ["action.arguments"]))

    def test_block_has_priority(self):
        event = make_event()
        findings = [
            PolicyFinding("review-policy", Decision.REVIEW, "NEEDS_REVIEW", "review"),
            PolicyFinding("block-policy", Decision.BLOCK, "DANGEROUS_ACTION", "blocked"),
        ]
        self.assertEqual(combine_findings(event, findings).decision, Decision.BLOCK)

    def test_indeterminate_does_not_become_allow(self):
        event = make_event()
        finding = PolicyFinding("input-policy", Decision.INDETERMINATE, "MISSING_EVIDENCE", "required field missing")
        self.assertEqual(combine_findings(event, [finding]).decision, Decision.INDETERMINATE)

    def test_no_findings_allows(self):
        self.assertEqual(combine_findings(make_event(), []).decision, Decision.ALLOW)


if __name__ == "__main__":
    unittest.main()
