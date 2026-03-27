from secara.output.models import Finding
from secara.output.formatter import output_rich


def test_output_rich_handles_markup_like_snippets_without_crash():
    finding = Finding(
        rule_id="CMD101",
        rule_name="Command Injection via exec()",
        severity="HIGH",
        file_path="app.js",
        line_number=2,
        snippet='exec(userInput + "[/caption]")',
        description="Untrusted input is passed to exec and can execute arbitrary commands.",
        fix="Avoid exec and use safe parameterized APIs.",
        language="javascript",
        confidence="HIGH",
        evidence={"sink": "exec"},
    )

    # Regression: rich markup parser should not crash on snippet text like [/caption].
    output_rich([finding], verbose=False)
