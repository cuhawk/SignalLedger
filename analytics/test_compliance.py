"""Exercise the auditor CLI with native Parquet fixtures and real signatures."""

from analytics.compliance_fixture import compliance_cases


def test_compliance_posture(cli, tmp_path):
    expected = {
        "verified": ("PASS", "PASS", "PASS", 8, 1),
        "missing": ("FAIL", "PASS", "PASS", 3, 0),
        "unapproved": ("FAIL", "PASS", "PASS", 3, 0),
        "invalid_approval_signature": ("FAIL", "PASS", "PASS", 3, 0),
        "invalid_window": ("FAIL", "FAIL", "FAIL", 0, 0),
        "unsigned_detection": ("PASS", "PASS", "FAIL", 4, 1),
    }
    for case, report, markdown, _ in compliance_cases(tmp_path, cli):
        oversight, window, cybersecurity, coverage, approvals = expected[case]
        controls = {row["id"]: row for row in report["controls"]}
        assert len(controls) == 27
        assert report["window_verification"] == window
        assert (report["verified_records"] > 0) == (window == "PASS")
        assert controls["Article 14"]["posture"] == oversight
        assert controls["Article 14"]["merkle_verification"] == oversight
        assert controls["Article 14"]["verified_approvals"] == approvals
        assert controls["Article 15"]["posture"] == cybersecurity
        assert controls["Article 15"]["merkle_verification"] == cybersecurity
        assert sum(row["posture"] == "PASS" for row in controls.values()) == coverage
        assert f"| Article 14 Human oversight | {oversight} | {oversight} |" in markdown
