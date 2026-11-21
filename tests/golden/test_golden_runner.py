from ra.cli.main import _offline_responder
from ra.press.golden import check_golden, load_golden
from ra.press.routing import TaskType


def test_RA_MDL_007_golden_set_runner_green():
    cases = load_golden("tests/golden/bug_class.jsonl", "bug_class")
    report = check_golden(cases, _offline_responder)
    assert report.passed is True
    assert report.rows == 200
    assert report.score == 1.0


def test_RA_MDL_007_task_type_filter():
    cases = load_golden("tests/golden/bug_class.jsonl", TaskType.BUG_CLASS.value)
    assert cases and all(case.task_type is TaskType.BUG_CLASS for case in cases)
