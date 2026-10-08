"""
tools/junit_parser.py
---------------------
Structured parser for pytest --junitxml output.
Extracts per-test records: name, file, classname, status, error message,
and pinpointed failing file and line number.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from core.logging import get_logger
from core.state import TestCaseResult

logger = get_logger(__name__)


def parse_junit_xml(xml_source: str | Path) -> list[TestCaseResult]:
    """
    Parse a JUnit XML file or string into a list of TestCaseResult models.
    Handles <failure>, <error>, <skipped>, and passed test cases.
    Extracts failing file and line number from python tracebacks.
    """
    content = ""
    if isinstance(xml_source, Path) or (isinstance(xml_source, str) and "\n" not in xml_source and Path(xml_source).is_file()):
        path = Path(xml_source)
        if not path.is_file():
            return []
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except Exception as exc:
            logger.warning("junit_xml_read_error", error=str(exc))
            return []
    else:
        content = str(xml_source)

    if not content.strip():
        return []

    try:
        root = ET.fromstring(content)
    except Exception as exc:
        logger.warning("junit_xml_parse_error", error=str(exc))
        return []

    results: list[TestCaseResult] = []

    # Iterate over all <testcase> elements anywhere in the document
    for tc in root.iter("testcase"):
        name = tc.attrib.get("name", "unknown")
        classname = tc.attrib.get("classname", "")
        file_attr = tc.attrib.get("file", "")

        # Duration
        try:
            duration = float(tc.attrib.get("time", "0.0"))
        except ValueError:
            duration = 0.0

        # Infer file from classname if file attribute not provided
        file_path = file_attr
        if not file_path and classname:
            # e.g. "test_calc.TestCalc" or "calculator.test_calc.TestCalc" -> "test_calc.py"
            parts = classname.split(".")
            for part in parts:
                if "test" in part.lower():
                    file_path = f"{part}.py" if not part.endswith(".py") else part
                    break
            if not file_path:
                file_path = parts[0] + ".py"

        # Check status
        fail_node = tc.find("failure")
        err_node = tc.find("error")
        skip_node = tc.find("skipped")

        status = "passed"
        err_msg: str | None = None
        failing_file: str | None = None
        failing_line: int | None = None

        node = fail_node if fail_node is not None else err_node

        if node is not None:
            status = "failed" if fail_node is not None else "error"
            err_msg = node.attrib.get("message")
            body = (node.text or "").strip()
            if not err_msg and body:
                err_msg = body.splitlines()[-1]

            # Look for "filename.py:line" pattern in failure traceback
            # e.g. "test_calc.py:15: TypeError" or "  File ".../calc.py", line 14"
            match = re.search(r"([a-zA-Z0-9_\-\./\\]+\.py):(\d+)", body)
            if match:
                failing_file = Path(match.group(1)).name
                failing_line = int(match.group(2))
            else:
                py_line_match = re.search(r'File "([^"]+\.py)", line (\d+)', body)
                if py_line_match:
                    failing_file = Path(py_line_match.group(1)).name
                    failing_line = int(py_line_match.group(2))
        elif skip_node is not None:
            status = "skipped"
            err_msg = skip_node.attrib.get("message")

        results.append(
            TestCaseResult(
                name=name,
                file=file_path or "test",
                classname=classname,
                status=status,
                error_message=err_msg,
                failing_file=failing_file,
                failing_line=failing_line,
                duration=round(duration, 4),
            )
        )

    return results
