import csv
import io
import json

import pytest

from conftest import web
from regexsoc.services import Analyzer
from regexsoc.services.export import sanitize_cell, to_csv, to_json


@pytest.mark.parametrize("value", ["=1+1", "+cmd|' /C calc'!A0", "-2+3", "@SUM(A1)", "\t=1", "  =1+1"])
def test_formula_prefixes_are_neutralised(value):
    assert sanitize_cell(value).startswith("'")


@pytest.mark.parametrize("value", ["hello", "203.0.113.5", "", 42, None])
def test_safe_values_untouched(value):
    assert sanitize_cell(value) == value


def test_csv_roundtrip_and_injection_protection():
    text = to_csv([{"username": "=HYPERLINK(\"http://x\")", "ip": "203.0.113.5", "n": 3}])
    row = next(csv.DictReader(io.StringIO(text)))
    assert row["username"].startswith("'=") and row["ip"] == "203.0.113.5" and row["n"] == "3"


def test_csv_flattens_lists():
    assert "a | b" in to_csv([{"evidence": ["a", "b"]}])


def test_json_export_of_analysis_is_valid():
    result = Analyzer().analyze_lines([web(0, "/.env")])
    data = json.loads(to_json(result.to_dict()))
    assert {"summary", "alerts", "detections", "iocs", "risk_profiles"} <= set(data)
    assert data["alerts"][0]["rule_id"] == "RULE-010"


def test_export_of_empty_rows():
    assert to_csv([], ["a", "b"]) == "a,b\n"


@pytest.mark.parametrize("value", ["\n=1+1", "\v@SUM(A1)", "\u00a0=1+1", "\u2003+1+1"])
def test_formula_after_whitespace_is_neutralised(value):
    assert sanitize_cell(value).startswith("'"), repr(value)


def test_csv_header_neutralises_formula_names():
    text = to_csv([{"=SUM(1,1)": "safe"}], fields=["=SUM(1,1)"])
    header = next(csv.reader(io.StringIO(text)))[0]
    assert header == "'=SUM(1,1)"
