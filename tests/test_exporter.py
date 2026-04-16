"""Tests for ResultExporter class — 7 tests across 4 test classes."""

import json
import csv

from cyberguard_toolkit import ResultExporter


class TestExportJSON:

    def test_export_json(self, exporter):
        data = {"key": "value", "number": 42}
        path = exporter.export_json(data, "test_export")
        assert path.exists()
        loaded = json.loads(path.read_text())
        assert loaded["key"] == "value"
        assert loaded["number"] == 42

    def test_export_json_nested(self, exporter):
        data = {"list": [1, 2, 3], "nested": {"a": "b"}}
        path = exporter.export_json(data, "test_nested")
        loaded = json.loads(path.read_text())
        assert loaded["list"] == [1, 2, 3]
        assert loaded["nested"] == {"a": "b"}


class TestExportCSV:

    def test_export_csv(self, exporter):
        rows = [
            {"name": "Alice", "age": "30"},
            {"name": "Bob", "age": "25"},
        ]
        path = exporter.export_csv(rows, "test_csv")
        assert path.exists()
        content = path.read_text()
        assert "Alice" in content
        assert "Bob" in content

    def test_export_csv_empty(self, exporter):
        path = exporter.export_csv([], "test_empty")
        assert path is not None

    def test_export_csv_with_fieldnames(self, exporter):
        rows = [{"name": "Test", "age": "20", "extra": "ignored"}]
        path = exporter.export_csv(rows, "test_fields", fieldnames=["name", "age", "extra"])
        content = path.read_text()
        assert "name" in content
        assert "age" in content


class TestExportTXT:

    def test_export_txt(self, exporter):
        content = "Line 1\nLine 2\nLine 3"
        path = exporter.export_txt(content, "test_txt")
        assert path.exists()
        assert path.read_text() == content


class TestExportHTML:

    def test_export_html(self, exporter):
        html = "<html><body>Test</body></html>"
        path = exporter.export_html(html, "test_html")
        assert path.exists()
        assert "<html>" in path.read_text()
