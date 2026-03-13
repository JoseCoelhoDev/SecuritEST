import json
from core.models import ScanResult


class ReportBuilder:
    @staticmethod
    def save_json(result: ScanResult, output_file: str = "scan_report.json"):
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(result.to_dict(), f, indent=4, ensure_ascii=False)