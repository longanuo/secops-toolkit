"""报告基类"""
from datetime import datetime


class ReportBase:
    def __init__(self, title):
        self.title = title
        self.generated_at = datetime.now()

    def to_markdown(self):
        raise NotImplementedError

    def to_json(self):
        raise NotImplementedError

    def save(self, output_dir, prefix="report"):
        from pathlib import Path
        import json
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        ts = self.generated_at.strftime("%Y%m%d_%H%M%S")
        md_path = output_dir / f"{prefix}_{ts}.md"
        json_path = output_dir / f"{prefix}_{ts}.json"
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(self.to_markdown())
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(self.to_json(), f, indent=2, ensure_ascii=False)
        return str(md_path), str(json_path)
