# NITC Physical Reporting · Token System

A Flask prototype for coordinating physical reporting at NIT Calicut. It gives students a way to request a reporting token and check queue progress. Staff can track a reporting session from intake through completion.

[Quick start](#quick-start) · [Project files](#project-files)

## Quick start

Run from the repository root in a Python environment. Use fictional records for local testing.

```bash
python -m pip install -r requirements.txt
python app.py
```

## Project files

| Path | Purpose |
| --- | --- |
| [`app.py`](app.py) | Flask application and queue logic |
| [`templates/`](templates/) | Student and staff screens |
| [`static/`](static/) | Browser-side behavior |

## License

See [LICENSE](LICENSE).
