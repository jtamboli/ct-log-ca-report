# Generate reports from existing sample data
run:
    uv run python3 generate_reports.py

# Fetch certificates from CT logs and generate reports
fetch *args:
    uv run python3 main.py {{args}}
