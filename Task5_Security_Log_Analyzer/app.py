
import csv
import io
import logging
import os
from pathlib import Path

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
)

from detector import analyze_logs
from database import (
    init_db,
    save_analysis,
    dashboard_data,
    clear_history,
)


# ==========================================
# APPLICATION CONFIGURATION
# ==========================================

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "security_logs.db"

app = Flask(__name__)

app.secret_key = os.environ.get(
    "FLASK_SECRET_KEY",
    "local-student-project-key",
)

app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024

logging.basicConfig(level=logging.INFO)

# Initialize database
init_db(DB_PATH)


# ==========================================
# REQUIRED CSV COLUMNS
# ==========================================

REQUIRED_COLUMNS = [
    "timestamp",
    "username",
    "source_ip",
    "event_type",
    "status",
]


# ==========================================
# CSV FILE READER
# ==========================================

def read_csv(file):

    filename = (file.filename or "").strip()

    if not filename.lower().endswith(".csv"):
        raise ValueError(
            "Please upload a valid .csv file."
        )

    content = file.read()

    if not content:
        raise ValueError(
            "The CSV file is empty."
        )

    # --------------------------------------
    # Detect file encoding
    # --------------------------------------

    try:
        if content.startswith(
            (b"\xff\xfe", b"\xfe\xff")
        ):
            text = content.decode("utf-16")

        elif b"\x00" in content[:200]:
            text = content.decode("utf-16")

        else:
            text = content.decode("utf-8-sig")

    except UnicodeDecodeError:

        try:
            text = content.decode("cp1252")

        except UnicodeDecodeError as exc:
            raise ValueError(
                "Unable to read CSV encoding. "
                "Please save the file as UTF-8 CSV."
            ) from exc

    # Remove BOM and empty leading lines
    text = text.lstrip("\ufeff")

    # --------------------------------------
    # Detect CSV delimiter
    # --------------------------------------

    try:
        sample = "\n".join(
            line for line in text.splitlines()
            if line.strip()
        )[:5000]

        try:
            dialect = csv.Sniffer().sniff(
                sample,
                delimiters=",;\t|"
            )
            delimiter = dialect.delimiter

        except csv.Error:
            delimiter = ","

        reader = csv.reader(
            io.StringIO(text, newline=""),
            delimiter=delimiter,
            skipinitialspace=True,
        )

        # ----------------------------------
        # Find first non-empty row as header
        # ----------------------------------

        headers = None
        header_line = 0

        for line_number, row in enumerate(reader, start=1):

            if not row or not any(
                str(value).strip() for value in row
            ):
                continue

            headers = [
                str(name).strip().lstrip("\ufeff").lower()
                for name in row
            ]

            header_line = line_number
            break

        if not headers:
            raise ValueError(
                "The CSV file is empty or has no header row."
            )

        # ----------------------------------
        # Validate headers
        # ----------------------------------

        if len(headers) != len(set(headers)):
            raise ValueError(
                "Duplicate column names found in CSV."
            )

        missing = [
            column
            for column in REQUIRED_COLUMNS
            if column not in headers
        ]

        if missing:
            raise ValueError(
                "CSV header not recognized. Missing columns: "
                + ", ".join(missing)
                + ". Expected: "
                + ", ".join(REQUIRED_COLUMNS)
                + f". Detected headers: {headers}"
            )

        # ----------------------------------
        # Read CSV records
        # ----------------------------------

        rows = []

        for line_number, row in enumerate(
            reader,
            start=header_line + 1
        ):

            # Skip blank rows
            if not row or not any(
                str(value).strip() for value in row
            ):
                continue

            if len(row) != len(headers):
                raise ValueError(
                    f"CSV row {line_number} has "
                    f"{len(row)} values, but "
                    f"{len(headers)} columns are expected."
                )

            cleaned = {
                headers[index]: str(value).strip()
                for index, value in enumerate(row)
            }

            # Check required values
            empty_fields = [
                column
                for column in REQUIRED_COLUMNS
                if not cleaned.get(column, "")
            ]

            if empty_fields:
                raise ValueError(
                    f"CSV row {line_number} has empty fields: "
                    + ", ".join(empty_fields)
                )

            rows.append(cleaned)

            if len(rows) > 10000:
                raise ValueError(
                    "Maximum upload limit is 10,000 records."
                )

        if not rows:
            raise ValueError(
                "No log records found in the CSV file."
            )

        return rows

    except csv.Error as exc:
        raise ValueError(
            f"Invalid CSV formatting: {exc}"
        ) from exc


# ==========================================
# DASHBOARD HOME PAGE
# ==========================================

@app.route("/")
def index():

    try:
        data = dashboard_data(DB_PATH)

        return render_template(
            "index.html",
            data=data
        )

    except Exception:

        app.logger.exception(
            "Dashboard loading failed"
        )

        flash(
            "Unable to load dashboard data.",
            "error"
        )

        return render_template(
            "index.html",
            data={
                "total_events": 0,
                "failed_events": 0,
                "alert_count": 0,
                "high_count": 0,
                "top_ips": [],
                "alerts": [],
            },
        )


# ==========================================
# ANALYZE SECURITY LOGS
# ==========================================

@app.route("/analyze", methods=["POST"])
def analyze():

    uploaded = request.files.get("logfile")

    if not uploaded or not uploaded.filename:

        flash(
            "Please select a CSV file.",
            "error"
        )

        return redirect(url_for("index"))

    try:

        # Read uploaded CSV
        rows = read_csv(uploaded)

        app.logger.info(
            "CSV successfully read: %d records",
            len(rows)
        )

        # Analyze security events
        result = analyze_logs(rows)

        # Validate timestamps
        if result.get("valid_events") != len(rows):

            raise ValueError(
                "Some timestamps are invalid. "
                "Please check the timestamp column."
            )

        # Get detected alerts
        alerts = result["alerts"]

        # Save logs and alerts
        save_analysis(
            DB_PATH,
            rows,
            alerts
        )

        # Get updated dashboard data
        data = dashboard_data(DB_PATH)

        app.logger.info(
            "Database: %s",
            DB_PATH
        )

        app.logger.info(
            "Uploaded records: %d",
            len(rows)
        )

        app.logger.info(
            "New alerts: %d",
            len(alerts)
        )

        app.logger.info(
            "Dashboard data: %s",
            data
        )

        flash(
            f"Analysis successful! "
            f"{len(rows)} records processed "
            f"and {len(alerts)} alerts detected.",
            "success"
        )

    except ValueError as error:

        app.logger.warning(
            "CSV validation error: %s",
            error
        )

        flash(
            str(error),
            "error"
        )

    except Exception:

        app.logger.exception(
            "Security log analysis failed"
        )

        flash(
            "Analysis failed. Please check the terminal "
            "for more details.",
            "error"
        )

    return redirect(url_for("index"))


# ==========================================
# CLEAR DASHBOARD HISTORY
# ==========================================

@app.route("/clear", methods=["POST"])
def clear():

    try:

        clear_history(DB_PATH)

        flash(
            "Dashboard history cleared successfully.",
            "success"
        )

    except Exception:

        app.logger.exception(
            "Unable to clear dashboard history"
        )

        flash(
            "Unable to clear dashboard history.",
            "error"
        )

    return redirect(url_for("index"))


# ==========================================
# FILE SIZE ERROR
# ==========================================

@app.errorhandler(413)
def file_too_large(error):

    flash(
        "File too large. Maximum upload size is 5 MB.",
        "error"
    )

    return redirect(url_for("index"))


# ==========================================
# RUN FLASK APPLICATION
# ==========================================

if __name__ == "__main__":

    print("=" * 45)
    print("       SECURITY LOG ANALYZER")
    print("=" * 45)

    print("Database:", DB_PATH)

    print(
        "Open: http://127.0.0.1:5000"
    )

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
    )
