import os
from dotenv import load_dotenv
from pathlib import Path
env_path = Path(__file__).parent / ".env"
load_dotenv(dotenv_path=env_path)
import random
import uuid
import smtplib
import hashlib
import secrets
from datetime import datetime
from datetime import timedelta
from email.message import EmailMessage
from flask import Flask, request, jsonify, render_template, session, send_from_directory, abort, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# CONFIG
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
# import os

# database_url = os.environ.get("postgresql://student_2sm2_user:Z77YWKFCFx04F8z7DuSXLgMIuzBUACC7@dpg-d6gudsk50q8c73aaca1g-a/student_2sm2")

# if database_url:
#     app.config['postgresql://student_2sm2_user:Z77YWKFCFx04F8z7DuSXLgMIuzBUACC7@dpg-d6gudsk50q8c73aaca1g-a/student_2sm2'] = database_url
# else:
#     app.config['postgresql://student_2sm2_user:Z77YWKFCFx04F8z7DuSXLgMIuzBUACC7@dpg-d6gudsk50q8c73aaca1g-a/student_2sm2'] = 'sqlite:///users.db'
# app.config['SECRET_KEY'] = "secret"
import os

database_url = os.environ.get("DATABASE_URL")

if database_url:
    # Fix Render's postgres:// issue if needed
    if database_url.startswith("postgres://"):
        database_url = database_url.replace("postgres://", "postgresql://", 1)

    app.config["SQLALCHEMY_DATABASE_URI"] = database_url
else:
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"

app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")

db = SQLAlchemy(app)
UPLOAD_DIR = os.path.join(app.instance_path, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)


def load_env_file_if_present():
    """
    Lightweight .env loader to avoid hard dependency on python-dotenv.
    Expected format: KEY=VALUE, one per line.
    """
    env_path = os.path.join(os.path.dirname(__file__), ".env")
    if not os.path.exists(env_path):
        return

    with open(env_path, "r", encoding="utf-8") as env_file:
        for raw_line in env_file:
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value


load_env_file_if_present()

# ---------------- MODELS ---------------- #

class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    otp_hash = db.Column(db.String(128))
    otp_expires_at = db.Column(db.String(64))
    otp_attempts = db.Column(db.Integer, default=0)
    otp_verified = db.Column(db.Boolean, default=False)

class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))

class ServerAdminCredential(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)


class Slot(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    time = db.Column(db.String(50), unique=True)
    capacity = db.Column(db.Integer)

class TokenBooking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_email = db.Column(db.String(100))
    fee_status = db.Column(db.String(20))
    payment_mode = db.Column(db.String(50))
    slot_time = db.Column(db.String(50))
    token_id = db.Column(db.String(20), unique=True)
    class10_doc = db.Column(db.String(255))
    class12_doc = db.Column(db.String(255))
    category_doc = db.Column(db.String(255))
    paid_receipt_doc = db.Column(db.String(255))
    sent_to_chanakya = db.Column(db.Boolean, default=False)
    admin1_notes = db.Column(db.Text)
    final_registration_completed = db.Column(db.Boolean, default=False)
    final_registration_completed_at = db.Column(db.String(50))
    is_bhaskara_active = db.Column(db.Boolean, default=False)
    moved_to_late_pool = db.Column(db.Boolean, default=False)
    late_reporting_reason = db.Column(db.Text)
    moved_to_late_pool_at = db.Column(db.String(50))


def parse_identity_from_email(email):
    local = (email or "").split("@")[0]
    if "_" not in local:
        return {"name": email or "Unknown", "roll_no": "--"}
    name_part, roll_part = local.split("_", 1)
    name = name_part.replace(".", " ").replace("-", " ").title()
    return {"name": name, "roll_no": roll_part.upper()}


def is_likely_hashed_password(stored_password):
    return (stored_password or "").startswith("pbkdf2:") or (stored_password or "").startswith("scrypt:")


def verify_user_password(stored_password, provided_password):
    if not stored_password or not provided_password:
        return False
    if is_likely_hashed_password(stored_password):
        try:
            return check_password_hash(stored_password, provided_password)
        except ValueError:
            return False
    return stored_password == provided_password


def hash_otp(email, otp):
    payload = f"{(email or '').lower()}:{otp}:{app.config['SECRET_KEY']}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def parse_iso_datetime(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def send_otp_email(receiver_email, otp):
    sender_email = os.environ.get("EMAIL_ADDRESS")
    sender_password = os.environ.get("EMAIL_PASSWORD")
    if not sender_email or not sender_password:
        raise RuntimeError("EMAIL_ADDRESS or EMAIL_PASSWORD is not configured.")

    msg = EmailMessage()
    msg["Subject"] = "NITC Password Reset OTP"
    msg["From"] = sender_email
    msg["To"] = receiver_email
    msg.set_content(
        f"Your NITC password reset OTP is: {otp}\n"
        "This OTP is valid for 10 minutes.\n"
        "If you did not request this, please ignore this email."
    )

    # Uses SMTP over SSL for encrypted transport.
    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
        smtp.login(sender_email, sender_password)
        smtp.send_message(msg)


def build_qr_payload(token_id, roll_no=None, slot_time=None):
    parts = [f"TOKEN:{token_id or '--'}"]
    if roll_no:
        parts.append(f"ROLL:{roll_no}")
    if slot_time:
        parts.append(f"SLOT:{slot_time}")
    return "NITC-PHYSICAL-REPORTING|" + "|".join(parts)


def payment_label(raw_payment):
    if raw_payment == "already-paid":
        return "Already Paid"
    if raw_payment == "on-spot":
        return "On Spot Payment"
    if raw_payment == "education-loan":
        return "Education Loan"
    return (raw_payment or "NA").replace("-", " ").title()


def capacity_units_for_fee(fee_status):
    return 1 if (fee_status or "").lower() == "yes" else 2


def default_dashboard_metrics():
    return {
        "total_served": 0,
        "active_in_bhaskara": 0,
        "chanakya_pending": 0,
        "late_pool_count": 0,
        "quick_waiting": 0,
        "detailed_waiting": 0,
        "avg_processing_minutes": 0,
        "last_sync": datetime.now().strftime("%d %b %Y, %I:%M %p"),
    }


def booking_to_view(booking):
    identity = parse_identity_from_email(booking.student_email)
    return {
        "id": booking.id,
        "token_id": booking.token_id,
        "student_email": booking.student_email,
        "student_name": identity["name"],
        "roll_no": identity["roll_no"],
        "fee_status": booking.fee_status,
        "slot_time": booking.slot_time,
        "payment_mode": booking.payment_mode,
        "payment_label": payment_label(booking.payment_mode),
        "queue_type": "X (Quick Review)" if (booking.fee_status or "").lower() == "yes" else "Y (Detailed Consultation)",
        "sent_to_chanakya": bool(booking.sent_to_chanakya),
        "qr_payload": build_qr_payload(booking.token_id, identity["roll_no"], booking.slot_time),
        "class10_doc_url": f"/uploads/{booking.class10_doc}" if booking.class10_doc else None,
        "class12_doc_url": f"/uploads/{booking.class12_doc}" if booking.class12_doc else None,
        "category_doc_url": f"/uploads/{booking.category_doc}" if booking.category_doc else None,
        "paid_receipt_doc_url": f"/uploads/{booking.paid_receipt_doc}" if booking.paid_receipt_doc else None,
        "admin1_notes": booking.admin1_notes or "",
        "final_registration_completed": bool(booking.final_registration_completed),
        "final_registration_completed_at": booking.final_registration_completed_at or "",
        "moved_to_late_pool": bool(booking.moved_to_late_pool),
        "late_reporting_reason": booking.late_reporting_reason or "",
        "moved_to_late_pool_at": booking.moved_to_late_pool_at or "",
    }

@app.context_processor
def inject_global_template_values():
    now = datetime.now()
    return {
        "current_year": now.year,
        "academic_session_label": f"{now.year}-{(now.year + 1) % 100:02d}",
    }


def save_uploaded_file(file_obj, email, label):
    if not file_obj or not file_obj.filename:
        return None
    safe_name = secure_filename(file_obj.filename)
    _, ext = os.path.splitext(safe_name)
    base_email = (email or "student").replace("@", "_at_").replace(".", "_")
    unique_name = f"{base_email}_{label}_{uuid.uuid4().hex[:10]}{ext}"
    file_obj.save(os.path.join(UPLOAD_DIR, unique_name))
    return unique_name


def generate_token_id():
    while True:
        token = f"TKN-{random.randint(100, 999)}"
        if not TokenBooking.query.filter_by(token_id=token).first():
            return token


def ensure_tokenbooking_columns():
    rows = db.session.execute(text("PRAGMA table_info(token_booking)")).fetchall()
    existing = {row[1] for row in rows}
    required_columns = {
        "token_id": "TEXT",
        "class10_doc": "TEXT",
        "class12_doc": "TEXT",
        "category_doc": "TEXT",
        "paid_receipt_doc": "TEXT",
        "sent_to_chanakya": "INTEGER DEFAULT 0",
        "admin1_notes": "TEXT",
        "final_registration_completed": "INTEGER DEFAULT 0",
        "final_registration_completed_at": "TEXT",
        "is_bhaskara_active": "INTEGER DEFAULT 0",
        "moved_to_late_pool": "INTEGER DEFAULT 0",
        "late_reporting_reason": "TEXT",
        "moved_to_late_pool_at": "TEXT",
    }
    for column, ddl_type in required_columns.items():
        if column not in existing:
            db.session.execute(text(f"ALTER TABLE token_booking ADD COLUMN {column} {ddl_type}"))
    db.session.commit()


def ensure_student_columns():
    rows = db.session.execute(text("PRAGMA table_info(student)")).fetchall()
    existing = {row[1] for row in rows}
    required_columns = {
        "otp_hash": "TEXT",
        "otp_expires_at": "TEXT",
        "otp_attempts": "INTEGER DEFAULT 0",
        "otp_verified": "INTEGER DEFAULT 0",
    }
    for column, ddl_type in required_columns.items():
        if column not in existing:
            db.session.execute(text(f"ALTER TABLE student ADD COLUMN {column} {ddl_type}"))
    db.session.commit()



# ---------------- PAGE ROUTES ---------------- #

@app.route("/")
def home():
    return render_template("login.html")

@app.route("/logout", methods=["POST", "GET"])
def logout():
    session.clear()
    if request.method == "GET":
        return render_template("login.html")
    return jsonify({"success": True})


@app.route("/forgot-password.html")
def forgot_password_page():
    return render_template("forgot-password.html")


def is_server_admin_authenticated():
    return bool(session.get("server_admin_authenticated"))


def get_server_admin_credential():
    return ServerAdminCredential.query.filter_by(email="admin@server.nitc.in").first()


@app.route("/server-admin", methods=["GET"])
def server_admin_page():
    authenticated = is_server_admin_authenticated()
    students = Student.query.order_by(Student.id.desc()).all() if authenticated else []
    return render_template(
        "server-admin.html",
        authenticated=authenticated,
        students=students,
        message=request.args.get("message", ""),
        error=request.args.get("error", ""),
    )


@app.route("/server-admin/login", methods=["POST"])
def server_admin_login():
    server_admin = get_server_admin_credential()
    if not server_admin:
        return redirect(url_for("server_admin_page", error="Server admin account is not available."))

    admin_id = (request.form.get("admin_id") or "").strip().lower()
    password = (request.form.get("password") or "").strip()

    if admin_id != (server_admin.email or "").lower() or not verify_user_password(server_admin.password, password):
        return redirect(url_for("server_admin_page", error="Invalid server admin credentials."))

    session["server_admin_authenticated"] = True
    session["server_admin_id"] = server_admin.email
    return redirect(url_for("server_admin_page", message="Server admin login successful."))


@app.route("/server-admin/logout", methods=["POST"])
def server_admin_logout():
    session.pop("server_admin_authenticated", None)
    session.pop("server_admin_id", None)
    return redirect(url_for("server_admin_page", message="Logged out from server admin panel."))


@app.route("/server-admin/students/add", methods=["POST"])
def server_admin_add_student():
    if not is_server_admin_authenticated():
        return redirect(url_for("server_admin_page", error="Please login as server admin first."))

    email = (request.form.get("email") or "").strip().lower()
    password = (request.form.get("password") or "").strip()
    if not email or not password:
        return redirect(url_for("server_admin_page", error="Student email and password are required."))

    existing = Student.query.filter_by(email=email).first()
    if existing:
        return redirect(url_for("server_admin_page", error=f"{email} already exists."))

    student = Student(email=email, password=generate_password_hash(password))
    db.session.add(student)
    db.session.commit()
    return redirect(url_for("server_admin_page", message=f"Added {email} to database."))


@app.route("/server-admin/students/remove", methods=["POST"])
def server_admin_remove_student():
    if not is_server_admin_authenticated():
        return redirect(url_for("server_admin_page", error="Please login as server admin first."))

    student_id = request.form.get("student_id", type=int)
    if not student_id:
        return redirect(url_for("server_admin_page", error="student_id is required."))

    student = Student.query.get(student_id)
    if not student:
        return redirect(url_for("server_admin_page", error="Student not found."))

    removed_email = student.email
    db.session.delete(student)
    db.session.commit()
    return redirect(url_for("server_admin_page", message=f"Removed {removed_email} from database."))


@app.route("/password/otp/request", methods=["POST"])
def request_password_otp():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    generic_message = "If the account exists, an OTP has been sent to the registered email."

    if not email:
        return jsonify({"success": True, "message": generic_message})

    student = Student.query.filter_by(email=email).first()
    if not student:
        # Generic response to avoid account enumeration.
        return jsonify({"success": True, "message": generic_message})

    otp = f"{secrets.randbelow(1000000):06d}"
    student.otp_hash = hash_otp(email, otp)
    student.otp_expires_at = (datetime.utcnow() + timedelta(minutes=10)).isoformat()
    student.otp_attempts = 0
    student.otp_verified = False
    db.session.commit()

    try:
        send_otp_email(email, otp)
    except Exception as exc:
        app.logger.exception("OTP email send failed: %s", exc)
        return jsonify({"success": True, "message": generic_message})

    return jsonify({"success": True, "message": generic_message})


@app.route("/password/otp/verify", methods=["POST"])
def verify_password_otp():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    otp = (data.get("otp") or "").strip()

    if not email or not otp:
        return jsonify({"success": False, "message": "Invalid OTP request."}), 400

    student = Student.query.filter_by(email=email).first()
    if not student or not student.otp_hash:
        return jsonify({"success": False, "message": "Invalid or expired OTP."}), 400

    expires_at = parse_iso_datetime(student.otp_expires_at)
    if not expires_at or datetime.utcnow() > expires_at:
        student.otp_hash = None
        student.otp_expires_at = None
        student.otp_attempts = 0
        student.otp_verified = False
        db.session.commit()
        return jsonify({"success": False, "message": "OTP has expired. Please request a new one."}), 400

    attempts = int(student.otp_attempts or 0)
    if attempts >= 5:
        student.otp_hash = None
        student.otp_expires_at = None
        student.otp_attempts = 0
        student.otp_verified = False
        db.session.commit()
        return jsonify({"success": False, "message": "Too many invalid attempts. Request a new OTP."}), 429

    if hash_otp(email, otp) != student.otp_hash:
        student.otp_attempts = attempts + 1
        db.session.commit()
        return jsonify({"success": False, "message": "Invalid or expired OTP."}), 400

    student.otp_verified = True
    student.otp_attempts = attempts
    db.session.commit()
    return jsonify({"success": True, "message": "OTP verified successfully."})


@app.route("/password/reset", methods=["POST"])
def reset_password():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    new_password = (data.get("new_password") or "").strip()
    otp = (data.get("otp") or "").strip()

    if not email or not new_password or not otp:
        return jsonify({"success": False, "message": "Email, OTP and new password are required."}), 400

    student = Student.query.filter_by(email=email).first()
    if not student:
        return jsonify({"success": False, "message": "Unable to reset password."}), 400
    if not student.otp_verified:
        return jsonify({"success": False, "message": "OTP verification is required before reset."}), 403
    if not student.otp_hash:
        return jsonify({"success": False, "message": "OTP is invalid or already used. Request a new OTP."}), 400

    expires_at = parse_iso_datetime(student.otp_expires_at)
    if not expires_at or datetime.utcnow() > expires_at:
        student.otp_hash = None
        student.otp_expires_at = None
        student.otp_attempts = 0
        student.otp_verified = False
        db.session.commit()
        return jsonify({"success": False, "message": "OTP has expired. Please request a new one."}), 400

    if hash_otp(email, otp) != student.otp_hash:
        student.otp_attempts = int(student.otp_attempts or 0) + 1
        db.session.commit()
        return jsonify({"success": False, "message": "Invalid OTP. Please verify again."}), 400

    # Password is hashed before storage.
    student.password = generate_password_hash(new_password)
    # Invalidate OTP after successful reset.
    student.otp_hash = None
    student.otp_expires_at = None
    student.otp_attempts = 0
    student.otp_verified = False
    db.session.commit()
    return jsonify({"success": True, "message": "Password reset successful. Please login."})

@app.route("/student.html")
def student_page():
    email = session.get("student_email")
    existing_booking = None
    if email:
        current = TokenBooking.query.filter_by(student_email=email).order_by(TokenBooking.id.desc()).first()
        if current:
            existing_booking = booking_to_view(current)
    final_admission_slip_url = None
    if existing_booking and existing_booking["final_registration_completed"]:
        final_admission_slip_url = url_for("final_registration_print_page", booking_id=existing_booking["id"])

    slot_rows = Slot.query.order_by(Slot.id.asc()).all()
    reporting_window = "Reporting window as per admission schedule"
    if slot_rows:
        reporting_window = f"Daily slots: {slot_rows[0].time} to {slot_rows[-1].time}"
    return render_template(
        "student.html",
        email=email,
        has_booking=existing_booking is not None,
        existing_booking=existing_booking,
        final_admission_slip_url=final_admission_slip_url,
        reporting_window=reporting_window,
    )

@app.route("/admin.html")
def admin_page():
    bookings = TokenBooking.query.filter_by(sent_to_chanakya=False, moved_to_late_pool=False).order_by(TokenBooking.id.asc()).all()
    quick_bookings = [booking_to_view(b) for b in bookings if (b.fee_status or "").lower() == "yes"]
    detailed_bookings = [booking_to_view(b) for b in bookings if (b.fee_status or "").lower() == "no"]
    metrics = default_dashboard_metrics()
    metrics["quick_waiting"] = len(quick_bookings)
    metrics["detailed_waiting"] = len(detailed_bookings)
    metrics["active_in_bhaskara"] = len(bookings)
    metrics["total_served"] = TokenBooking.query.filter_by(final_registration_completed=True).count()
    metrics["chanakya_pending"] = TokenBooking.query.filter_by(
        sent_to_chanakya=True,
        final_registration_completed=False,
        moved_to_late_pool=False
    ).count()
    metrics["late_pool_count"] = TokenBooking.query.filter_by(moved_to_late_pool=True).count()
    if bookings:
        total_minutes = sum(3 if (b.fee_status or "").lower() == "yes" else 6 for b in bookings)
        metrics["avg_processing_minutes"] = round(total_minutes / len(bookings))
    return render_template(
        "admin.html",
        quick_bookings=quick_bookings,
        detailed_bookings=detailed_bookings,
        metrics=metrics,
    )

@app.route("/book-token.html")
def book_token_page():
    email = session.get("student_email")
    slots = Slot.query.order_by(Slot.id.asc()).all()
    slot_data = [{"time": s.time, "capacity": s.capacity} for s in slots]
    existing_booking = None
    if email:
        current = TokenBooking.query.filter_by(student_email=email).order_by(TokenBooking.id.desc()).first()
        if current:
            existing_booking = booking_to_view(current)
    reporting_window = "Reporting window as per admission schedule"
    if slots:
        reporting_window = f"Daily slots: {slots[0].time} to {slots[-1].time}"
    return render_template(
        "book-token.html",
        email=email,
        slots=slot_data,
        existing_booking=existing_booking,
        reporting_window=reporting_window
    )
@app.route("/lateadmin.html")
def lateadmin_page():
    late_entries = TokenBooking.query.filter_by(moved_to_late_pool=True).order_by(TokenBooking.id.desc()).all()
    late_views = [booking_to_view(b) for b in late_entries]
    return render_template(
        "lateadmin.html",
        late_entries=late_views,
        late_count=len(late_views),
        latest_move_at=late_views[0]["moved_to_late_pool_at"] if late_views else "--",
    )

@app.route("/admin2.html")
def admin2_page():
    chanakya_queue = TokenBooking.query.filter_by(
        sent_to_chanakya=True,
        final_registration_completed=False,
        moved_to_late_pool=False
    ).order_by(TokenBooking.id.asc()).all()
    chanakya_bookings = [booking_to_view(b) for b in chanakya_queue]
    selected_booking_id = request.args.get("booking", type=int)
    active_booking = None
    if chanakya_bookings:
        active_booking = chanakya_bookings[0]
        if selected_booking_id is not None:
            for booking in chanakya_bookings:
                if booking["id"] == selected_booking_id:
                    active_booking = booking
                    break
    return render_template(
        "admin2.html",
        chanakya_bookings=chanakya_bookings,
        active_booking=active_booking,
        chanakya_pending_count=len(chanakya_bookings),
    )


@app.route("/final-registration-print/<int:booking_id>")
def final_registration_print_page(booking_id):
    booking = TokenBooking.query.get(booking_id)
    if not booking:
        return abort(404)

    admin_email = session.get("admin_email")
    student_email = session.get("student_email")
    if not admin_email:
        if not student_email or student_email != booking.student_email:
            return abort(403)
        if not booking.final_registration_completed:
            return abort(403)

    return render_template(
        "final-registration-print.html",
        booking=booking_to_view(booking),
        generated_at=booking.final_registration_completed_at or datetime.now().strftime("%d %b %Y, %I:%M %p"),
        generated_by=admin_email or "Admissions Office",
    )


@app.route("/complete-final-registration", methods=["POST"])
def complete_final_registration():
    if not session.get("admin_email"):
        return jsonify({"success": False, "message": "Admin login required."}), 401

    data = request.get_json(silent=True) or {}
    booking_id = data.get("booking_id")
    if not booking_id:
        return jsonify({"success": False, "message": "booking_id is required."}), 400

    booking = TokenBooking.query.get(booking_id)
    if not booking:
        return jsonify({"success": False, "message": "Booking not found."}), 404
    if booking.final_registration_completed:
        return jsonify({"success": False, "message": "Final registration is already completed for this student."}), 400
    if booking.moved_to_late_pool:
        return jsonify({"success": False, "message": "This profile is in late reporting pool."}), 400

    booking.final_registration_completed = True
    if not booking.final_registration_completed_at:
        booking.final_registration_completed_at = datetime.now().strftime("%d %b %Y, %I:%M %p")
    booking.is_bhaskara_active = False
    db.session.commit()

    return jsonify({
        "success": True,
        "message": "Final registration completed.",
        "print_url": url_for("final_registration_print_page", booking_id=booking.id),
    })


@app.route("/livestatus.html")
def livestatus_page():
    email = session.get("student_email")
    current_booking = None
    if email:
        current_booking = TokenBooking.query.filter_by(student_email=email).order_by(TokenBooking.id.desc()).first()

    queue = []
    if current_booking:
        queue = TokenBooking.query.filter_by(
            sent_to_chanakya=False,
            slot_time=current_booking.slot_time
        ).order_by(TokenBooking.id.asc()).all()

    now_serving = next((b for b in queue if b.is_bhaskara_active), None)
    if not now_serving and queue:
        now_serving = queue[0]

    upcoming_tokens = []
    if queue:
        now_index = 0
        if now_serving:
            for idx, booking in enumerate(queue):
                if booking.id == now_serving.id:
                    now_index = idx
                    break
        upcoming_tokens = [b.token_id for b in queue[now_index + 1: now_index + 6] if b.token_id]

    x_count = 0
    y_count = 0
    student_token = current_booking.token_id if current_booking else "--"

    if current_booking and queue:
        ahead = [b for b in queue if b.id < current_booking.id]
        x_count = sum(1 for b in ahead if (b.fee_status or "").lower() == "yes")
        y_count = sum(1 for b in ahead if (b.fee_status or "").lower() != "yes")

    students_ahead = x_count + y_count
    expected_time_minutes = (3 * x_count) + (6 * y_count)

    total_today = len(queue)
    served_count = 0
    if now_serving:
        served_count = sum(1 for b in queue if b.id <= now_serving.id)
    hall_progress = round((served_count / total_today) * 100) if total_today else 0

    return render_template(
        "livestatus.html",
        email=email,
        now_serving_token=now_serving.token_id if now_serving and now_serving.token_id else "--",
        student_token=student_token,
        upcoming_tokens=upcoming_tokens,
        x_count=x_count,
        y_count=y_count,
        students_ahead=students_ahead,
        expected_time_minutes=expected_time_minutes,
        hall_progress=hall_progress,
        updated_label="Live",
    )


@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    if not session.get("admin_email"):
        abort(403)
    return send_from_directory(UPLOAD_DIR, filename, as_attachment=False)

# @app.route("/success-token.html")
# def success_token():
#     email = session.get("student_email")
#     return render_template("success-token.html", email=email)


@app.route("/set-40")
def set_40():

    slots = Slot.query.all()

    for s in slots:
        s.capacity = 40

    db.session.commit()

    return "All slots set to 40"
 
@app.route("/success-token.html")
def success_token():

    email = session.get("student_email")
    booking = session.get("booking")
    queue_stats = {"students_ahead": 0, "expected_time_minutes": 0}
    latest = None
    if email:
        latest = TokenBooking.query.filter_by(student_email=email).order_by(TokenBooking.id.desc()).first()

    if not booking and latest:
        identity = parse_identity_from_email(email)
        booking = {
            "slot": latest.slot_time,
            "token": latest.token_id,
            "fee": latest.fee_status,
            "payment": latest.payment_mode,
            "qr_payload": build_qr_payload(latest.token_id, identity["roll_no"], latest.slot_time),
        }

    if latest:
        slot_queue = TokenBooking.query.filter_by(sent_to_chanakya=False, slot_time=latest.slot_time).order_by(TokenBooking.id.asc()).all()
        ahead = [b for b in slot_queue if b.id < latest.id]
        x_count = sum(1 for b in ahead if (b.fee_status or "").lower() == "yes")
        y_count = sum(1 for b in ahead if (b.fee_status or "").lower() != "yes")
        queue_stats["students_ahead"] = x_count + y_count
        queue_stats["expected_time_minutes"] = (3 * x_count) + (6 * y_count)

    return render_template(
        "success-token.html",
        email=email,
        booking=booking,
        queue_stats=queue_stats,
    )


@app.route("/proceed-to-chanakya", methods=["POST"])
def proceed_to_chanakya():
    if not session.get("admin_email"):
        return jsonify({"success": False, "message": "Admin login required."}), 401

    data = request.get_json(silent=True) or {}
    booking_id = data.get("booking_id")
    admin1_notes = (data.get("admin1_notes") or "").strip()
    if not booking_id:
        return jsonify({"success": False, "message": "booking_id is required."}), 400

    booking = TokenBooking.query.get(booking_id)
    if not booking:
        return jsonify({"success": False, "message": "Booking not found."}), 404
    if booking.moved_to_late_pool:
        return jsonify({"success": False, "message": "Selected booking is already in late reporting pool."}), 400

    booking.sent_to_chanakya = True
    booking.is_bhaskara_active = False
    booking.admin1_notes = admin1_notes
    db.session.commit()
    return jsonify({"success": True, "message": "Student moved to Chanakya queue."})


@app.route("/move-to-late-reporting", methods=["POST"])
def move_to_late_reporting():
    if not session.get("admin_email"):
        return jsonify({"success": False, "message": "Admin login required."}), 401

    data = request.get_json(silent=True) or {}
    booking_id = data.get("booking_id")
    reason = (data.get("reason") or "").strip()
    if not booking_id:
        return jsonify({"success": False, "message": "booking_id is required."}), 400
    if not reason:
        return jsonify({"success": False, "message": "Reason is required."}), 400

    booking = TokenBooking.query.get(booking_id)
    if not booking:
        return jsonify({"success": False, "message": "Booking not found."}), 404
    if booking.final_registration_completed:
        return jsonify({"success": False, "message": "Cannot move a completed registration to late pool."}), 400

    booking.moved_to_late_pool = True
    booking.late_reporting_reason = reason
    booking.moved_to_late_pool_at = datetime.now().strftime("%d %b %Y, %I:%M %p")
    booking.is_bhaskara_active = False
    booking.sent_to_chanakya = True
    db.session.commit()
    return jsonify({"success": True, "message": "Student moved to late reporting pool."})


@app.route("/set-bhaskara-active", methods=["POST"])
def set_bhaskara_active():
    if not session.get("admin_email"):
        return jsonify({"success": False, "message": "Admin login required."}), 401

    data = request.get_json(silent=True) or {}
    booking_id = data.get("booking_id")
    if not booking_id:
        return jsonify({"success": False, "message": "booking_id is required."}), 400

    booking = TokenBooking.query.get(booking_id)
    if not booking:
        return jsonify({"success": False, "message": "Booking not found."}), 404
    if booking.sent_to_chanakya:
        return jsonify({"success": False, "message": "Selected booking is already moved to Chanakya."}), 400
    if booking.moved_to_late_pool:
        return jsonify({"success": False, "message": "Selected booking is in late reporting pool."}), 400

    TokenBooking.query.update({"is_bhaskara_active": False})
    booking.is_bhaskara_active = True
    db.session.commit()
    return jsonify({
        "success": True,
        "message": "Now serving token updated.",
        "token_id": booking.token_id,
        "slot_time": booking.slot_time
    })


@app.route("/reject-booking", methods=["POST"])
def reject_booking():
    if not session.get("admin_email"):
        return jsonify({"success": False, "message": "Admin login required."}), 401

    data = request.get_json(silent=True) or {}
    booking_id = data.get("booking_id")
    if not booking_id:
        return jsonify({"success": False, "message": "booking_id is required."}), 400

    booking = TokenBooking.query.get(booking_id)
    if not booking:
        return jsonify({"success": False, "message": "Booking not found."}), 404

    booking.is_bhaskara_active = False

    slot_obj = Slot.query.filter_by(time=booking.slot_time).first()
    if slot_obj:
        slot_obj.capacity += capacity_units_for_fee(booking.fee_status)

    for doc_name in [booking.class10_doc, booking.class12_doc, booking.category_doc, booking.paid_receipt_doc]:
        if not doc_name:
            continue
        path = os.path.join(UPLOAD_DIR, doc_name)
        if os.path.exists(path):
            os.remove(path)

    db.session.delete(booking)
    db.session.commit()
    return jsonify({"success": True, "message": "Profile rejected and booking removed."})



# ---------------- LOGIN API ---------------- #

@app.route("/login", methods=["POST"])
def login():

    data = request.get_json()

    role = data.get("role")
    email = data.get("email").strip()
    password = data.get("password").strip()

    # -------- STUDENT LOGIN -------- #
    if role == "student":
        user = Student.query.filter_by(email=email).first()
        if user and verify_user_password(user.password, password):
            session["student_email"] = email   # ⭐ STORE EMAIL
            return jsonify({"success":True,"redirect":"student.html"})

        return jsonify({"success":False,"message":"Invalid student login"})

    # -------- ADMIN LOGIN -------- #
    if role == "admin":
        hall_role = (data.get("hallRole") or data.get("hall_role") or "").strip().lower()
        user = Admin.query.filter_by(
            email=email,
            password=password
        ).first()

        if user:
            session["admin_email"] = email
            session["admin_hall_role"] = hall_role
            redirect_page = "admin2.html" if hall_role == "chanakya" else "admin.html"
            return jsonify({"success":True,"redirect":redirect_page})

        return jsonify({"success":False,"message":"Invalid admin login"})

    return jsonify({"success":False,"message":"Invalid role"})

#---------------------Booking API-----------------------#
@app.route("/submit-booking", methods=["POST"])
def submit_booking():
    data = request.get_json(silent=True) or {}
    slot = request.form.get("slot") or data.get("slot")
    fee = request.form.get("fee") or data.get("fee")
    payment = request.form.get("payment") or data.get("payment")
    class10_file = request.files.get("docClass10")
    class12_file = request.files.get("docClass12")
    category_file = request.files.get("docCategory")
    paid_receipt_file = request.files.get("paidReceipt")

    email = session.get("student_email")

    if not email:
        return jsonify({"success": False, "message": "Please login as student first."})

    if fee not in ["yes", "no"]:
        return jsonify({"success": False, "message": "Invalid fee status."})

    if not slot:
        return jsonify({"success": False, "message": "Slot is required."})

    if fee == "no" and not payment:
        return jsonify({"success": False, "message": "Payment mode is required for unpaid fee."})
    if fee == "yes" and not paid_receipt_file:
        return jsonify({"success": False, "message": "Fee receipt is required for paid candidates."})

    if not class10_file or not class12_file:
        return jsonify({"success": False, "message": "Class 10 and Class 12 documents are required."})

    existing_booking = TokenBooking.query.filter_by(student_email=email).first()
    if existing_booking:
        return jsonify({
            "success": False,
            "message": f"You already booked a slot ({existing_booking.slot_time}). Multiple bookings are not allowed."
        })

    slot_obj = Slot.query.filter_by(time=slot).first()
    if not slot_obj:
        return jsonify({"success": False, "message": "Invalid slot selected."})
    needed_capacity = capacity_units_for_fee(fee)
    if slot_obj.capacity < needed_capacity:
        return jsonify({"success": False, "message": "Selected slot is full. Please choose another slot."})

    token_id = generate_token_id()
    class10_name = save_uploaded_file(class10_file, email, "class10")
    class12_name = save_uploaded_file(class12_file, email, "class12")
    category_name = save_uploaded_file(category_file, email, "category")
    receipt_name = save_uploaded_file(paid_receipt_file, email, "receipt")

    booking = TokenBooking(
        student_email=email,
        fee_status=fee,
        payment_mode=payment if fee == "no" else "already-paid",
        slot_time=slot,
        token_id=token_id,
        class10_doc=class10_name,
        class12_doc=class12_name,
        category_doc=category_name,
        paid_receipt_doc=receipt_name,
        sent_to_chanakya=False
    )
    slot_obj.capacity -= needed_capacity
    db.session.add(booking)
    db.session.commit()

    # store lightweight data in session for success page
    session["booking"] = {
        "slot": slot,
        "token": token_id,
        "fee": fee,
        "payment": payment if fee == "no" else "already-paid",
        "qr_payload": build_qr_payload(token_id, parse_identity_from_email(email)["roll_no"], slot),
    }

    return jsonify({
        "success": True,
        "redirect": "/success-token.html"
    })

# ---------------- INIT DB ---------------- #

with app.app_context():
    db.create_all()
    # ensure_tokenbooking_columns()
    # ensure_student_columns()
    if not get_server_admin_credential():
        # Default server admin account seeded in DB (password hashed).
        db.session.add(
            ServerAdminCredential(
                email="admin@server.nitc.in",
                password=generate_password_hash("kp@1234")
            )
        )
        db.session.commit()
    slots = Slot.query.all()

    if not slots:
        slots = [
            Slot(time="9:00 AM - 10:00 AM", capacity=40),
            Slot(time="10:00 AM - 11:00 AM", capacity=40),
            Slot(time="11:00 AM - 12:00 PM", capacity=40),
            Slot(time="12:00 PM - 1:00 PM", capacity=40),
            Slot(time="1:00 PM - 2:00 PM", capacity=40),
            Slot(time="2:00 PM - 3:00 PM", capacity=40),
            Slot(time="3:00 PM - 4:00 PM", capacity=40),
            Slot(time="4:00 PM - 5:00 PM", capacity=40),
        ]
        db.session.add_all(slots)
        db.session.commit()



# ---------------- RUN ---------------- #

if __name__ == "__main__":
    app.run()
