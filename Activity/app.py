from flask import Flask, request, jsonify, session, render_template, redirect, url_for, flash, send_from_directory, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
from datetime import datetime
import logging
from sqlalchemy import and_
import pandas as pd


logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'  # Change this to a secure secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:1234@localhost/activity_points_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Create uploads directory if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg'}

ALLOWED_EXTENSIONS.add('csv')
ALLOWED_EXTENSIONS.add('xlsx')

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Models
class Student(UserMixin, db.Model):
    usn = db.Column(db.String(20), primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    branch = db.Column(db.String(50))
    year = db.Column(db.Integer)
    course_id = db.Column(db.String(20))
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255))
    events = db.relationship('StudentEvent', backref='student', lazy=True)
    certificates = db.relationship('Certificate', backref='student', lazy=True)
    clubs = db.relationship('StudentClub', backref='student', lazy=True)

    def get_id(self):
        return f"STU_{self.usn}"

class Club(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    core_team = db.Column(db.String(255))
    club_head = db.Column(db.String(100))
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255))
    events = db.relationship('Event', backref='club', lazy=True)

    def get_id(self):
        return f"CLB_{self.id}"

class Counsellor(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    branch = db.Column(db.String(50))
    batch = db.Column(db.String(20))
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255))
    verified_certificates = db.relationship('Certificate', backref='counsellor', lazy=True)

    def get_id(self):
        return f"CNS_{self.id}"

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    date = db.Column(db.Date, nullable=False)
    place = db.Column(db.String(100))
    participants = db.Column(db.Integer)
    points = db.Column(db.Integer, nullable=False)  # Added points field
    club_id = db.Column(db.Integer, db.ForeignKey('club.id'))
    student_events = db.relationship('StudentEvent', backref='event', lazy=True)
    certificates = db.relationship('Certificate', backref='event', lazy=True)

class Certificate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    usn = db.Column(db.String(20), db.ForeignKey('student.usn'))
    activity_points = db.Column(db.Integer)
    counsellor_id = db.Column(db.Integer, db.ForeignKey('counsellor.id'))
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'))
    file_path = db.Column(db.String(255))
    verified = db.Column(db.Boolean, default=False)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)

class StudentClub(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    usn = db.Column(db.String(20), db.ForeignKey('student.usn'))
    club_id = db.Column(db.Integer, db.ForeignKey('club.id'))

class StudentEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    usn = db.Column(db.String(20), db.ForeignKey('student.usn'))
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'))
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    certificate_id = db.Column(db.Integer, db.ForeignKey('certificate.id'), nullable=False)
    sender_type = db.Column(db.String(20), nullable=False)  # 'student' or 'counsellor'
    sender_id = db.Column(db.String(50), nullable=False)  # USN for students, ID for counsellors
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    certificate = db.relationship('Certificate', backref='messages')
    
class CounselorStudent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    counselor_id = db.Column(db.Integer, db.ForeignKey('counsellor.id'), nullable=False)
    student_usn = db.Column(db.String(20), db.ForeignKey('student.usn'), nullable=False)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    
    __table_args__ = (db.UniqueConstraint('counselor_id', 'student_usn', name='unique_counselor_student'),)

Counsellor.students = db.relationship('Student', 
                                    secondary='counselor_student',
                                    backref=db.backref('counselors', lazy='dynamic'))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def validate_participants_file(file_path, expected_participants):
    """
    Validate the uploaded participants file
    Returns (success, message, usn_list)
    """
    try:
        # Read file based on extension
        if file_path.endswith('.csv'):
            df = pd.read_csv(file_path)
        else:  # xlsx
            df = pd.read_excel(file_path)
        
        # Check if 'usn' column exists
        if 'usn' not in df.columns:
            return False, "File must contain a 'usn' column", None
            
        # Get unique USNs
        usn_list = df['usn'].unique().tolist()
        
        # Check number of participants
        if len(usn_list) > expected_participants:
            return False, f"Number of USNs ({len(usn_list)}) exceeds expected participants ({expected_participants})", None
            
        # Verify all USNs exist in the database
        existing_usns = set(Student.query.with_entities(Student.usn).all())
        invalid_usns = [usn for usn in usn_list if (usn,) not in existing_usns]
        
        if invalid_usns:
            return False, f"Following USNs not found in database: {', '.join(invalid_usns)}", None
            
        return True, "File validated successfully", usn_list
        
    except Exception as e:
        return False, f"Error processing file: {str(e)}", None

@login_manager.user_loader
def load_user(user_id):
    if user_id.startswith('STU_'):
        return Student.query.get(user_id[4:])
    elif user_id.startswith('CLB_'):
        return Club.query.get(int(user_id[4:]))
    elif user_id.startswith('CNS_'):
        return Counsellor.query.get(int(user_id[4:]))
    return None

@app.route('/')
def index():
    return render_template('index.html')

# Updated signup route in app.py
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        try:
            # Log all form data for debugging
            logger.debug("Form Data: %s", request.form)
            
            user_type = request.form.get('user_type')
            email = request.form.get('email')
            password = request.form.get('password')
            
            if not all([user_type, email, password]):
                flash('Missing required fields')
                return redirect(url_for('signup'))

            # Check for existing email across all user types
            if Student.query.filter_by(email=email).first() or \
               Club.query.filter_by(email=email).first() or \
               Counsellor.query.filter_by(email=email).first():
                flash('Email already registered')
                return redirect(url_for('signup'))

            password_hash = generate_password_hash(password)
            
            if user_type == 'student':
                # Log student-specific fields
                logger.debug("Creating student with USN: %s, Name: %s", 
                           request.form.get('usn'), 
                           request.form.get('studentName'))
                
                if not request.form.get('usn'):
                    flash('USN is required')
                    return redirect(url_for('signup'))
                    
                user = Student(
                    usn=request.form.get('usn'),
                    name=request.form.get('studentName'),
                    branch=request.form.get('branch'),
                    year=int(request.form.get('year')) if request.form.get('year') else None,
                    course_id=request.form.get('course_id'),
                    email=email,
                    password_hash=password_hash
                )
            elif user_type == 'club':
                # Log club-specific fields
                logger.debug("Creating club with Name: %s", request.form.get('clubName'))
                
                if not request.form.get('clubName'):
                    flash('Club name is required')
                    return redirect(url_for('signup'))
                    
                user = Club(
                    name=request.form.get('clubName'),
                    core_team=request.form.get('coreTeam'),
                    club_head=request.form.get('clubHead'),
                    email=email,
                    password_hash=password_hash
                )
            elif user_type == 'counsellor':
                # Log counsellor-specific fields
                logger.debug("Creating counsellor with Name: %s", 
                           request.form.get('counsellorName'))
                
                if not request.form.get('counsellorName'):
                    flash('Counsellor name is required')
                    return redirect(url_for('signup'))
                    
                user = Counsellor(
                    name=request.form.get('counsellorName'),
                    branch=request.form.get('counsellorBranch'),
                    batch=request.form.get('batch'),
                    email=email,
                    password_hash=password_hash
                )
            else:
                flash('Invalid user type')
                return redirect(url_for('signup'))
            
            logger.debug("About to add user to database")
            db.session.add(user)
            db.session.commit()
            logger.debug("User added successfully")
            
            flash('Registration successful!')
            return redirect(url_for('login'))
            
        except Exception as e:
            logger.error("Error during signup: %s", str(e), exc_info=True)
            db.session.rollback()
            flash(f'Registration failed: {str(e)}')
            return redirect(url_for('signup'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user_type = request.form.get('user_type')
        email = request.form.get('email')
        password = request.form.get('password')

        if not all([user_type, email, password]):
            flash('Please fill in all fields')
            return render_template('login.html')

        user = None
        if user_type == 'student':
            user = Student.query.filter_by(email=email).first()
        elif user_type == 'counsellor':
            user = Counsellor.query.filter_by(email=email).first()
        elif user_type == 'club':
            user = Club.query.filter_by(email=email).first()

        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            if isinstance(user, Student):
                return redirect(url_for('student_dashboard'))
            elif isinstance(user, Counsellor):
                return redirect(url_for('counsellor_dashboard'))
            else:
                return redirect(url_for('club_dashboard'))

        flash('Invalid email or password')
    return render_template('login.html')

@app.route('/student/dashboard')
@login_required
def student_dashboard():
    if not isinstance(current_user, Student):
        return redirect(url_for('login'))
    
    certificates = Certificate.query\
        .filter_by(usn=current_user.usn)\
        .order_by(Certificate.upload_date.desc())\
        .all()
    
    # Get events the student is registered for, excluding those with verified certificates
    registered_events = db.session.query(
        Event,
        Club.name.label('club_name'),
        StudentEvent.date_added
    ).join(
        StudentEvent, Event.id == StudentEvent.event_id
    ).join(
        Club, Event.club_id == Club.id
    ).filter(
        and_(
            StudentEvent.usn == current_user.usn,
            ~Event.id.in_(
                db.session.query(Certificate.event_id)
                .filter(
                    and_(
                        Certificate.usn == current_user.usn,
                        Certificate.verified == True
                    )
                )
            )
        )
    ).order_by(
        Event.date.desc()
    ).all()
    
    total_points = sum(cert.activity_points or 0 for cert in certificates if cert.verified)
    
    return render_template('student_dashboard.html',
                         certificates=certificates,
                         events=registered_events,
                         total_points=total_points)

@app.route('/student/upload_certificate', methods=['POST'])
@login_required
def upload_certificate():
    if not isinstance(current_user, Student):
        return redirect(url_for('login'))

    file = request.files.get('certificate')
    event_id = request.form.get('event_id')
    
    if not file or not event_id:
        flash('Please provide both certificate and event')
        return redirect(url_for('student_dashboard'))

    # Check if a verified certificate already exists for this event
    existing_cert = Certificate.query.filter(
        and_(
            Certificate.usn == current_user.usn,
            Certificate.event_id == event_id,
            Certificate.verified == True
        )
    ).first()

    if existing_cert:
        flash('A verified certificate already exists for this event')
        return redirect(url_for('student_dashboard'))
        
    if file and allowed_file(file.filename):
        try:
            filename = secure_filename(f"{current_user.usn}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{file.filename}")
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            
            event = Event.query.get(event_id)
            if not event:
                flash('Event not found')
                return redirect(url_for('student_dashboard'))
            
            certificate = Certificate(
                name=filename,
                usn=current_user.usn,
                event_id=event_id,
                file_path=file_path,
                activity_points=event.points
            )
            db.session.add(certificate)
            db.session.commit()
            
            flash('Certificate uploaded successfully')
        except Exception as e:
            flash('Error uploading certificate')
    else:
        flash('Invalid file type')
        
    return redirect(url_for('student_dashboard'))

# Add this new route to your Flask application
@app.route('/counsellor/dashboard')
@login_required
def counsellor_dashboard():
    if not isinstance(current_user, Counsellor):
        return redirect(url_for('login'))
        
    # Get certificates only from assigned students
    pending_certificates = Certificate.query\
        .join(Student)\
        .join(Event)\
        .join(CounselorStudent, Certificate.usn == CounselorStudent.student_usn)\
        .filter(
            Certificate.verified == False,
            CounselorStudent.counselor_id == current_user.id
        )\
        .add_columns(
            Student.name.label('student_name'),
            Student.usn.label('student_usn'),
            Event.name.label('event_name'),
            Event.points.label('event_points')
        ).all()
        
    return render_template('counsellor_dashboard.html',
                         pending_certificates=pending_certificates)
    
@app.route('/counsellor/manage_students')
@login_required
def manage_students():
    if not isinstance(current_user, Counsellor):
        return redirect(url_for('login'))
        
    # Get all students assigned to this counselor
    assigned_students = db.session.query(Student)\
        .join(CounselorStudent)\
        .filter(CounselorStudent.counselor_id == current_user.id)\
        .all()
        
    return render_template('manage_students.html',
                         assigned_students=assigned_students)

@app.route('/counsellor/add_student', methods=['POST'])
@login_required
def add_student():
    if not isinstance(current_user, Counsellor):
        return jsonify({'error': 'Unauthorized'}), 403
        
    usn = request.form.get('usn')
    
    if not usn:
        flash('Please provide a USN')
        return redirect(url_for('manage_students'))
        
    try:
        # Check if student exists
        student = Student.query.filter_by(usn=usn).first()
        if not student:
            flash('Student not found')
            return redirect(url_for('manage_students'))
            
        # Check if student is already assigned
        existing = CounselorStudent.query.filter_by(
            counselor_id=current_user.id,
            student_usn=usn
        ).first()
        
        if existing:
            flash('Student already assigned to you')
            return redirect(url_for('manage_students'))
            
        # Add new assignment
        assignment = CounselorStudent(
            counselor_id=current_user.id,
            student_usn=usn
        )
        db.session.add(assignment)
        db.session.commit()
        
        flash('Student added successfully')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error adding student: {str(e)}')
        
    return redirect(url_for('manage_students'))

@app.route('/counsellor/upload_students', methods=['POST'])
@login_required
def upload_students():
    if not isinstance(current_user, Counsellor):
        return jsonify({'error': 'Unauthorized'}), 403
        
    if 'file' not in request.files:
        flash('No file uploaded')
        return redirect(url_for('manage_students'))
        
    file = request.files['file']
    if file.filename == '':
        flash('No file selected')
        return redirect(url_for('manage_students'))
        
    if not allowed_file(file.filename):
        flash('Invalid file type')
        return redirect(url_for('manage_students'))
        
    try:
        # Save file temporarily
        filename = secure_filename(file.filename)
        temp_path = os.path.join(app.config['UPLOAD_FOLDER'], 'temp_' + filename)
        file.save(temp_path)
        
        # Read file
        if filename.endswith('.csv'):
            df = pd.read_csv(temp_path)
        else:  # xlsx
            df = pd.read_excel(temp_path)
            
        # Verify file has required column
        if 'usn' not in df.columns:
            flash('File must contain a "usn" column')
            os.remove(temp_path)
            return redirect(url_for('manage_students'))
            
        # Get unique USNs
        usn_list = df['usn'].unique().tolist()
        
        # Verify all USNs exist
        existing_usns = set(Student.query.with_entities(Student.usn).all())
        invalid_usns = [usn for usn in usn_list if (usn,) not in existing_usns]
        
        if invalid_usns:
            flash(f'Following USNs not found: {", ".join(invalid_usns)}')
            os.remove(temp_path)
            return redirect(url_for('manage_students'))
            
        # Add students
        added_count = 0
        for usn in usn_list:
            # Check if already assigned
            if not CounselorStudent.query.filter_by(
                counselor_id=current_user.id,
                student_usn=usn
            ).first():
                assignment = CounselorStudent(
                    counselor_id=current_user.id,
                    student_usn=usn
                )
                db.session.add(assignment)
                added_count += 1
                
        db.session.commit()
        flash(f'Successfully added {added_count} students')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error processing file: {str(e)}')
        
    finally:
        # Clean up temporary file
        if os.path.exists(temp_path):
            os.remove(temp_path)
            
    return redirect(url_for('manage_students'))
    
@app.route('/counsellor/reject_certificate/<int:cert_id>', methods=['POST'])
@login_required
def reject_certificate(cert_id):
    if not isinstance(current_user, Counsellor):
        return redirect(url_for('login'))

    certificate = Certificate.query.get_or_404(cert_id)
    
    try:
        certificate.verified = False
        certificate.activity_points = 0
        certificate.counsellor_id = current_user.id
        db.session.commit()
        flash('Certificate rejected')
    except Exception as e:
        db.session.rollback()
        flash('Error rejecting certificate')
    
    return redirect(url_for('counsellor_dashboard'))

# Add a new route for viewing certificates
@app.route('/student/view_certificate/<int:certificate_id>')
@login_required
def view_certificate(certificate_id):
    if not isinstance(current_user, Student):
        return redirect(url_for('login'))
        
    certificate = Certificate.query.get_or_404(certificate_id)
    
    # Security check - only allow viewing own certificates
    if certificate.usn != current_user.usn:
        abort(403)
    
    filename = os.path.basename(certificate.file_path)
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    
@app.route('/counsellor/view_certificate/<int:cert_id>')
@login_required
def counsellor_view_certificate(cert_id):
    if not isinstance(current_user, Counsellor):
        return redirect(url_for('login'))
        
    certificate = Certificate.query.get_or_404(cert_id)
    
    # Get the filename from the file_path
    filename = os.path.basename(certificate.file_path)
    
    # Return the file from the UPLOAD_FOLDER
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/counsellor/verify_certificate/<int:cert_id>', methods=['POST'])
@login_required
def verify_certificate(cert_id):
    if not isinstance(current_user, Counsellor):
        return redirect(url_for('login'))

    certificate = Certificate.query.get_or_404(cert_id)
    points = request.form.get('points', type=int)
    
    if points is None:
        flash('Please provide points')
        return redirect(url_for('counsellor_dashboard'))
    
    try:
        certificate.verified = True
        certificate.activity_points = points
        certificate.counsellor_id = current_user.id
        db.session.commit()
        flash('Certificate verified and points assigned')
    except Exception as e:
        db.session.rollback()
        flash('Error verifying certificate')
    
    return redirect(url_for('counsellor_dashboard'))

@app.route('/club/dashboard')
@login_required
def club_dashboard():
    if not isinstance(current_user, Club):
        return redirect(url_for('login'))
    
    events = Event.query.filter_by(club_id=current_user.id)\
        .order_by(Event.date.desc())\
        .all()
    
    return render_template('club_dashboard.html',
                         club=current_user,
                         events=events)

@app.route('/club/create_event', methods=['POST'])
@login_required
def create_event():
    if not isinstance(current_user, Club):
        return redirect(url_for('login'))

    try:
        event_date = datetime.strptime(request.form.get('date'), '%Y-%m-%d')
        points = request.form.get('points', type=int)
        
        if not points or points < 0:
            flash('Please provide valid points')
            return redirect(url_for('club_dashboard'))
        
        event = Event(
            name=request.form.get('name'),
            date=event_date,
            place=request.form.get('place'),
            participants=request.form.get('participants', type=int),
            points=points,
            club_id=current_user.id
        )
        
        db.session.add(event)
        db.session.commit()
        flash('Event created successfully')
        
    except Exception as e:
        db.session.rollback()
        flash('Error creating event')
    
    return redirect(url_for('club_dashboard'))

@app.route('/club/add_participant', methods=['POST'])
@login_required
def add_participant():
    if not isinstance(current_user, Club):
        return redirect(url_for('login'))
        
    try:
        usn = request.form.get('usn')
        event_id = request.form.get('event_id')
        
        # Check if student exists
        student = Student.query.filter_by(usn=usn).first()
        if not student:
            flash('Student not found')
            return redirect(url_for('club_dashboard'))
            
        # Check if student is already added to event
        existing_entry = StudentEvent.query.filter_by(usn=usn, event_id=event_id).first()
        if existing_entry:
            flash('Student already added to this event')
            return redirect(url_for('club_dashboard'))
        
        student_event = StudentEvent(
            usn=usn,
            event_id=event_id
        )
        
        db.session.add(student_event)
        db.session.commit()
        flash('Participant added successfully')
        
    except Exception as e:
        db.session.rollback()
        flash('Error adding participant')
        
    return redirect(url_for('club_dashboard'))

@app.route('/club/upload_participants/<int:event_id>', methods=['POST'])
@login_required
def upload_participants(event_id):
    if not isinstance(current_user, Club):
        return jsonify({'error': 'Unauthorized'}), 403
        
    try:
        # Check if event exists and belongs to current club
        event = Event.query.filter_by(id=event_id, club_id=current_user.id).first()
        if not event:
            return jsonify({'error': 'Event not found'}), 404
            
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
            
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
            
        if not file or not allowed_file(file.filename):
            return jsonify({'error': 'Invalid file type'}), 400
            
        # Save file temporarily
        filename = secure_filename(file.filename)
        temp_path = os.path.join(app.config['UPLOAD_FOLDER'], 'temp_' + filename)
        file.save(temp_path)
        
        # Validate file contents
        success, message, usn_list = validate_participants_file(temp_path, event.participants)
        
        # Delete temporary file
        os.remove(temp_path)
        
        if not success:
            return jsonify({'error': message}), 400
            
        # Add participants to database
        added_count = 0
        for usn in usn_list:
            # Check if student is already registered
            if not StudentEvent.query.filter_by(usn=usn, event_id=event_id).first():
                student_event = StudentEvent(usn=usn, event_id=event_id)
                db.session.add(student_event)
                added_count += 1
                
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'Successfully added {added_count} participants',
            'total_usns': len(usn_list)
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/get_messages/<int:certificate_id>')
@login_required
def get_messages(certificate_id):
    certificate = Certificate.query.get_or_404(certificate_id)
    
    # Security check - only allow access to relevant users
    if isinstance(current_user, Student):
        if certificate.usn != current_user.usn:
            abort(403)
    elif isinstance(current_user, Counsellor):
        # Counsellors can see all messages
        pass
    else:
        abort(403)
        
    messages = Message.query.filter_by(certificate_id=certificate_id)\
        .order_by(Message.timestamp.asc())\
        .all()
        
    messages_data = []
    for msg in messages:
        if msg.sender_type == 'student':
            sender = Student.query.filter_by(usn=msg.sender_id).first()
            sender_name = sender.name if sender else 'Unknown Student'
        else:
            sender = Counsellor.query.get(int(msg.sender_id))
            sender_name = sender.name if sender else 'Unknown Counsellor'
            
        messages_data.append({
            'id': msg.id,
            'content': msg.content,
            'sender_name': sender_name,
            'sender_type': msg.sender_type,
            'timestamp': msg.timestamp.strftime('%Y-%m-%d %H:%M:%S')
        })
    
    return jsonify(messages_data)

@app.route('/send_message/<int:certificate_id>', methods=['POST'])
@login_required
def send_message(certificate_id):
    certificate = Certificate.query.get_or_404(certificate_id)
    content = request.form.get('content')
    
    if not content:
        return jsonify({'error': 'Message content is required'}), 400
        
    # Security check and sender type determination
    if isinstance(current_user, Student):
        if certificate.usn != current_user.usn:
            abort(403)
        sender_type = 'student'
        sender_id = current_user.usn
    elif isinstance(current_user, Counsellor):
        sender_type = 'counsellor'
        sender_id = str(current_user.id)
    else:
        abort(403)
        
    message = Message(
        certificate_id=certificate_id,
        sender_type=sender_type,
        sender_id=sender_id,
        content=content
    )
    
    try:
        db.session.add(message)
        db.session.commit()
        return jsonify({
            'success': True,
            'message': {
                'id': message.id,
                'content': message.content,
                'sender_name': current_user.name,
                'sender_type': sender_type,
                'timestamp': message.timestamp.strftime('%Y-%m-%d %H:%M:%S')
            }
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully')
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)