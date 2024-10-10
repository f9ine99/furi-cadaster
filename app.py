from flask import Flask, render_template, request, redirect, url_for, session, make_response, flash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from models import db, Order
from models import db, workerSession
from models import db, WorkerActivityLog
from datetime import datetime, timedelta
import logging
from logging.handlers import RotatingFileHandler
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import re
import bcrypt
import hashlib
import bcrypt
from flask import request, abort
from sqlalchemy import func


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///orders.db'
app.secret_key = '3312211033122110'  # Change this to a strong secret key
db.init_app(app)
migrate = Migrate(app, db)

# Set up logging for user orders
order_log_handler = RotatingFileHandler('order_logs.log', maxBytes=10000, backupCount=1)
order_log_handler.setLevel(logging.INFO)
order_log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
order_log_handler.setFormatter(order_log_formatter)
order_logger = logging.getLogger('order_logger')
order_logger.setLevel(logging.INFO)
order_logger.addHandler(order_log_handler)

# Set up logging for admin PIN login attempts
workers_log_handler = RotatingFileHandler('workers.log', maxBytes=10000, backupCount=1)
workers_log_handler.setLevel(logging.INFO)
workers_log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
workers_log_handler.setFormatter(workers_log_formatter)
workers_logger = logging.getLogger('workers_logger')
workers_logger.setLevel(logging.INFO)
workers_logger.addHandler(workers_log_handler)

# Set up Flask-Limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri='memory://'
)


@app.before_request
def block_suspicious_user_agents():
    user_agent = request.headers.get('User-Agent')
    if not user_agent or "bot" in user_agent.lower():
        abort(403)  # Forbid the request


@app.route('/')
def index():
    return render_template('search.html')

#####################################################

@app.route('/search', methods=['POST'])
@limiter.limit("10 per minute")
def search():
    order_id = request.form.get('order_id')
    user_ip = request.remote_addr
    
    # Log user search input with their IP address
    order_logger.info(f'User Search Input: Order ID - {order_id} from IP {user_ip}')

    # Validate and sanitize the input
    if not is_valid_order_id(order_id):
        order_logger.warning(f'Malicious input detected: {order_id} from IP {user_ip}')
        return render_template('search.html', error="Invalid UPIC ID format.")

    # Search for the order
    order = Order.query.filter_by(order_id=order_id).first()

    if order:
        order_logger.info(f'UPIC Found: {order_id} for IP {user_ip}')
        return render_template('search.html', order=order)
    else:
        order_logger.warning(f'UPIC ID not found: {order_id} for IP {user_ip}')
        return render_template('search.html', error="UPIC ID not found")



################->

def is_valid_order_id(order_id):
    # Define a regular expression for valid order ID formats
    pattern = re.compile(r'^[A-Za-z0-9/]+$')
    return pattern.match(order_id) is not None

##############################################################

WORKER_CREDENTIALS = {
    'Nuguse': b'$2b$12$c0LUTcsp98oWTgofAdflHOAdnNB4BT0rB32lnzdiNM0hZBPeGDQnO', 
    'Teshager': b'$2b$12$/.zEMkz.u8Iwxhiz3ZxMfelnVJzHVnOUU9XLCal1.cNGZm.5NlRo.',
    'Imebet': b'$2b$12$PRF.vtDleuSb.U93XuoeheORc58e8Lvksi4e1yQPiEKTpkJ07u6sa',
    'Olana': b'$2b$12$MI8bGmM.MEEhktcOUixufeOmTYm85ocLLVTr/lIKtwQeWxqSmr4YS',
    'Gezahegn': b'$2b$12$7.LNIkxv9XumWCwxBagRx.oWNZTrJ0lpoNOH7BaIAdvG0Hwu6y5Yu',
    'Bereket': b'$2b$12$2cjFAQqSuymeMMuei0boJuv/osAMCxHcJTgSDjmlEeE1dALQ7mFhS',
    'Hirut': b'$2b$12$Y3wF50aIS4XeHXNaJAanB.IRGXE8BZpTIWktuh1bRkRM9dnuMSZ0O',
    'Leelloo': b'$2b$12$lVTz6SntHgbhovncP/lOy.Z4VXVdrO3MQsjvRninfprstX5LZ4rrG',
    'Gonfa': b'$2b$12$GBLCJj/Cd.z8/PBDuGO/a.hZrigYBpPxumYqb/HBADChH/rTIwUiW'
}

def verify_worker_credentials(username, password):
    stored_password_hash = WORKER_CREDENTIALS.get(username)
    if stored_password_hash:
        return bcrypt.checkpw(password.encode('utf-8'), stored_password_hash)
    return False


##############->

MAX_FAILED_ATTEMPTS = 4
LOCKOUT_TIME_MINUTES = 30

@app.route('/workers', methods=['GET', 'POST'])
def workers():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        ip_address = request.remote_addr  # Track the IP address for lockout

        # Fetch or create worker session by username
        worker_session = workerSession.query.filter_by(username=username).first()

        # Create a new session for the worker if one doesn't exist
        if not worker_session:
            worker_session = workerSession(
                username=username, 
                failed_attempts=0,
                session_active=False, 
                lockout_until=None,
                ip_address=ip_address  # Save the IP address for tracking
            )
            db.session.add(worker_session)
            db.session.commit()

        # Check if the worker is locked out based on IP address
        if worker_session.lockout_until and worker_session.lockout_until > datetime.utcnow():
            lockout_time_remaining = worker_session.lockout_until - datetime.utcnow()
            minutes_left = lockout_time_remaining.seconds // 60
            workers_logger.warning(f"Worker {username} (IP: {ip_address}) is locked out for another {minutes_left} minutes.")
            return render_template('workers_login.html', error=f"Account locked. Try again in {minutes_left} minutes.")

        # Verify credentials only if the worker is not locked out
        if verify_worker_credentials(username, password):
            # Reset failed attempts and lockout if credentials are correct
            worker_session.failed_attempts = 0
            worker_session.lockout_until = None

            # Check if there's an active session for this worker
            active_session = workerSession.query.filter_by(username=username, session_active=True).first()
            if active_session:
                workers_logger.warning(f"Login attempt blocked: Worker {username} is already logged in.")
                session['worker_authenticated'] = True
                session['worker_username'] = username
                return redirect(url_for('workers_dashboard'))

            # Deactivate any previous session
            worker_session.session_active = False
            db.session.commit()

            # Create a new session for the worker
            new_session = workerSession(username=username, session_active=True, last_login=datetime.utcnow())
            db.session.add(new_session)
            db.session.commit()

            # Set session variables for the logged-in worker
            session['worker_authenticated'] = True
            session['worker_username'] = username
            workers_logger.info(f"Successful worker login from IP {ip_address} - Worker: {username}")

            return redirect(url_for('workers_dashboard'))
        else:
            # Ensure failed_attempts is initialized to 0 if it's None
            if worker_session.failed_attempts is None:
                worker_session.failed_attempts = 0

            # Increment failed attempts based on IP address
            worker_session.failed_attempts += 1

            # Lock the worker out based on IP address if max failed attempts are reached
            if worker_session.failed_attempts >= MAX_FAILED_ATTEMPTS:
                worker_session.lockout_until = datetime.utcnow() + timedelta(minutes=LOCKOUT_TIME_MINUTES)
                workers_logger.error(f"Worker {username} (IP: {ip_address}) locked out after {worker_session.failed_attempts} failed attempts.")
                db.session.commit()
                return render_template('workers_login.html', error="Account locked due to too many failed attempts. Try again later.")

            db.session.commit()

            # Log failed login attempt and return error message
            workers_logger.error(f"Failed worker login attempt from IP {ip_address} - Invalid credentials for {username}")
            return render_template('workers_login.html', error=f"Invalid username or password. Attempt {worker_session.failed_attempts} of {MAX_FAILED_ATTEMPTS}.")

    # Redirect the worker if they are already authenticated
    if session.get('worker_authenticated'):
        return redirect(url_for('workers_dashboard'))

    return render_template('workers_login.html')





######################################################

@app.route('/workers/dashboard')
def workers_dashboard():
    if not session.get('worker_authenticated'):
        return redirect(url_for('workers'))

    query = request.args.get('query', '')
    page = request.args.get('page', 1, type=int)  # Get current page number, default to 1
    per_page = 10  # Number of items per page

    if query:
        search = f"%{query}%"
        orders_query = Order.query.filter(
            db.or_(
                Order.order_id.like(search),
                Order.customer_name.like(search),
                Order.carta_id.like(search)
            )
        )
    else:
        orders_query = Order.query

    # Use pagination here with positional arguments
    orders = orders_query.paginate(page=page, per_page=per_page, error_out=False)

    response = make_response(render_template('workers_dashboard.html', orders=orders))
    return response




#############################################################

def log_user_activity(username, action, ip_address):
    log_entry = WorkerActivityLog(username=username, action=action, ip_address=ip_address)
    db.session.add(log_entry)
    db.session.commit()


##################

@app.route('/workers/add-order', methods=['POST'])
def add_order():
    if not session.get('worker_authenticated'):
        return redirect(url_for('workers'))

    username = session.get('worker_username')
    ip_address = request.remote_addr

    try:
        customer_name = request.form.get('customer_name') or None
        order_id = request.form.get('order_id')
        carta_id = request.form.get('carta_id') or None
        status = request.form.get('status') or None
        shape_of_carta = request.form.get('shape_of_carta') or None  # Default value if empty
        width_of_carta = request.form.get('width_of_carta') or None

        if not is_valid_order_id(order_id):
            order_logger.warning('Invalid Order ID format: %s', order_id)
            log_user_activity(username, "Failed to add order - Invalid Order ID format.", ip_address)
            return redirect(url_for('workers_dashboard', error='Invalid Order ID format.'))

        existing_order = Order.query.filter_by(order_id=order_id).first()
        if existing_order:
            order_logger.warning('Failed to add order. Order ID %s already exists.', order_id)
            log_user_activity(username, "Failed to add order - Order ID already exists.", ip_address)
            return redirect(url_for('workers_dashboard', error='Order ID already exists.'))

        new_order = Order(
            customer_name=customer_name,
            order_id=order_id,
            carta_id=carta_id,
            shape_of_carta=shape_of_carta,  
            width_of_carta=width_of_carta,
            status=status,
            created_by=username,
            updated_by=username,
        )
        db.session.add(new_order)
        db.session.commit()

        order_logger.info('Order added: %s', order_id)
        log_user_activity(username, f"Added order with ID {order_id}.", ip_address)

        return redirect(url_for('workers_dashboard'))

    except Exception as e:
        db.session.rollback()  # Rollback any changes in case of error
        order_logger.error('Error adding order: %s', str(e))
        log_user_activity(username, f"Error adding order: {str(e)}", ip_address)
        return render_template('500.html', error=str(e)), 500



    
 #################################################################


@app.route('/workers/update-order/<int:order_id>', methods=['POST'])
def update_order(order_id):
    if not session.get('worker_authenticated'):
        return redirect(url_for('workers'))

    username = session.get('worker_username')
    ip_address = request.remote_addr

    order = Order.query.get_or_404(order_id)

    # Get updated values from the form
    customer_name = request.form.get('customer_name', '').strip()
    new_order_id = request.form.get('order_id', '').strip()
    carta_id = request.form.get('carta_id', '').strip()
    shape_of_carta = request.form.get('shape_of_carta', '').strip()
    width_of_carta = request.form.get('width_of_carta', '').strip()
    status = request.form.get('status', '').strip()

    # Validate inputs
    if not all([new_order_id, carta_id, customer_name, shape_of_carta, width_of_carta, status]):
        log_user_activity(username, "Failed to update order - Empty input field.", ip_address)
        return redirect(url_for('existing_orders', error='All fields are required.'))

    # Validate Order ID
    if not is_valid_order_id(new_order_id):
        log_user_activity(username, "Failed to update order - Invalid Order ID format.", ip_address)
        return redirect(url_for('existing_orders', error='Invalid Order ID format.'))

    # Check if the new order ID already exists
    existing_order = Order.query.filter_by(order_id=new_order_id).first()
    if existing_order and existing_order.id != order_id:
        log_user_activity(username, "Failed to update order - Order ID already exists.", ip_address)
        return redirect(url_for('existing_orders', error='Order ID already exists.'))

    # Check for actual changes and log changes
    changes = []
    if order.customer_name != customer_name:
        changes.append(f"Customer Name: '{order.customer_name}' -> '{customer_name}'")
    if order.order_id != new_order_id:
        changes.append(f"Order ID: '{order.order_id}' -> '{new_order_id}'")
    if order.carta_id != carta_id:
        changes.append(f"Carta ID: '{order.carta_id}' -> '{carta_id}'")
    if order.shape_of_carta != shape_of_carta:
        changes.append(f"Shape of Carta: '{order.shape_of_carta}' -> '{shape_of_carta}'")
    if order.width_of_carta != width_of_carta:
        changes.append(f"Width of Carta: '{order.width_of_carta}' -> '{width_of_carta}'")
    if order.status != status:
        changes.append(f"Status: '{order.status}' -> '{status}'")

    if not changes:
        # Log no changes made
        return redirect(url_for('existing_orders', error='No changes were made.'))

    # Update the order fields
    order.customer_name = customer_name
    order.order_id = new_order_id
    order.carta_id = carta_id
    order.shape_of_carta = shape_of_carta
    order.width_of_carta = width_of_carta
    order.status = status
    order.updated_by = username
    order.updated_at = datetime.utcnow()

    # Commit changes to the database
    db.session.commit()

    # Log successful updates with detailed changes
    change_summary = "; ".join(changes)
    log_user_activity(username, f"Updated order ID {new_order_id}: {change_summary}", ip_address)

    # Redirect back to the existing orders page
    return redirect(url_for('existing_orders'))



#####################################

@app.route('/workers/existing-orders', methods=['GET'])
def existing_orders():
    if not session.get('worker_authenticated'):
        return redirect(url_for('workers'))

    query = request.args.get('query', '')
    page = request.args.get('page', 1, type=int)

    # Filter orders based on the search query
    if query:
        orders = Order.query.filter(
            (Order.order_id.ilike(f'%{query}%')) | 
            (Order.customer_name.ilike(f'%{query}%'))
        ).paginate(page=page, per_page=10)
    else:
        orders = Order.query.paginate(page=page, per_page=10)

    return render_template('existing_orders.html', orders=orders, query=query)



###############################################################

@app.route('/workers/logout')
def logout():
    username = session.get('worker_username')
    session.pop('worker_authenticated', None)
    session.pop('worker_username', None)

    # Deactivate the worker session
    active_session = workerSession.query.filter_by(username=username, session_active=True).first()
    if active_session:
        active_session.session_active = False
        active_session.last_activity = datetime.utcnow()
        db.session.commit()

    workers_logger.info('Worker %s logged out', username)

    # Set cache control headers to prevent caching
    response = make_response(redirect(url_for('workers')))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0'
    response.headers['Pragma'] = 'no-cache'
    return response




####################   admin part
# Store the hashed value of the admin PIN
HASHED_ADMIN_PIN = '0585a52f36c9e01edf92a110516a3a34b29c5f76009d960b2a02bf3389ca57dd'

# Function to verify entered PIN against the stored hash
def verify_admin_pin(entered_pin):
    entered_pin_hash = hashlib.sha256(entered_pin.encode('utf-8')).hexdigest()
    return entered_pin_hash == HASHED_ADMIN_PIN

# Set lockout parameters
MAX_ATTEMPTS = 3
LOCKOUT_DURATION = timedelta(minutes=15)  # 15 minutes lockout

# Define datetime format
DATETIME_FORMAT = '%Y-%m-%dT%H:%M:%S.%f'

@app.route('/admin/pin', methods=['GET', 'POST'])
def admin_pin():
    now = datetime.utcnow()

    if 'attempts' not in session:
        session['attempts'] = 0
    if 'last_attempt_time' not in session:
        session['last_attempt_time'] = now.strftime(DATETIME_FORMAT)

    if 'lockout_time' in session:
        try:
            lockout_time = datetime.strptime(session['lockout_time'], DATETIME_FORMAT)
        except (ValueError, TypeError):
            session.pop('lockout_time', None)
            return redirect(url_for('admin_pin'))

        if now < lockout_time:
            remaining_time = lockout_time - now
            minutes_left = remaining_time.total_seconds() // 60
            return render_template('admin_pin.html', error=f'Locked out. Try again after {int(minutes_left)} minutes.')

    attempts_left = MAX_ATTEMPTS - session['attempts']

    if request.method == 'POST':
        entered_pin = request.form.get('pin')

        if verify_admin_pin(entered_pin):  # Use the verification function
            session.pop('attempts', None)
            session.pop('last_attempt_time', None)
            session.pop('lockout_time', None)
            session['admin_authenticated'] = True
            return redirect(url_for('monitor'))
        else:
            session['attempts'] += 1
            session['last_attempt_time'] = now.strftime(DATETIME_FORMAT)
            if session['attempts'] >= MAX_ATTEMPTS:
                session['lockout_time'] = (now + LOCKOUT_DURATION).strftime(DATETIME_FORMAT)
                session.pop('attempts', None)
                return render_template('admin_pin.html', error='Too many failed attempts. Try again later.')
            return render_template('admin_pin.html', error=f'Invalid PIN. {attempts_left} attempt(s) left.')

    if not session.get('admin_authenticated'):
        return render_template('admin_pin.html', attempts_left=attempts_left)

    return redirect(url_for('monitor'))


#############
@app.route('/admin/monitor', methods=['GET'])
def monitor():
    # Check if the admin is authenticated
    if not session.get('admin_authenticated'):
        return redirect(url_for('admin_pin'))

    try:
        # Get filter parameters from query string
        username = request.args.get('username', type=str, default=None)
        action = request.args.get('action', type=str, default=None)
        ip_address = request.args.get('ip_address', type=str, default=None)
        start_date_str = request.args.get('start_date', type=str, default=None)
        end_date_str = request.args.get('end_date', type=str, default=None)
        daily_activity = request.args.get('daily_activity', type=str, default=None)  # New daily activity filter

        # Get the current page number from query parameters, default to 1
        page = request.args.get('page', 1, type=int)
        per_page = 10  # Number of logs per page

        # Initialize the base query
        query = WorkerActivityLog.query.filter(
            ~WorkerActivityLog.action.ilike('%ERROR%'),
            ~WorkerActivityLog.action.ilike('%WARNING%')
        )

        # Apply filters if provided
        if username:
            query = query.filter(WorkerActivityLog.username.ilike(f"%{username}%"))
        if action:
            query = query.filter(WorkerActivityLog.action.ilike(f"%{action}%"))
        if ip_address:
            query = query.filter(WorkerActivityLog.ip_address == ip_address)
        
        # Handle daily activity filter
        if daily_activity:
            today = datetime.utcnow().date()
            start_date = datetime.combine(today, datetime.min.time())
            end_date = datetime.combine(today, datetime.max.time())
            query = query.filter(WorkerActivityLog.timestamp.between(start_date, end_date))
        else:
            # Handle date filters if provided
            if start_date_str:
                try:
                    start_date = datetime.strptime(start_date_str, '%Y-%m-%d')
                    query = query.filter(WorkerActivityLog.timestamp >= start_date)
                except ValueError:
                    flash('Invalid start date format. Use YYYY-MM-DD.', 'warning')
            if end_date_str:
                try:
                    end_date = datetime.strptime(end_date_str, '%Y-%m-%d') + timedelta(days=1)  # Include the entire end day
                    query = query.filter(WorkerActivityLog.timestamp < end_date)
                except ValueError:
                    flash('Invalid end date format. Use YYYY-MM-DD.', 'warning')

        # Order the logs by timestamp descending
        query = query.order_by(WorkerActivityLog.timestamp.desc())

        # Fetch logs with pagination
        paginated_logs = query.paginate(page=page, per_page=per_page, error_out=False)

        # Prepare the list of valid logs
        valid_logs = [
            {
                'username': log.username,
                'action': log.action,
                'ip_address': log.ip_address,
                'timestamp': log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            }
            for log in paginated_logs.items
        ]

        if not valid_logs:
            flash('No valid logs found on this page.', 'info')  # Inform the admin if no logs on the current page

        # Calculate Top 10 Workers based on the number of actions performed
        top_workers_query = db.session.query(
            WorkerActivityLog.username,
            func.count(WorkerActivityLog.action).label('action_count')
        ).filter(
            ~WorkerActivityLog.action.ilike('%ERROR%'),
            ~WorkerActivityLog.action.ilike('%WARNING%')
        )

        # Apply the same filters to top_workers_query
        if username:
            top_workers_query = top_workers_query.filter(WorkerActivityLog.username.ilike(f"%{username}%"))
        if action:
            top_workers_query = top_workers_query.filter(WorkerActivityLog.action.ilike(f"%{action}%"))
        if ip_address:
            top_workers_query = top_workers_query.filter(WorkerActivityLog.ip_address == ip_address)
        if daily_activity:
            top_workers_query = top_workers_query.filter(WorkerActivityLog.timestamp.between(start_date, end_date))
        else:
            if start_date_str:
                try:
                    top_workers_query = top_workers_query.filter(WorkerActivityLog.timestamp >= start_date)
                except ValueError:
                    pass
            if end_date_str:
                try:
                    top_workers_query = top_workers_query.filter(WorkerActivityLog.timestamp < end_date)
                except ValueError:
                    pass

        top_workers_query = top_workers_query.group_by(WorkerActivityLog.username).order_by(func.count(WorkerActivityLog.action).desc()).limit(10)

        top_workers = top_workers_query.all()

        # Convert top_workers to a list of dictionaries for easier handling in the template
        top_workers_list = [
            {
                'username': worker.username,
                'action_count': worker.action_count
            }
            for worker in top_workers
        ]

    except Exception as e:
        # Log the error for debugging purposes
        app.logger.error(f'Error fetching logs or top workers: {e}')
        flash('An error occurred while fetching logs. Please try again later.', 'error')
        valid_logs = []
        paginated_logs = None
        top_workers_list = []

    return render_template('admin_monitor.html', logs=valid_logs, pagination=paginated_logs, top_workers=top_workers_list)

###################


@app.route('/admin/logout', methods=['GET'])
def admin_logout():
    session.pop('admin_authenticated', None)
    session.pop('attempts', None)
    session.pop('last_attempt_time', None)
    session.pop('lockout_time', None)

    # Set cache control headers to prevent caching
    response = make_response(redirect(url_for('admin_pin')))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0'
    response.headers['Pragma'] = 'no-cache'
    return response

####################
@app.errorhandler(404)
def page_not_found(erro):
    return render_template('404.html'), 404

@app.errorhandler(Exception)
def handle_exception(error):
    return render_template('500.html', error=str(error)), 500

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000 , debug=True)
