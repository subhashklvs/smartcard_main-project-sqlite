from flask import Flask, render_template, request, redirect, session, flash, jsonify, make_response
from flask_mail import Mail, Message
from flask import url_for
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
import mysql.connector
import bcrypt
import random
import os
import traceback
from werkzeug.utils import secure_filename
import config
import razorpay
from utils.pdf_generator import generate_pdf


app = Flask(__name__)
app.secret_key = config.SECRET_KEY

razorpay_client = razorpay.Client(
    auth=(config.RAZORPAY_KEY_ID, config.RAZORPAY_KEY_SECRET)
)


# ---------------- EMAIL CONFIGURATION ----------------
app.config['MAIL_SERVER'] = config.MAIL_SERVER
app.config['MAIL_PORT'] = config.MAIL_PORT
app.config['MAIL_USE_TLS'] = config.MAIL_USE_TLS
app.config['MAIL_USERNAME'] = config.MAIL_USERNAME
app.config['MAIL_PASSWORD'] = config.MAIL_PASSWORD

# ---------------- IMAGE UPLOAD CONFIGURATION ----------------
app.config['UPLOAD_FOLDER'] = 'static/uploads/product_images'

mail = Mail(app)
password_reset_serializer = URLSafeTimedSerializer(app.secret_key)
PASSWORD_RESET_MAX_AGE = 3600


# Dynamic headers, footers, stylesheets, and scripts are fully managed by modern base templates.

@app.after_request
def add_header(response):
    """
    Add headers to both force latest IE rendering engine or Chrome Frame,
    and also to cache the rendered page for 0 seconds.
    This prevents the "back button" caching issue after logout.
    """
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


# ---------------- DB CONNECTION FUNCTION --------------
def get_db_connection():
    return mysql.connector.connect(
        host=config.DB_HOST,
        user=config.DB_USER,
        password=config.DB_PASSWORD,
        database=config.DB_NAME
    )


USER_UPLOAD_FOLDER = 'static/uploads/user_profiles'
app.config['USER_UPLOAD_FOLDER'] = USER_UPLOAD_FOLDER


def init_user_tables():
    """Create users and cart tables if they don't exist."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            email VARCHAR(100) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL,
            profile_image VARCHAR(255) DEFAULT NULL
        )
    """)
    # Add profile_image column if table already exists without it
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN profile_image VARCHAR(255) DEFAULT NULL")
    except Exception:
        pass  # Column already exists
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cart (
            cart_id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            product_id INT NOT NULL,
            quantity INT DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES users(user_id),
            FOREIGN KEY (product_id) REFERENCES products(product_id)
        )
    """)
    conn.commit()
    cursor.close()
    conn.close()


init_user_tables()

def init_superadmin_table():
    """Create superadmins table if it doesn't exist and add default superadmin."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS superadmins (
            id INT AUTO_INCREMENT PRIMARY KEY,
            email VARCHAR(100) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    
    cursor.execute("SELECT * FROM superadmins WHERE email = %s", ("subhashklvs@gmail.com",))
    if not cursor.fetchone():
        hashed_pw = bcrypt.hashpw("123".encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        cursor.execute("INSERT INTO superadmins (email, password) VALUES (%s, %s)", ("subhashklvs@gmail.com", hashed_pw))
        conn.commit()
        
    cursor.close()
    conn.close()

init_superadmin_table()

def create_superadmin_password_reset_token(superadmin):
    return password_reset_serializer.dumps(
        {"superadmin_id": superadmin["id"], "email": superadmin["email"]},
        salt="superadmin-password-reset"
    )

def verify_superadmin_password_reset_token(token):
    return password_reset_serializer.loads(
        token,
        salt="superadmin-password-reset",
        max_age=PASSWORD_RESET_MAX_AGE
    )

def create_password_reset_token(admin):
    return password_reset_serializer.dumps(
        {"admin_id": admin["admin_id"], "email": admin["email"]},
        salt="admin-password-reset"
    )

def verify_password_reset_token(token):
    return password_reset_serializer.loads(
        token,
        salt="admin-password-reset",
        max_age=PASSWORD_RESET_MAX_AGE
    )

# ---------------------------------------------------------
# ROUTE 0: ROOT -> REDIRECT TO LOGIN
# ---------------------------------------------------------
@app.route('/')
def index():
    return redirect('/admin-login')

# ---------------------------------------------------------
# ABOUT PAGE
# ---------------------------------------------------------
@app.route('/about')
def about_page():
    base_template = "admin/base.html"
    if 'user_id' in session or request.referrer and 'user' in request.referrer:
        base_template = "user/user_base.html"
    return render_template("admin/about.html", base_template=base_template)

# ---------------------------------------------------------
# ROUTE 1: ADMIN SIGNUP (SEND OTP)
# ---------------------------------------------------------
@app.route('/admin-signup', methods=['GET', 'POST'])
def admin_signup():

    if request.method == "GET":
        return render_template("admin/admin_signup.html")

    name = request.form['name']
    email = request.form['email']

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT admin_id FROM admin WHERE email=%s", (email,))
    existing_admin = cursor.fetchone()
    cursor.close()
    conn.close()

    if existing_admin:
        flash("This email is already registered. Please login instead.", "danger")
        return redirect('/admin-signup')

    session['signup_name'] = name
    session['signup_email'] = email

    otp = str(random.randint(100000, 999999))
    session['otp'] = otp

    message = Message(
        subject="SmartCart Admin OTP",
        sender=config.MAIL_USERNAME,
        recipients=[email]
    )
    message.body = f"Your OTP for SmartCart Admin Registration is: {otp}"
    mail.send(message)

    flash("OTP sent to your email!", "success")
    return redirect('/verify-otp')

# ---------------------------------------------------------
# ROUTE 2: DISPLAY OTP PAGE
# ---------------------------------------------------------
@app.route('/verify-otp', methods=['GET'])
def verify_otp_get():
    return render_template("admin/verify_otp.html")


# ---------------------------------------------------------
# ROUTE 3: VERIFY OTP + SAVE ADMIN
# ---------------------------------------------------------
@app.route('/verify-otp', methods=['POST'])
def verify_otp_post():

    user_otp = request.form['otp']
    password = request.form['password']

    if session.get('otp') != user_otp:
        flash("Invalid OTP. Try again!", "danger")
        return redirect('/verify-otp')

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO admin (name, email, password) VALUES (%s, %s, %s)",
        (session['signup_name'], session['signup_email'], hashed_password)
    )
    conn.commit()
    cursor.close()
    conn.close()

    session.pop('otp', None)
    session.pop('signup_name', None)
    session.pop('signup_email', None)

    flash("Admin Registered Successfully! Please login.", "success")
    return redirect('/admin-login')

# ---------------------------------------------------------
# ROUTE 4: ADMIN LOGIN
# ---------------------------------------------------------
@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():

    if request.method == 'GET':
        return render_template("admin/admin_login.html")

    email = request.form['email']
    password = request.form['password']

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM admin WHERE email=%s", (email,))
    admin = cursor.fetchone()
    cursor.close()
    conn.close()

    if admin is None:
        flash("Email not found! Please register first.", "danger")
        return redirect('/admin-login')

    stored_hashed_password = admin['password'].encode('utf-8')
    if not bcrypt.checkpw(password.encode('utf-8'), stored_hashed_password):
        flash("Incorrect password! Try again.", "danger")
        return redirect('/admin-login')

    if admin.get('status') != 'approved':
        flash("Your account is pending. Please take approval from the superadmin.", "warning")
        return redirect('/admin-login')

    session['admin_id'] = admin['admin_id']
    session['admin_name'] = admin['name']
    session['admin_email'] = admin['email']

    flash(f"Welcome, {admin['name']}", "success")
    return redirect('/admin-dashboard')

# ---------------------------------------------------------
# ROUTE 4A: REQUEST ADMIN PASSWORD RESET LINK
# ---------------------------------------------------------
@app.route('/admin/forgot-password', methods=['GET', 'POST'])
def admin_forgot_password():

    if request.method == 'GET':
        return render_template("admin/forgot_password.html")

    email = request.form['email']

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT admin_id, name, email FROM admin WHERE email=%s", (email,))
    admin = cursor.fetchone()
    cursor.close()
    conn.close()

    if admin:
        token = create_password_reset_token(admin)
        reset_link = url_for('admin_reset_password', token=token, _external=True)

        message = Message(
            subject="SmartCart Admin Password Reset",
            sender=config.MAIL_USERNAME,
            recipients=[admin['email']]
        )
        message.body = (
            f"Hello {admin['name']},\n\n"
            "Click the link below to reset your SmartCart admin password:\n"
            f"{reset_link}\n\n"
            "This link will expire in 1 hour. If you did not request this, please ignore this email."
        )

        try:
            mail.send(message)
            flash("Password reset link sent to your email.", "success")
        except Exception:
            flash("Unable to send reset email right now. Please try again later.", "danger")
            return redirect('/admin/forgot-password')
    else:
        flash("Email not found. Please check your email or register first.", "danger")
        return redirect('/admin/forgot-password')

    return redirect('/admin-login')

# ---------------------------------------------------------
# ROUTE 4B: RESET ADMIN PASSWORD FROM EMAIL LINK
# ---------------------------------------------------------
@app.route('/admin/reset-password/<token>', methods=['GET', 'POST'])
def admin_reset_password(token):

    try:
        reset_data = verify_password_reset_token(token)
    except SignatureExpired:
        flash("Reset link expired. Please request a new password reset link.", "danger")
        return redirect('/admin/forgot-password')
    except BadSignature:
        flash("Invalid reset link. Please request a new password reset link.", "danger")
        return redirect('/admin/forgot-password')

    if request.method == 'GET':
        return render_template("admin/reset_password.html", token=token)

    password = request.form['password']
    confirm_password = request.form['confirm_password']

    if password != confirm_password:
        flash("Passwords do not match. Please try again.", "danger")
        return redirect(f'/admin/reset-password/{token}')

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE admin SET password=%s WHERE admin_id=%s AND email=%s",
        (hashed_password, reset_data['admin_id'], reset_data['email'])
    )
    conn.commit()
    cursor.close()
    conn.close()

    flash("Password changed successfully. Please login with your new password.", "success")
    return redirect('/admin-login')

# ---------------------------------------------------------
# ROUTE 5: ADMIN DASHBOARD (PROTECTED)
# ---------------------------------------------------------
@app.route('/admin-dashboard')
def admin_dashboard():

    if 'admin_id' not in session:
        flash("Please login to access the dashboard!", "danger")
        return redirect('/admin-login')
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM admin WHERE admin_id=%s", (session['admin_id'],))
    admin = cursor.fetchone()
    cursor.close()
    conn.close()

    return render_template("admin/dashboard.html", admin_name=session['admin_name'], admin=admin)


@app.route('/admin/admin_dashboard')
def old_admin_dashboard():
    return redirect('/admin-dashboard')

# ---------------------------------------------------------
# ROUTE 5A: ADMIN CONTACT FORM
# ---------------------------------------------------------
@app.route('/contact', methods=['GET', 'POST'])
def contact_page():
    base_template = "admin/base.html"
    if 'user_id' in session or request.referrer and 'user' in request.referrer:
        base_template = "user/user_base.html"

    if request.method == 'GET':
        return render_template("admin/contact.html", base_template=base_template)

    name = request.form['name']
    email = request.form['email']
    phone = request.form.get('phone', '')
    subject = request.form['subject']
    message_text = request.form['message']

    message = Message(
        subject=f"SmartCart Contact: {subject}",
        sender=config.MAIL_USERNAME,
        recipients=[config.MAIL_USERNAME]
    )
    message.body = (
        "New contact message from SmartCart:\n\n"
        f"Name: {name}\n"
        f"Email: {email}\n"
        f"Phone: {phone}\n"
        f"Subject: {subject}\n\n"
        f"Message:\n{message_text}"
    )

    try:
        mail.send(message)
        flash("Your message was sent successfully.", "success")
    except Exception:
        flash("Unable to send your message right now. Please try again later.", "danger")

    return redirect('/contact')

# ---------------------------------------------------------
# ROUTE 6: ADMIN LOGOUT
# ---------------------------------------------------------
@app.route('/admin-logout')
def admin_logout():

    session.pop('admin_id', None)
    session.pop('admin_name', None)
    session.pop('admin_email', None)

    flash("Logged out successfully.", "success")
    return redirect('/admin-login')

# ---------------------------------------------------------
# ROUTE 7: SHOW ADD PRODUCT PAGE (PROTECTED)
# ---------------------------------------------------------
@app.route('/admin/add-item', methods=['GET'])
def add_item_page():

    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    return render_template("admin/add_item.html")

# ---------------------------------------------------------
# ROUTE 8: ADD PRODUCT INTO DATABASE
# ---------------------------------------------------------
@app.route('/admin/add-item', methods=['POST'])
def add_item():

    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    name        = request.form['name']
    description = request.form['description']
    category    = request.form['category']
    price       = request.form['price']
    image_file  = request.files['image']

    if image_file.filename == "":
        flash("Please upload a product image!", "danger")
        return redirect('/admin/add-item')

    filename = secure_filename(image_file.filename)
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    image_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO products (name, description, category, price, image, admin_id) VALUES (%s, %s, %s, %s, %s, %s)",
        (name, description, category, price, filename, session['admin_id'])
    )
    conn.commit()
    cursor.close()
    conn.close()

    flash("Product added successfully!", "success")
    return redirect('/admin/add-item')

# ---------------------------------------------------------
# ROUTE 9: DISPLAY ALL PRODUCTS
# ---------------------------------------------------------
@app.route('/admin/item-list')
def item_list():

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    search = request.args.get('search', '')
    category_filter = request.args.get('category', '')
    page = request.args.get('page', 1, type=int)
    per_page = 12

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Fetch category list for dropdown
    cursor.execute("SELECT DISTINCT category FROM products WHERE admin_id = %s ORDER BY category", (session['admin_id'],))
    categories = cursor.fetchall()

    # Build dynamic query based on filters
    base_where = " WHERE admin_id = %s"
    params = [session['admin_id']]

    if search:
        base_where += " AND name LIKE %s"
        params.append("%" + search + "%")

    if category_filter:
        base_where += " AND category = %s"
        params.append(category_filter)

    # Get total count for pagination
    cursor.execute("SELECT COUNT(*) AS total FROM products" + base_where, params[:])
    total = cursor.fetchone()['total']
    total_pages = max(1, (total + per_page - 1) // per_page)
    page = max(1, min(page, total_pages))

    # Fetch paginated results
    query = "SELECT * FROM products" + base_where + " ORDER BY product_id ASC LIMIT %s OFFSET %s"
    params.extend([per_page, (page - 1) * per_page])
    cursor.execute(query, params)
    products = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        "admin/item_list.html",
        products=products,
        categories=categories,
        page=page,
        total_pages=total_pages,
        total=total,
        search=search,
        category_filter=category_filter
    )

# ---------------------------------------------------------
# ROUTE 10: VIEW SINGLE PRODUCT DETAILS
# ---------------------------------------------------------
@app.route('/admin/view-item/<int:item_id>')
def view_item(item_id):

    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM products WHERE product_id = %s AND admin_id = %s", (item_id, session['admin_id']))
    product = cursor.fetchone()
    cursor.close()
    conn.close()

    if not product:
        flash("Product not found!", "danger")
        return redirect('/admin/item-list')

    return render_template("admin/view_item.html", product=product)

# ---------------------------------------------------------
# ROUTE 11: SHOW UPDATE FORM WITH EXISTING DATA
# ---------------------------------------------------------
@app.route('/admin/update-item/<int:item_id>', methods=['GET'])
def update_item_page(item_id):

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM products WHERE product_id = %s AND admin_id = %s", (item_id, session['admin_id']))
    product = cursor.fetchone()
    cursor.close()
    conn.close()

    if not product:
        flash("Product not found!", "danger")
        return redirect('/admin/item-list')

    return render_template("admin/update_item.html", product=product)

# ---------------------------------------------------------
# ROUTE 12: UPDATE PRODUCT + OPTIONAL IMAGE REPLACE
# ---------------------------------------------------------
@app.route('/admin/update-item/<int:item_id>', methods=['POST'])
def update_item(item_id):

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    name        = request.form['name']
    description = request.form['description']
    category    = request.form['category']
    price       = request.form['price']
    new_image   = request.files['image']

    # Fetch old product data
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM products WHERE product_id = %s AND admin_id = %s", (item_id, session['admin_id']))
    product = cursor.fetchone()

    # Close connection before redirecting
    if not product:
        cursor.close()
        conn.close()
        flash("Product not found!", "danger")
        return redirect('/admin/item-list')

    old_image_name = product['image']

    # If new image uploaded, replace old image
    if new_image and new_image.filename != "":

        new_filename = secure_filename(new_image.filename)

        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        new_image.save(os.path.join(app.config['UPLOAD_FOLDER'], new_filename))

        # Delete old image file from folder
        old_image_path = os.path.join(app.config['UPLOAD_FOLDER'], old_image_name)
        if os.path.exists(old_image_path):
            os.remove(old_image_path)

        final_image_name = new_filename

    else:
        # No new image, keep existing image
        final_image_name = old_image_name

    # Update product in database
    cursor.execute("""
        UPDATE products
        SET name=%s, description=%s, category=%s, price=%s, image=%s
        WHERE product_id=%s AND admin_id=%s
    """, (name, description, category, price, final_image_name, item_id, session['admin_id']))

    conn.commit()
    cursor.close()
    conn.close()

    flash("Product updated successfully!", "success")
    return redirect('/admin/item-list')

# ---------------------------------------------------------
# ROUTE 13: DELETE PRODUCT
# ---------------------------------------------------------
@app.route('/admin/delete-item/<int:item_id>')
def delete_item(item_id):

    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Fetch image name before deleting
    cursor.execute("SELECT image FROM products WHERE product_id = %s AND admin_id = %s", (item_id, session['admin_id']))
    product = cursor.fetchone()

    if product:
        # Delete image file from folder
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], product['image'])
        if os.path.exists(image_path):
            os.remove(image_path)

        try:
            # Remove from carts first to prevent basic foreign key errors
            cursor.execute("DELETE FROM cart WHERE product_id = %s", (item_id,))
            
            # Now attempt to delete the product
            cursor.execute("DELETE FROM products WHERE product_id = %s AND admin_id = %s", (item_id, session['admin_id']))
            conn.commit()
            flash("Product deleted successfully!", "success")
        except mysql.connector.Error as err:
            conn.rollback()
            if err.errno == 1451: # Cannot delete a parent row
                flash("Cannot delete this product because it has already been ordered by customers.", "danger")
            else:
                flash(f"Database error: {err}", "danger")
    else:
        flash("Product not found!", "danger")

    cursor.close()
    conn.close()

    return redirect('/admin/item-list')


# ---------------------------------------------------------
# ROUTE 14: VIEW ALL ORDERS
# ---------------------------------------------------------
@app.route('/admin/orders')
def admin_orders():
    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        query = """
            SELECT o.*, u.name as user_name, u.email as user_email
            FROM orders o
            LEFT JOIN users u ON o.user_id = u.user_id
            ORDER BY o.created_at DESC
        """
        cursor.execute(query)
        orders = cursor.fetchall()
        return render_template('admin/admin_orders.html', orders=orders)
    except Exception as e:
        flash(f"Error fetching orders: {e}", "danger")
        return render_template('admin/admin_orders.html', orders=[])
    finally:
        cursor.close()
        conn.close()

ADMIN_UPLOAD_FOLDER = 'static/uploads/admin_profiles'
app.config['ADMIN_UPLOAD_FOLDER'] = ADMIN_UPLOAD_FOLDER

# =================================================================
# ROUTE 14: SHOW ADMIN PROFILE DATA
# =================================================================
@app.route('/admin/profile', methods=['GET'])
def admin_profile():

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM admin WHERE admin_id = %s", (admin_id,))
    admin = cursor.fetchone()

    cursor.close()
    conn.close()

    return render_template("admin/admin_profile.html", admin=admin)

# =================================================================
# ROUTE 15: UPDATE ADMIN PROFILE (NAME, EMAIL, PASSWORD, IMAGE)
# =================================================================
@app.route('/admin/profile', methods=['POST'])
def admin_profile_update():

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    # Get form data
    name = request.form['name']
    email = request.form['email']
    new_password = request.form['password']
    new_image = request.files['profile_image']

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Fetch old admin data
    cursor.execute("SELECT * FROM admin WHERE admin_id = %s", (admin_id,))
    admin = cursor.fetchone()

    old_image_name = admin['profile_image']

    # Update password only if entered
    if new_password:
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    else:
        hashed_password = admin['password']  # keep old password

    # Process new profile image if uploaded
    if new_image and new_image.filename != "":
        
        from werkzeug.utils import secure_filename
        new_filename = secure_filename(new_image.filename)

        # Save new image
        os.makedirs(app.config['ADMIN_UPLOAD_FOLDER'], exist_ok=True)
        image_path = os.path.join(app.config['ADMIN_UPLOAD_FOLDER'], new_filename)
        new_image.save(image_path)

        # Delete old image
        if old_image_name:
            old_image_path = os.path.join(app.config['ADMIN_UPLOAD_FOLDER'], old_image_name)
            if os.path.exists(old_image_path):
                os.remove(old_image_path)

        final_image_name = new_filename
    else:
        final_image_name = old_image_name

    # Update database
    cursor.execute("""
        UPDATE admin
        SET name=%s, email=%s, password=%s, profile_image=%s
        WHERE admin_id=%s
    """, (name, email, hashed_password, final_image_name, admin_id))

    conn.commit()
    cursor.close()
    conn.close()

    # Update session name for UI consistency
    session['admin_name'] = name  
    session['admin_email'] = email

    flash("Profile updated successfully!", "success")
    return redirect('/admin/profile')

# =================================================================
# ROUTE 15A: DELETE ADMIN PROFILE
# =================================================================
@app.route('/admin/delete-account')
def admin_delete_account():
    if 'admin_id' not in session:
        return redirect('/admin-login')

    admin_id = session['admin_id']
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT profile_image FROM admin WHERE admin_id=%s", (admin_id,))
    admin = cursor.fetchone()
    if admin and admin.get('profile_image'):
        img_path = os.path.join(app.config['ADMIN_UPLOAD_FOLDER'], admin['profile_image'])
        if os.path.exists(img_path):
            os.remove(img_path)

    cursor.execute("DELETE FROM admin WHERE admin_id=%s", (admin_id,))
    conn.commit()
    cursor.close()
    conn.close()

    session.pop('admin_id', None)
    session.pop('admin_name', None)
    session.pop('admin_email', None)
    flash("Admin account deleted.", "success")
    return redirect('/admin-login')

# ---------------------------------------------------------
# USER ROUTE 1: USER REGISTRATION (SEND OTP)
# ---------------------------------------------------------
@app.route('/user-register', methods=['GET', 'POST'])
def user_register():
    if request.method == 'GET':
        return render_template("user/user_register.html")

    name = request.form['name']
    email = request.form['email']
    password = request.form['password']

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT user_id FROM users WHERE email=%s", (email,))
    existing = cursor.fetchone()
    cursor.close()
    conn.close()

    if existing:
        flash("This email is already registered. Please login.", "danger")
        return redirect('/user-register')

    session['user_signup_name'] = name
    session['user_signup_email'] = email
    session['user_signup_password'] = password

    otp = str(random.randint(100000, 999999))
    session['user_otp'] = otp

    message = Message(
        subject="SmartCart User OTP",
        sender=config.MAIL_USERNAME,
        recipients=[email]
    )
    message.body = f"Your OTP for SmartCart Registration is: {otp}"
    mail.send(message)

    flash("OTP sent to your email!", "success")
    return redirect('/user-verify-otp')

# ---------------------------------------------------------
# USER ROUTE 2: VERIFY OTP & COMPLETE REGISTRATION
# ---------------------------------------------------------
@app.route('/user-verify-otp', methods=['GET', 'POST'])
def user_verify_otp():
    if request.method == 'GET':
        return render_template("user/user_verify_otp.html")

    user_otp = request.form['otp']
    password = request.form['password']

    if session.get('user_otp') != user_otp:
        flash("Invalid OTP. Try again!", "danger")
        return redirect('/user-verify-otp')

    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO users (name, email, password) VALUES (%s, %s, %s)",
        (session['user_signup_name'], session['user_signup_email'], hashed)
    )
    conn.commit()
    cursor.close()
    conn.close()

    session.pop('user_otp', None)
    session.pop('user_signup_name', None)
    session.pop('user_signup_email', None)
    session.pop('user_signup_password', None)

    flash("Registered successfully! Please login.", "success")
    return redirect('/user-login')

# ---------------------------------------------------------
# USER ROUTE 3: USER LOGIN
# ---------------------------------------------------------
@app.route('/user-login', methods=['GET', 'POST'])
def user_login():
    if request.method == 'GET':
        return render_template("user/user_login.html")

    email = request.form['email']
    password = request.form['password']

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    if user is None:
        flash("Email not found! Please register first.", "danger")
        return redirect('/user-login')

    if not bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
        flash("Incorrect password!", "danger")
        return redirect('/user-login')

    session['user_id'] = user['user_id']
    session['user_name'] = user['name']
    session['user_email'] = user['email']

    flash(f"Welcome, {user['name']}!", "success")
    return redirect('/user-home')

# ---------------------------------------------------------
# USER ROUTE 4: USER HOME / DASHBOARD
# ---------------------------------------------------------
@app.route('/user-home')
def user_home():
    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')
        
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE user_id=%s", (session['user_id'],))
    user = cursor.fetchone()
    cursor.close()
    conn.close()
    
    return render_template("user/user_home.html", user_name=session['user_name'], user=user)


@app.route('/user-dashboard')
def user_dashboard_redirect():
    return redirect('/user-home')

# ---------------------------------------------------------
# USER ROUTE 4A: EXPLORE PRODUCTS
# ---------------------------------------------------------
@app.route('/user/products')
def user_products():
    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    search = request.args.get('search', '')
    category_filter = request.args.get('category', '')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Fixed category list — only these 9 show in the dropdown
    PREDEFINED_CATEGORIES = [
        "Sarees", "Men's Clothing", "Women's Clothing", "Kids Wear",
        "Footwear", "Watches", "Handbags", "Jewelry", "Sunglasses", "Electronics"
    ]
    categories = [{'category': c} for c in PREDEFINED_CATEGORIES]

    query = "SELECT * FROM products WHERE 1=1"
    params = []

    if search:
        query += " AND name LIKE %s"
        params.append("%" + search + "%")

    if category_filter:
        query += " AND category = %s"
        params.append(category_filter)

    cursor.execute(query, params)
    products = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        "user/user_products.html",
        products=products,
        categories=categories
    )


# ---------------------------------------------------------
# USER ROUTE 5: PRODUCT DETAILS
# ---------------------------------------------------------
@app.route('/user/product/<int:product_id>')
def user_product_detail(product_id):
    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM products WHERE product_id=%s", (product_id,))
    product = cursor.fetchone()
    cursor.close()
    conn.close()

    if not product:
        flash("Product not found!", "danger")
        return redirect('/user-home')

    return render_template("user/product_details.html", product=product)



# ---------------------------------------------------------
# USER ROUTE 9: USER PROFILE
# ---------------------------------------------------------
@app.route('/user/profile', methods=['GET', 'POST'])
def user_profile():
    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    user_id = session['user_id']

    if request.method == 'GET':
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE user_id=%s", (user_id,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()
        return render_template("user/user_profile.html", user=user)

    # POST - update profile
    name = request.form['name']
    email = request.form['email']
    new_password = request.form['password']
    new_image = request.files.get('profile_image')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE user_id=%s", (user_id,))
    user = cursor.fetchone()

    if new_password:
        hashed = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    else:
        hashed = user['password']

    old_image_name = user.get('profile_image')

    # Handle profile image upload
    if new_image and new_image.filename != '':
        new_filename = secure_filename(new_image.filename)
        os.makedirs(app.config['USER_UPLOAD_FOLDER'], exist_ok=True)
        new_image.save(os.path.join(app.config['USER_UPLOAD_FOLDER'], new_filename))

        # Delete old image
        if old_image_name:
            old_path = os.path.join(app.config['USER_UPLOAD_FOLDER'], old_image_name)
            if os.path.exists(old_path):
                os.remove(old_path)

        final_image = new_filename
    else:
        final_image = old_image_name

    cursor.execute(
        "UPDATE users SET name=%s, email=%s, password=%s, profile_image=%s WHERE user_id=%s",
        (name, email, hashed, final_image, user_id)
    )
    conn.commit()
    cursor.close()
    conn.close()

    session['user_name'] = name
    session['user_email'] = email

    flash("Profile updated successfully!", "success")
    return redirect('/user/profile')

# ---------------------------------------------------------
# USER ROUTE 9.5: DELETE USER PROFILE
# ---------------------------------------------------------
@app.route('/user/delete-account')
def user_delete_account():
    if 'user_id' not in session:
        return redirect('/user-login')

    user_id = session['user_id']
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT profile_image FROM users WHERE user_id=%s", (user_id,))
    user = cursor.fetchone()
    if user and user.get('profile_image'):
        img_path = os.path.join(app.config['USER_UPLOAD_FOLDER'], user['profile_image'])
        if os.path.exists(img_path):
            os.remove(img_path)

    cursor.execute("DELETE FROM cart WHERE user_id=%s", (user_id,))
    cursor.execute("DELETE FROM user_addresses WHERE user_id=%s", (user_id,))
    cursor.execute("DELETE FROM order_items WHERE order_id IN (SELECT order_id FROM orders WHERE user_id=%s)", (user_id,))
    cursor.execute("DELETE FROM orders WHERE user_id=%s", (user_id,))
    cursor.execute("DELETE FROM users WHERE user_id=%s", (user_id,))
    
    conn.commit()
    cursor.close()
    conn.close()

    session.pop('user_id', None)
    session.pop('user_name', None)
    session.pop('user_email', None)
    session.pop('cart', None)
    flash("User account deleted.", "success")
    return redirect('/user-login')

# ---------------------------------------------------------
# USER ROUTE 10: FORGOT PASSWORD (SEND RESET LINK)
# ---------------------------------------------------------
@app.route('/user/forgot-password', methods=['GET', 'POST'])
def user_forgot_password():
    if request.method == 'GET':
        return render_template("user/user_forgot_password.html")

    email = request.form['email']

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT user_id, name, email FROM users WHERE email=%s", (email,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    if user:
        token = password_reset_serializer.dumps(
            {"user_id": user["user_id"], "email": user["email"]},
            salt="user-password-reset"
        )
        reset_link = url_for('user_reset_password', token=token, _external=True)

        message = Message(
            subject="SmartCart Password Reset",
            sender=config.MAIL_USERNAME,
            recipients=[user['email']]
        )
        message.body = (
            f"Hello {user['name']},\n\n"
            "Click the link below to reset your SmartCart password:\n"
            f"{reset_link}\n\n"
            "This link will expire in 1 hour. If you did not request this, please ignore this email."
        )

        try:
            mail.send(message)
            flash("Password reset link sent to your email.", "success")
        except Exception:
            flash("Unable to send reset email right now. Please try again later.", "danger")
            return redirect('/user/forgot-password')
    else:
        flash("Email not found. Please check your email or register first.", "danger")
        return redirect('/user/forgot-password')

    return redirect('/user-login')

# ---------------------------------------------------------
# USER ROUTE 11: RESET PASSWORD FROM EMAIL LINK
# ---------------------------------------------------------
@app.route('/user/reset-password/<token>', methods=['GET', 'POST'])
def user_reset_password(token):
    try:
        reset_data = password_reset_serializer.loads(
            token, salt="user-password-reset", max_age=PASSWORD_RESET_MAX_AGE
        )
    except SignatureExpired:
        flash("Reset link expired. Please request a new one.", "danger")
        return redirect('/user/forgot-password')
    except BadSignature:
        flash("Invalid reset link. Please request a new one.", "danger")
        return redirect('/user/forgot-password')

    if request.method == 'GET':
        return render_template("user/user_reset_password.html", token=token)

    password = request.form['password']
    confirm_password = request.form['confirm_password']

    if password != confirm_password:
        flash("Passwords do not match. Please try again.", "danger")
        return redirect(f'/user/reset-password/{token}')

    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE users SET password=%s WHERE user_id=%s AND email=%s",
        (hashed, reset_data['user_id'], reset_data['email'])
    )
    conn.commit()
    cursor.close()
    conn.close()

    flash("Password changed successfully. Please login with your new password.", "success")
    return redirect('/user-login')


# =================================================================
# ADD ITEM TO CART
# =================================================================
@app.route('/user/add-to-cart/<int:product_id>')
def add_to_cart(product_id):

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    # Create cart if doesn't exist
    if 'cart' not in session:
        session['cart'] = {}

    cart = session['cart']

    # Get product
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM products WHERE product_id=%s", (product_id,))
    product = cursor.fetchone()
    cursor.close()
    conn.close()

    if not product:
        flash("Product not found.", "danger")
        return redirect(request.referrer)

    pid = str(product_id)

    # If exists → increase quantity
    if pid in cart:
        cart[pid]['quantity'] += 1
    else:
        cart[pid] = {
            'name': product['name'],
            'price': float(product['price']),
            'image': product['image'],
            'quantity': 1
        }

    session['cart'] = cart
    session.modified = True

    flash("Item added to cart!", "success")
    return redirect(request.referrer)   # ⭐ Return to same page


# =================================================================
# BUY NOW
# =================================================================
@app.route('/user/buy-now/<int:product_id>')
def buy_now(product_id):
    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    if 'cart' not in session:
        session['cart'] = {}

    cart = session['cart']

    # Get product
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM products WHERE product_id=%s", (product_id,))
    product = cursor.fetchone()
    cursor.close()
    conn.close()

    if not product:
        flash("Product not found.", "danger")
        return redirect(request.referrer or '/user/products')

    pid = str(product_id)

    # If exists → increase quantity
    if pid in cart:
        cart[pid]['quantity'] += 1
    else:
        cart[pid] = {
            'name': product['name'],
            'price': float(product['price']),
            'image': product['image'],
            'quantity': 1
        }

    session['cart'] = cart
    session.modified = True

    return redirect('/user/checkout')


# =================================================================
# ADD ITEM TO CART AJAX
# =================================================================
@app.route('/user/add-to-cart-ajax/<int:product_id>')
def add_to_cart_ajax(product_id):

    if 'user_id' not in session:
        return {"error": "not_logged_in"}, 401

    if 'cart' not in session:
        session['cart'] = {}

    cart = session['cart']

    # Fetch product from DB
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM products WHERE product_id=%s", (product_id,))
    product = cursor.fetchone()
    cursor.close()
    conn.close()

    if not product:
        return {"error": "Product not found"}, 404

    pid = str(product_id)

    # Increase quantity if exists
    if pid in cart:
        cart[pid]['quantity'] += 1
    else:
        cart[pid] = {
            'name': product['name'],
            'price': float(product['price']),
            'image': product['image'],
            'quantity': 1
        }

    session['cart'] = cart
    session.modified = True

    # Return JSON response
    return {
        "message": "Item added to cart!",
        "cart_count": len(cart)
    }


# =================================================================
# VIEW CART PAGE
# =================================================================
@app.route('/user/cart')
def view_cart():

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    cart = session.get('cart', {})

    # Calculate total
    grand_total = sum(item['price'] * item['quantity'] for item in cart.values())

    return render_template("user/cart.html", cart=cart, grand_total=grand_total)

# =================================================================
# INCREASE QUANTITY
# =================================================================
@app.route('/user/cart/increase/<pid>')
def increase_quantity(pid):

    cart = session.get('cart', {})

    if pid in cart:
        cart[pid]['quantity'] += 1

    session['cart'] = cart
    session.modified = True
    return redirect('/user/cart')

# =================================================================
# DECREASE QUANTITY
# =================================================================
@app.route('/user/cart/decrease/<pid>')
def decrease_quantity(pid):

    cart = session.get('cart', {})

    if pid in cart:
        cart[pid]['quantity'] -= 1

        # If quantity becomes 0 → remove item
        if cart[pid]['quantity'] <= 0:
            cart.pop(pid)

    session['cart'] = cart
    session.modified = True
    return redirect('/user/cart')

# =================================================================
# REMOVE ITEM
# =================================================================
@app.route('/user/cart/remove/<pid>')
def remove_from_cart(pid):

    cart = session.get('cart', {})

    if pid in cart:
        cart.pop(pid)

    session['cart'] = cart
    session.modified = True

    flash("Item removed!", "success")
    return redirect('/user/cart')


# ---------------------------------------------------------
# USER ROUTE 11.5: CHECKOUT / SHIPPING ADDRESS
# ---------------------------------------------------------
@app.route('/user/checkout', methods=['GET', 'POST'])
def checkout():
    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    cart = session.get('cart', {})
    if not cart:
        flash("Your cart is empty!", "warning")
        return redirect('/user/products')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    # Create the user_addresses table if it doesn't exist
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_addresses (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            full_name VARCHAR(255) NOT NULL,
            phone VARCHAR(20) NOT NULL,
            address TEXT NOT NULL,
            landmark VARCHAR(255) NOT NULL,
            city VARCHAR(100) NOT NULL,
            district VARCHAR(100) NOT NULL,
            state VARCHAR(100) NOT NULL,
            country VARCHAR(100) DEFAULT 'India',
            pincode VARCHAR(20) NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
        )
    """)
    conn.commit()

    # Get user profile info
    cursor.execute("SELECT * FROM users WHERE user_id = %s", (session['user_id'],))
    user = cursor.fetchone()

    # Get all saved addresses for this user
    cursor.execute("SELECT * FROM user_addresses WHERE user_id = %s", (session['user_id'],))
    saved_addresses = cursor.fetchall()

    # If no address exists, insert a default matching the screenshot for a perfect demo!
    if not saved_addresses:
        cursor.execute("""
            INSERT INTO user_addresses (user_id, full_name, phone, address, landmark, city, district, state, country, pincode)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            session['user_id'],
            user['name'],
            '06309764785',
            'Hanuman Temple, Chilakalurupet',
            'Hanuman Temple',
            'Chilakalurupet',
            'Palnadhu',
            'Andhra Pradesh',
            'India',
            '522616'
        ))
        conn.commit()
        
        # Query again
        cursor.execute("SELECT * FROM user_addresses WHERE user_id = %s", (session['user_id'],))
        saved_addresses = cursor.fetchall()

    cursor.close()
    conn.close()

    if request.method == 'GET':
        return render_template("user/checkout.html", user=user, saved_addresses=saved_addresses)

    # POST - Handle Address Form submission
    full_name = request.form.get('full_name')
    phone = request.form.get('phone')
    address = request.form.get('address')
    landmark = request.form.get('landmark')
    city = request.form.get('city')
    district = request.form.get('district')
    state = request.form.get('state')
    country = request.form.get('country', 'India')
    pincode = request.form.get('pincode')

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO user_addresses (user_id, full_name, phone, address, landmark, city, district, state, country, pincode)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """, (session['user_id'], full_name, phone, address, landmark, city, district, state, country, pincode))
    conn.commit()
    
    new_addr_id = cursor.lastrowid
    
    cursor.close()
    conn.close()

    # Store in session for the order
    session['shipping_address'] = {
        'id': new_addr_id,
        'full_name': full_name,
        'phone': phone,
        'address': address,
        'landmark': landmark,
        'city': city,
        'district': district,
        'state': state,
        'country': country,
        'pincode': pincode
    }
    session.modified = True

    return redirect('/user/pay')


# ---------------------------------------------------------
# ROUTE: USE SAVED ADDRESS
# ---------------------------------------------------------
@app.route('/user/checkout/use-address', methods=['POST'])
def use_saved_address():
    if 'user_id' not in session:
        return redirect('/user-login')

    address_id = request.form.get('selected_address_id')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM user_addresses WHERE id = %s AND user_id = %s", (address_id, session['user_id']))
    addr = cursor.fetchone()
    cursor.close()
    conn.close()

    if addr:
        session['shipping_address'] = addr
        session.modified = True

    return redirect('/user/pay')


# ---------------------------------------------------------
# ROUTE: DELETE SAVED ADDRESS
# ---------------------------------------------------------
@app.route('/user/address/delete/<int:address_id>')
def delete_address(address_id):
    if 'user_id' not in session:
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM user_addresses WHERE id = %s AND user_id = %s", (address_id, session['user_id']))
    conn.commit()
    cursor.close()
    conn.close()

    flash("Address deleted successfully!", "success")
    return redirect('/user/checkout')



# =================================================================
# ROUTE: CREATE RAZORPAY ORDER
# =================================================================
@app.route('/user/pay')
def user_pay():
    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    cart = session.get('cart', {})
    if not cart:
        flash("Your cart is empty!", "danger")
        return redirect('/user/products')

    # Calculate total amount
    total_amount = sum(item['price'] * item['quantity'] for item in cart.values())
    razorpay_amount = int(total_amount * 100)  # convert to paise

    # Create Razorpay order
    razorpay_order = razorpay_client.order.create({
        "amount": razorpay_amount,
        "currency": "INR",
        "payment_capture": "1"
    })

    session['razorpay_order_id'] = razorpay_order['id']

    return render_template(
        "user/payment.html",
        amount=total_amount,
        key_id=config.RAZORPAY_KEY_ID,
        order_id=razorpay_order['id']
    )


# =================================================================
# TEMP SUCCESS PAGE (Verification in Day 13)
# =================================================================
@app.route('/payment-success')
def payment_success():
    payment_id = request.args.get('payment_id')
    order_id = request.args.get('order_id')

    if not payment_id:
        flash("Payment failed!", "danger")
        return redirect('/user/cart')

    # Empty the cart upon successful payment
    session.pop('cart', None)
    session.modified = True

    return render_template(
        "user/payment_success.html",
        payment_id=payment_id,
        order_id=order_id
    )


# =================================================================
# DAY 13: Verify Razorpay Payment & Store Order + Order Items
# =================================================================
@app.route('/verify-payment', methods=['POST'])
def verify_payment():
    if 'user_id' not in session:
        flash("Please login to complete the payment.", "danger")
        return redirect('/user-login')

    # Read values posted from frontend
    razorpay_payment_id = request.form.get('razorpay_payment_id')
    razorpay_order_id = request.form.get('razorpay_order_id')
    razorpay_signature = request.form.get('razorpay_signature')

    if not (razorpay_payment_id and razorpay_order_id and razorpay_signature):
        flash("Payment verification failed (missing data).", "danger")
        return redirect('/user/cart')

    # Build verification payload required by Razorpay client.utility
    payload = {
        'razorpay_order_id': razorpay_order_id,
        'razorpay_payment_id': razorpay_payment_id,
        'razorpay_signature': razorpay_signature
    }

    try:
        # This will raise an error if signature is invalid
        razorpay_client.utility.verify_payment_signature(payload)
    except Exception as e:
        app.logger.error("Razorpay signature verification failed: %s", str(e))
        flash("Payment verification failed. Please contact support.", "danger")
        return redirect('/user/cart')

    # Signature verified — now store order and items into DB
    user_id = session['user_id']
    cart = session.get('cart', {})

    if not cart:
        flash("Cart is empty. Cannot create order.", "danger")
        return redirect('/user/products')

    # Calculate total amount (ensure same as earlier)
    total_amount = sum(item['price'] * item['quantity'] for item in cart.values())

    # DB insert: orders and order_items
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Create orders and order_items tables automatically if they don't exist
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS orders (
                order_id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                razorpay_order_id VARCHAR(255) NOT NULL,
                razorpay_payment_id VARCHAR(255) NOT NULL,
                amount DECIMAL(10, 2) NOT NULL,
                payment_status VARCHAR(50) NOT NULL DEFAULT 'paid',
                shipping_address TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS order_items (
                id INT AUTO_INCREMENT PRIMARY KEY,
                order_id INT NOT NULL,
                product_id INT NOT NULL,
                product_name VARCHAR(255) NOT NULL,
                quantity INT NOT NULL,
                price DECIMAL(10, 2) NOT NULL,
                FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE,
                FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE
            )
        """)
        conn.commit()

        # Format shipping address from session
        addr_dict = session.get('shipping_address', {})
        formatted_address = ""
        if addr_dict:
            formatted_address = (
                f"{addr_dict.get('full_name')} | {addr_dict.get('phone')}\n"
                f"{addr_dict.get('address')}, {addr_dict.get('landmark')}\n"
                f"{addr_dict.get('city')}, {addr_dict.get('district')}, {addr_dict.get('state')} - {addr_dict.get('pincode')}\n"
                f"{addr_dict.get('country')}"
            )

        # Insert into orders table
        cursor.execute("""
            INSERT INTO orders (user_id, razorpay_order_id, razorpay_payment_id, amount, payment_status, shipping_address)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (user_id, razorpay_order_id, razorpay_payment_id, total_amount, 'paid', formatted_address))

        order_db_id = cursor.lastrowid  # newly created order's primary key

        # Insert all items
        for pid_str, item in cart.items():
            product_id = int(pid_str)
            cursor.execute("""
                INSERT INTO order_items (order_id, product_id, product_name, quantity, price)
                VALUES (%s, %s, %s, %s, %s)
            """, (order_db_id, product_id, item['name'], item['quantity'], item['price']))

        # Commit transaction
        conn.commit()

        # Clear cart and temporary razorpay order id
        session.pop('cart', None)
        session.pop('razorpay_order_id', None)

        flash("Payment successful and order placed!", "success")
        return redirect(f"/user/order-success/{order_db_id}")

    except Exception as e:
        # Rollback and log error
        conn.rollback()
        app.logger.error("Order storage failed: %s\n%s", str(e), traceback.format_exc())
        flash("There was an error saving your order. Contact support.", "danger")
        return redirect('/user/cart')
    finally:
        cursor.close()
        conn.close()


# ---------------------------------------------------------
# ROUTE: ORDER CONFIRMATION / SUCCESS DETAILS
# ---------------------------------------------------------
@app.route('/user/order-success/<int:order_db_id>')
def order_success(order_db_id):
    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute(
        "SELECT * FROM orders WHERE order_id = %s AND user_id = %s",
        (order_db_id, session['user_id'])
    )
    order = cursor.fetchone()

    cursor.execute(
        "SELECT * FROM order_items WHERE order_id = %s",
        (order_db_id,)
    )
    items = cursor.fetchall()

    cursor.close()
    conn.close()

    if not order:
        flash("Order not found.", "danger")
        return redirect('/user/products')

    return render_template(
        "user/order_success.html",
        order=order,
        items=items,
        shipping=session.get('shipping_address', {})
    )


# ---------------------------------------------------------
# USER ROUTE 12: MY ORDERS
# ---------------------------------------------------------
@app.route('/user/my-orders')
def my_orders():
    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute(
        "SELECT * FROM orders WHERE user_id=%s ORDER BY created_at DESC",
        (session['user_id'],)
    )
    orders = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template("user/my_orders.html", orders=orders)


# ---------------------------------------------------------
# USER ROUTE 12.5: DELETE ORDER
# ---------------------------------------------------------
@app.route('/user/delete-order/<int:order_id>')
def delete_order(order_id):
    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    user_id = session['user_id']
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Verify ownership of the order
        cursor.execute("SELECT order_id FROM orders WHERE order_id = %s AND user_id = %s", (order_id, user_id))
        order = cursor.fetchone()

        if order:
            # Delete order items first
            cursor.execute("DELETE FROM order_items WHERE order_id = %s", (order_id,))
            # Delete the order record
            cursor.execute("DELETE FROM orders WHERE order_id = %s", (order_id,))
            conn.commit()
            flash("Order deleted successfully!", "success")
        else:
            flash("Order not found or access denied.", "danger")
    except Exception as e:
        conn.rollback()
        app.logger.error("Error deleting order: %s", str(e))
        flash("An error occurred while trying to delete the order.", "danger")
    finally:
        cursor.close()
        conn.close()

    return redirect('/user/my-orders')


# ---------------------------------------------------------
# USER ROUTE 13: USER LOGOUT
# ---------------------------------------------------------
@app.route('/user-logout')
def user_logout():
    session.pop('user_id', None)
    session.pop('user_name', None)
    session.pop('user_email', None)

    flash("Logged out successfully.", "success")
    return redirect('/user-login')

# ---------------------------------------------------------
# USER ROUTE 14: DOWNLOAD INVOICE
# ---------------------------------------------------------
@app.route("/user/download-invoice/<int:order_id>")
def download_invoice(order_id):
    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    # Fetch order
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM orders WHERE order_id=%s AND user_id=%s",
                   (order_id, session['user_id']))
    order = cursor.fetchone()

    if not order:
        cursor.close()
        conn.close()
        flash("Order not found.", "danger")
        return redirect('/user/my-orders')

    # Fetch joined items
    cursor.execute("""
        SELECT oi.*, p.image, p.category, p.description 
        FROM order_items oi
        LEFT JOIN products p ON oi.product_id = p.product_id
        WHERE oi.order_id = %s
    """, (order_id,))
    items = cursor.fetchall()

    # Fetch user details
    cursor.execute("SELECT * FROM users WHERE user_id=%s", (session['user_id'],))
    user = cursor.fetchone()

    cursor.close()
    conn.close()

    import os
    product_images_dir = os.path.abspath(os.path.join(app.root_path, 'static', 'uploads', 'product_images'))

    # Render invoice HTML
    html = render_template("user/invoice.html", order=order, items=items, user=user, product_images_dir=product_images_dir)

    pdf = generate_pdf(html)
    if not pdf:
        flash("Error generating PDF", "danger")
        return redirect('/user/my-orders')

    # Prepare response
    response = make_response(pdf.getvalue())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f"attachment; filename=invoice_{order_id}.pdf"

    return response

# =========================================================
# SUPER ADMIN MODULE
# =========================================================

@app.route('/superadmin-login', methods=['GET', 'POST'])
def superadmin_login():
    if 'superadmin_id' in session:
        return redirect('/superadmin-dashboard')
        
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM superadmins WHERE email = %s", (email,))
        superadmin = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if superadmin and bcrypt.checkpw(password.encode('utf-8'), superadmin['password'].encode('utf-8')):
            session['superadmin_id'] = superadmin['id']
            session['superadmin_email'] = superadmin['email']
            flash("Welcome Super Admin!", "success")
            return redirect('/superadmin-dashboard')
        else:
            flash("Invalid email or password", "danger")
            
    return render_template('superadmin/login.html')


@app.route('/superadmin-logout')
def superadmin_logout():
    session.pop('superadmin_id', None)
    session.pop('superadmin_email', None)
    flash("Logged out successfully", "success")
    return redirect('/superadmin-login')


@app.route('/superadmin/forgot-password', methods=['GET', 'POST'])
def superadmin_forgot_password():
    if request.method == 'GET':
        return render_template("superadmin/forgot_password.html")

    email = request.form['email']

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id, email FROM superadmins WHERE email=%s", (email,))
    superadmin = cursor.fetchone()
    cursor.close()
    conn.close()

    if superadmin:
        try:
            token = create_superadmin_password_reset_token(superadmin)
            reset_link = url_for('superadmin_reset_password', token=token, _external=True)

            message = Message(
                subject="SmartCart Super Admin Password Reset",
                sender=config.MAIL_USERNAME,
                recipients=[superadmin['email']]
            )
            message.body = (
                f"Hello Super Admin,\n\n"
                "Click the link below to reset your SmartCart master password:\n"
                f"{reset_link}\n\n"
                "This link will expire in 1 hour.\n\n"
                "If you did not request this, please ignore this email."
            )
            mail.send(message)

            flash("Password reset link has been sent to your master email address.", "success")
            return redirect('/superadmin/forgot-password')
        except Exception as e:
            flash(f"Error sending email: {str(e)}", "danger")
            return redirect('/superadmin/forgot-password')
    else:
        flash("Email not found. Please check your master email.", "danger")
        return redirect('/superadmin/forgot-password')

    return redirect('/superadmin-login')


@app.route('/superadmin/reset-password/<token>', methods=['GET', 'POST'])
def superadmin_reset_password(token):
    try:
        reset_data = verify_superadmin_password_reset_token(token)
        superadmin_email = reset_data['email']
    except SignatureExpired:
        flash("The password reset link has expired. Please request a new one.", "danger")
        return redirect('/superadmin/forgot-password')
    except BadSignature:
        flash("Invalid reset link. Please request a new password reset link.", "danger")
        return redirect('/superadmin/forgot-password')

    if request.method == 'GET':
        return render_template("superadmin/reset_password.html", token=token)

    password = request.form['password']
    confirm_password = request.form['confirm_password']

    if password != confirm_password:
        flash("Passwords do not match. Please try again.", "danger")
        return redirect(f'/superadmin/reset-password/{token}')

    hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE superadmins SET password=%s WHERE email=%s", (hashed_pw, superadmin_email))
    conn.commit()
    cursor.close()
    conn.close()

    flash("Your master password has been updated successfully! You can now login.", "success")
    return redirect('/superadmin-login')


@app.route('/superadmin-dashboard')
def superadmin_dashboard():
    if 'superadmin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/superadmin-login')
        
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    # Get stats
    cursor.execute("SELECT COUNT(*) as count FROM admin")
    admins_count = cursor.fetchone()['count']
    
    cursor.execute("SELECT COUNT(*) as count FROM users")
    users_count = cursor.fetchone()['count']
    
    cursor.execute("SELECT COUNT(*) as count FROM products")
    products_count = cursor.fetchone()['count']
    
    cursor.execute("SELECT COUNT(*) as count FROM orders")
    orders_count = cursor.fetchone()['count']
    
    cursor.execute("SELECT SUM(amount) as total FROM orders WHERE payment_status='paid'")
    revenue_res = cursor.fetchone()
    total_revenue = revenue_res['total'] if revenue_res and revenue_res['total'] else 0
    
    cursor.close()
    conn.close()
    
    stats = {
        'admins': admins_count,
        'users': users_count,
        'products': products_count,
        'orders': orders_count,
        'revenue': total_revenue
    }
    
    return render_template('superadmin/dashboard.html', stats=stats)


@app.route('/superadmin/admins')
def superadmin_admins():
    if 'superadmin_id' not in session:
        return redirect('/superadmin-login')
        
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM admin")
    admins = cursor.fetchall()
    cursor.close()
    conn.close()
    
    return render_template('superadmin/admins.html', admins=admins)

@app.route('/superadmin/admin/approve/<int:admin_id>', methods=['POST'])
def superadmin_approve_admin(admin_id):
    if 'superadmin_id' not in session:
        return redirect('/superadmin-login')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE admin SET status = 'approved' WHERE admin_id = %s", (admin_id,))
    conn.commit()
    cursor.close()
    conn.close()
    
    flash("Administrator has been approved successfully.", "success")
    return redirect('/superadmin/admins')

@app.route('/superadmin/admin/reject/<int:admin_id>', methods=['POST'])
def superadmin_reject_admin(admin_id):
    if 'superadmin_id' not in session:
        return redirect('/superadmin-login')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE admin SET status = 'rejected' WHERE admin_id = %s", (admin_id,))
    conn.commit()
    cursor.close()
    conn.close()
    
    flash("Administrator has been rejected.", "danger")
    return redirect('/superadmin/admins')


@app.route('/superadmin/products')
def superadmin_products():
    if 'superadmin_id' not in session:
        return redirect('/superadmin-login')
        
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT p.*, a.name as admin_name 
        FROM products p 
        LEFT JOIN admin a ON p.admin_id = a.admin_id
    """)
    products = cursor.fetchall()
    cursor.close()
    conn.close()
    
    return render_template('superadmin/products.html', products=products)


@app.route('/superadmin/orders')
def superadmin_orders():
    if 'superadmin_id' not in session:
        return redirect('/superadmin-login')
        
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT o.*, u.name as user_name, u.email as user_email
        FROM orders o
        LEFT JOIN users u ON o.user_id = u.user_id
        ORDER BY o.created_at DESC
    """)
    orders = cursor.fetchall()
    cursor.close()
    conn.close()
    
    return render_template('superadmin/orders.html', orders=orders)


@app.route('/superadmin/order/update-status/<int:order_id>', methods=['POST'])
def superadmin_update_order_status(order_id):
    if 'superadmin_id' not in session:
        return redirect('/superadmin-login')
    
    new_status = request.form.get('order_status')
    if new_status in ['Pending', 'Success', 'Packed', 'Shipped', 'Cancelled']:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE orders SET order_status = %s WHERE order_id = %s", (new_status, order_id))
        conn.commit()
        cursor.close()
        conn.close()
        flash(f"Order #{order_id} status updated to {new_status}.", "success")
    else:
        flash("Invalid status selected.", "danger")
        
    return redirect('/superadmin/orders')


@app.route('/superadmin/revenue')
def superadmin_revenue():
    if 'superadmin_id' not in session:
        return redirect('/superadmin-login')
        
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    # Group revenue by date
    cursor.execute("""
        SELECT DATE(created_at) as date, SUM(amount) as daily_revenue 
        FROM orders 
        WHERE payment_status='paid' 
        GROUP BY DATE(created_at) 
        ORDER BY DATE(created_at) DESC
        LIMIT 30
    """)
    revenue_data = cursor.fetchall()
    
    cursor.execute("SELECT SUM(amount) as total FROM orders WHERE payment_status='paid'")
    total_res = cursor.fetchone()
    total_revenue = total_res['total'] if total_res and total_res['total'] else 0
    
    cursor.close()
    conn.close()
    
    return render_template('superadmin/revenue.html', revenue_data=revenue_data, total_revenue=total_revenue)


@app.route('/superadmin/admin-revenue')
def superadmin_admin_revenue():
    if 'superadmin_id' not in session:
        return redirect('/superadmin-login')
        
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    query = """
        SELECT a.name as admin_name, a.email as admin_email, SUM(oi.price * oi.quantity) as total_revenue
        FROM order_items oi
        JOIN orders o ON oi.order_id = o.order_id
        JOIN products p ON oi.product_id = p.product_id
        JOIN admin a ON p.admin_id = a.admin_id
        WHERE o.payment_status = 'paid'
        GROUP BY a.admin_id
        ORDER BY total_revenue DESC
    """
    cursor.execute(query)
    admin_revenues = cursor.fetchall()
    
    cursor.close()
    conn.close()
    
    return render_template('superadmin/admin_revenue.html', admin_revenues=admin_revenues)



# ------------------------- RUN APP ------------------------
if __name__ == '__main__':
    app.run(debug=True)