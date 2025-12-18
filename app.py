from flask import Flask, render_template, request, redirect, url_for, abort, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from flask import session
import os
from werkzeug.utils import secure_filename
from flask_migrate import Migrate
from sqlalchemy import or_
from datetime import datetime # Needed for the Feedback model timestamp if defined there

# --- CONSOLIDATED MODEL IMPORTS (Ensure these are correctly defined in models.py) ---
from db_models import db, User, Product, Feedback, Message
# -----------------------------------------------------------------------------------

app = Flask(__name__)
app.config['SECRET_KEY'] = 'ecoswapsecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///instanceecoswap.db'

UPLOAD_FOLDER = os.path.abspath(os.path.join('static', 'uploads'))
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER 
ALLOWED_EXTENSIONS = {'png','jpg', 'jpeg', 'gif', 'mp4'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Initialize extensions
db.init_app(app)
bcrypt = Bcrypt(app) 
migrate = Migrate(app, db)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User loader
@login_manager.user_loader
def load_user(user_id):
    # This must handle the case where the user is not found, returning None
    return User.query.get(int(user_id))

# --- DATABASE AND ADMIN SETUP ---
# Moved db.create_all() here to ensure tables exist before any query runs
#with app.app_context():
    #db.create_all() 

def create_admin():
    with app.app_context():
        try:
            # Check if admin exists
            admin = User.query.filter_by(username='adminecoswap').first()
            if not admin:
                hashed_pw = bcrypt.generate_password_hash('ecoswap12345').decode('utf-8')
                new_admin = User(
                    full_name='System Admin',
                    username='adminecoswap',
                    email='admin@ecoswap.com', 
                    password=hashed_pw,
                    is_admin=True 
                )
                db.session.add(new_admin)
                db.session.commit()
                print("Admin account created successfully!")
            else:
                print("Admin account already exists.")
        except Exception:
            print("Database tables not found. Skipping admin creation until 'flask db upgrade' is run.")

create_admin()

# ---------------- ROUTES ---------------- #

@app.route('/welcome')
def welcome():
    if current_user.is_authenticated:
        return redirect('/')
    return render_template('welcome.html')

@app.route('/')
def root():
    if current_user.is_authenticated:
        return redirect('/home')
    return redirect('/welcome')

@app.route('/home')
@login_required
def home():
    products = Product.query.filter_by(sold=False).all() # Only show unsold products
    
    return render_template('home.html', products=products)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        login_input = request.form['email']
        password = request.form['password']

        # Consolidated login flow for all users
        user = User.query.filter(
            or_(
                User.email == login_input,
                User.username == login_input
            )
        ).first()

        if not user:
            flash("User does not exist.", "error")
        elif not bcrypt.check_password_hash(user.password, password):
            flash("Incorrect password.", "error")
        else:
            login_user(user)
            flash(f"Welcome back, {user.username}!", "success")
            
            # Check if logged-in user is admin, and redirect to admin panel
            if user.is_admin:
                 return redirect(url_for('admin')) 
            else:
                 return redirect(url_for('home'))

    return render_template('login.html')

@app.route('/admin')
@login_required
def admin():
    # 1. Security Check: Ensure only admins can access
    if not current_user.is_admin:
        flash("You are not authorized to view this page.", "error")
        return redirect(url_for('home'))

    # 2. Fetch all data for the dashboard
    all_users = User.query.all()
    all_products = Product.query.all()
    all_feedback = Feedback.query.all()
    # Ensure ScamReport is imported from db_models at the top of your file
    all_scamreports = ScamReport.query.order_by(ScamReport.timestamp.desc()).all()

    return render_template(
        'admin.html',
        users=all_users,
        products=all_products,
        feedback_list=all_feedback,
        reports=all_scamreports # This matches the {% for report in reports %} in your HTML
    )

@app.route('/admin/delete_product/<int:product_id>', methods=['POST'])
@login_required
def admin_delete_product(product_id):
    # 1. Security Check: Only admins can trigger a deletion
    if not current_user.is_admin:
        abort(403) 
    
    product = Product.query.get_or_404(product_id)
    
    # 2. Delete the reports associated with this product first (Child records)
    ScamReport.query.filter_by(product_id=product_id).delete()
    
    # 3. Delete the product itself (Parent record)
    db.session.delete(product)
    db.session.commit()
    
    flash("The reported product and its associated reports have been removed.", "success")
    
    # 4. Redirect to the FUNCTION NAME 'admin'
    return redirect(url_for('admin'))

@app.route('/admin/dismiss_report/<int:report_id>', methods=['POST'])
@login_required
def dismiss_report(report_id):
    # Security Check
    if not current_user.is_admin:
        abort(403)

    # Find the specific report
    report = ScamReport.query.get_or_404(report_id)
    
    db.session.delete(report)
    db.session.commit()
    
    flash("The report was dismissed. The listing remains active.", "info")
    return redirect(url_for('admin'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    flash("You have been logged out.", "info")
    return redirect('/welcome')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        full_name = request.form['full_name']
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return redirect(url_for('register'))

        # Check for existing user/email
        if User.query.filter(or_(User.username == username, User.email == email)).first():
            flash("Username or Email already exists.", "error")
            return redirect(url_for('register'))
        
        allowed_domains = ("@ug.bilkent.edu.tr", "@pg.bilkent.edu.tr", "@bilkent.edu.tr")
        if not email.endswith(allowed_domains):
            flash("Please use your Bilkent email.", "error")
            return redirect(url_for('register'))

        hashed_pw = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')

        new_user = User(
            full_name=full_name,
            username=username,
            email=email,
            password=hashed_pw
        )
        db.session.add(new_user)
        db.session.commit()
        flash("success")
        return redirect('/login')
    return render_template('register.html')


@app.route('/add-product', methods=['GET', 'POST'])
@login_required
def add_product():
    if request.method == 'POST':        
        title = request.form['title']
        description = request.form['description']
        swap_option = 'swap' in request.form
        quality = request.form['quality']
        
        # --- 2. PROCESS FILE UPLOAD FIRST ---
        image_file = request.files.get('image')
        filename = None
        
        if image_file and image_file.filename != '' and allowed_file(image_file.filename):
            filename = secure_filename(image_file.filename)
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            
            # Save the file before using the filename variable in the database object
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            image_file.save(image_path)
        

        new_product = Product(
            title=title,
            description=description,
            swap_option=swap_option,
            user_id=current_user.id,
            image_filename=filename,
            quality_level=quality
        )

        db.session.add(new_product)
        
        db.session.commit()
        flash("Product listed successfully!", "success")
        return redirect('/')
    
    # Render GET request template
    return render_template('add_product.html')

@app.route('/chat/<int:receiver_id>', methods=['GET', 'POST'])
@app.route('/chat/<int:receiver_id>/<int:product_id>')
@login_required
def chat (receiver_id, product_id=None):
    receiver = User.query.get_or_404(receiver_id)

    if request.method == 'POST':
        content = request.form['message']
        new_msg = Message(
            sender_id=current_user.id, 
            receiver_id=receiver_id,
            content=content
            )
        db.session.add(new_msg)
        db.session.commit()
        # Redirect using a hash fragment to scroll to the last message
        return redirect(url_for('chat', receiver_id=receiver_id) + '#latest') 

    messages = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.receiver_id == receiver_id)) | 
        ((Message.sender_id == receiver_id) & (Message.receiver_id == current_user.id))
    ).order_by(Message.timestamp.asc()).all()

    return render_template('chat.html', messages=messages, receiver=receiver)

@app.route('/search')
@login_required
def search():
    search_query = request.args.get('search', '') # Default to empty string

    if search_query:
        products = Product.query.filter(
            Product.sold == False, # Only search unsold products
            or_(
                Product.title.ilike(f"%{search_query}%"),
                Product.description.ilike(f"%{search_query}%")
            )
        ).all()
    else:
        products = Product.query.filter_by(sold=False).all()

    return render_template('home.html', products=products, search_query=search_query)

@app.route('/inbox')
@login_required
def inbox():
    user1_case = db.case(
        (Message.sender_id < Message.receiver_id, Message.sender_id),
        else_=Message.receiver_id
    ).label('user1')

    # Simulates GREATEST(sender_id, receiver_id): returns the larger ID
    user2_case = db.case(
        (Message.sender_id > Message.receiver_id, Message.sender_id),
        else_=Message.receiver_id
    ).label('user2')

    # 1. Find the latest message timestamp for each unique conversation pair (the thread identifier)
    subquery = db.session.query(
        db.func.max(Message.timestamp).label('last_message_time'),
        user1_case,
        user2_case
    ).filter(
        (Message.sender_id == current_user.id) | (Message.receiver_id == current_user.id)
    ).group_by('user1', 'user2').subquery()

    # 2. Join the subquery back to the Message table to get the full latest message object
    latest_messages = db.session.query(Message).join(
        subquery,
        db.and_(
            Message.timestamp == subquery.c.last_message_time,
            db.or_(
                # Conversation is (user1 -> user2)
                db.and_(
                    Message.sender_id == subquery.c.user1, 
                    Message.receiver_id == subquery.c.user2
                ),
                # Conversation is (user2 -> user1)
                db.and_(
                    Message.sender_id == subquery.c.user2, 
                    Message.receiver_id == subquery.c.user1
                )
            )
        )
    ).order_by(Message.timestamp.desc()).all()
    
    # Pass the unique latest message objects (threads) to the template
    return render_template('inbox.html', threads=latest_messages)

@app.route('/delete_chat/<int:other_user_id>', methods=['POST'])
@login_required
def delete_chat(other_user_id):
    # This should delete ALL messages between current_user and other_user
    messages_to_delete = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.receiver_id == other_user_id)) | 
        ((Message.sender_id == other_user_id) & (Message.receiver_id == current_user.id))
    )
    
    # Check if any messages exist before deleting
    if messages_to_delete.count() > 0:
        messages_to_delete.delete(synchronize_session=False)
        db.session.commit()
        flash("Conversation deleted successfully.", "success")
    else:
        flash("Conversation not found.", "error")
        
    return redirect(url_for('inbox'))

@app.route('/toggle_sold/<int:product_id>', methods=['POST'])
@login_required
def toggle_sold(product_id):
    product = Product.query.get_or_404(product_id)
    if product.user_id != current_user.id:
        flash("You are not authorized to change this product's status.", "error")
        return redirect(url_for('profile'))
    
    product.sold = not product.sold
    db.session.commit()
    flash(f"Status changed to {'Sold' if product.sold else 'Available'}.", "info")
    return redirect(url_for('profile'))

@app.route('/feedback', methods=['GET', 'POST'])
@login_required
def feedback():
    if request.method == 'POST':
        # Get form data
        feedback_topic = request.form['topic']
        feedback_type = request.form['feedback_type']
        description = request.form['description']
        contact_info = request.form.get('contact_info')

        # Create a new Feedback report
        feedback_report = Feedback(
            feedback_topic=feedback_topic,
            feedback_type=feedback_type,
            description=description,
            contact_info=contact_info,
            user_id=current_user.id
        )

        # Add the report to the database
        db.session.add(feedback_report)
        db.session.commit()

        flash('Your feedback has been submitted successfully!', 'success')
        return redirect(url_for('home'))

    return render_template('feedback.html')

@app.route('/profile')
@login_required
def profile(): 
    user_products = Product.query.filter_by(user_id=current_user.id).all()
    return render_template('profile.html', products=user_products)

@app.route('/delete_product/<int:product_id>', methods=['POST'])
@login_required
def delete_product(product_id):
    product = Product.query.get_or_404(product_id)
    if product.user_id != current_user.id:
        flash("You are not authorized to delete this product.", "error")
        return redirect(url_for('profile'))

    db.session.delete(product)
    db.session.commit()
    flash("Product deleted successfully.", "success")
    return redirect(url_for('profile'))

@app.route('/product/<int:product_id>/orders')
@login_required
def orders_for_product(product_id):
    product = Product.query.get_or_404(product_id)
    
    if product.user_id != current_user.id:
        flash("Access denied.", "error")
        return redirect(url_for('home'))
        
    # Fetch all messages/requests specifically for this product
    requests = Message.query.filter_by(product_id=product_id).all()
    
    return render_template('orders_for_product.html', product=product, requests=requests)

@app.route('/accept_swap/<int:product_id>/<int:buyer_id>', methods=['POST'])
@login_required
def accept_swap(product_id, buyer_id):
    product = Product.query.get_or_404(product_id)
    
    # Check if current user is the owner
    if product.user_id != current_user.id:
        flash("Unauthorized action.", "error")
        return redirect(url_for('home'))
    
    # Update the product
    product.sold = True
    product.buyer_id = buyer_id
    
    db.session.commit()
    flash(f"Swap confirmed! '{product.title}' is now marked as sold.", "success")
    return redirect(url_for('profile'))

@app.route('/send_swap_request/<int:product_id>', methods=['POST'])
@login_required
def send_swap_request(product_id):
    product = Product.query.get_or_404(product_id)
    
    # Prevent users from swapping with themselves
    if product.user_id == current_user.id:
        flash("You cannot request your own item!", "error")
        return redirect(url_for('home'))

    new_message = Message(
        sender_id=current_user.id,
        receiver_id=product.user_id,
        content=f"Hello! I am interested in swapping for your '{product.title}'. Is it still available?",
        product_id=product.id
    )
    
    db.session.add(new_message)
    db.session.commit()
    
    flash(f"Swap request sent for {product.title}!", "success")
    return redirect(url_for('home'))  

from db_models import ScamReport 
@app.route('/report_product/<int:product_id>', methods=['POST'])
@login_required
def report_product(product_id):
    reason = request.form.get('reason')
    if not reason:
        flash("Please provide a reason for the report.", "error")
        return redirect(url_for('home'))

    report = ScamReport(
        product_id=product_id,
        reporter_id=current_user.id,
        reason=reason
    )
    
    db.session.add(report)
    db.session.commit()
    
    flash("Thank you. The report has been sent to the admins for review.", "info")
    return redirect(url_for('home'))  

@app.context_processor
def inject_notifications():
    if current_user.is_authenticated:
        # 1. Count unread messages (assuming you have a 'read' column, 
        # otherwise we can count total messages received in the last 24h)
        # For now, let's count all messages where the user is the receiver
        unread_msg_count = Message.query.filter_by(receiver_id=current_user.id).count()
        
        # 2. Count swap requests for the user's products
        # We look for messages that have a product_id linked to a product owned by the user
        swap_req_count = db.session.query(Message).join(Product).filter(
            Product.user_id == current_user.id,
            Message.product_id != None
        ).count()
        
        return dict(unread_count=unread_msg_count, swap_count=swap_req_count)
    return dict(unread_count=0, swap_count=0)

@app.route('/decline_swap/<int:message_id>', methods=['POST'])
@login_required
def decline_swap(message_id):
    # Find the request message
    request_to_delete = Message.query.get_or_404(message_id)
    
    # Optional: Safety check to ensure only the product owner can decline
    product = Product.query.get(request_to_delete.product_id)
    if product.user_id != current_user.id:
        return "Unauthorized", 403

    db.session.delete(request_to_delete)
    db.session.commit()
    
    flash('Swap request declined and removed.', 'info')
    return redirect(url_for('orders_for_product', product_id=product.id))

# ---------------- RUN APP ---------------- #

if __name__ == '__main__':
    # db.create_all() is now handled before create_admin()
    print(app.url_map)
    app.run(debug=True)