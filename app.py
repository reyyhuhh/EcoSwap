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
from models import db, User, Product, Feedback, Message, CartItem, Order
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
with app.app_context():
    db.create_all() 

def create_admin():
    with app.app_context():
        # Check if admin exists
        # This query now succeeds because db.create_all() has run
        admin = User.query.filter_by(username='adminecoswap').first()
        if not admin:
            # Create the admin if not found
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
    # Ensure only admins can access this route
    if not current_user.is_admin:
        flash("You are not authorized to view this page.", "error")
        return redirect(url_for('home'))

    all_users = User.query.all()
    all_products = Product.query.all()
    # Feedback is now correctly imported
    all_feedback = Feedback.query.all()

    return render_template(
        'admin.html',
        users=all_users,
        products=all_products,
        feedback_list=all_feedback
    )

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

        hashed_pw = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')

        new_user = User(
            full_name=full_name,
            username=username,
            email=email,
            password=hashed_pw
        )
        db.session.add(new_user)
        db.session.commit()
        flash("Registration successful! Please log in.", "success")
        return redirect('/login')
    return render_template('register.html')


@app.route('/add-product', methods=['GET', 'POST'])
@login_required
def add_product():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        swap_option = 'swap' in request.form

        image_file = request.files.get('image') # Use .get() for safety
        filename = None

        if image_file and image_file.filename != '' and allowed_file(image_file.filename):
            filename = secure_filename(image_file.filename)
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            
            # Ensure the upload folder exists before saving
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            image_file.save(image_path)
            
        # Ensure price is handled safely if not provided or non-numeric
        try:
            price = float(request.form.get('price') or 0.0)
        except ValueError:
            flash("Invalid price entered.", "error")
            return redirect(url_for('add_product'))


        new_product = Product(
            title=title,
            description=description,
            swap_option=swap_option,
            user_id=current_user.id,
            image_filename=filename,
            price=price
        )
        db.session.add(new_product)
        db.session.commit()
        flash("Product listed successfully!", "success")
        return redirect('/')
    return render_template('add_product.html')

@app.route('/chat/<int:receiver_id>', methods=['GET', 'POST'])
@login_required
def chat (receiver_id):
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

@app.route('/cart')
@login_required
def cart():
    items = CartItem.query.filter_by(user_id=current_user.id).all()
    # Ensure item.product exists before accessing price
    total = sum(item.product.price or 0 for item in items if item.product) 
    return render_template("cart.html", items=items, total=total)

@app.route('/checkout', methods=['GET', 'POST'])
@login_required
def checkout():
    items = CartItem.query.filter_by(user_id=current_user.id).all()
    if not items:
        flash("Your cart is empty.", "error")
        return redirect(url_for('cart'))
        
    total = sum(item.product.price or 0 for item in items)
    
    # Store items details for receipt before clearing the cart
    cart_items_for_receipt = [{'title': item.product.title, 'price': item.product.price or 0} for item in items]


    if request.method == 'POST':
        delivery = request.form['delivery']
        address = request.form['address']
        payment = request.form['payment']

        for item in items:
            # Note: This assumes the Product model has a seller_id or we use item.product.user_id
            order = Order(
                buyer_id=current_user.id,
                product_id=item.product.id,
                delivery_method=delivery,
                shipping_address=address,
                payment_method=payment
            )
            db.session.add(order)
            item.product.sold = True # Mark product as sold

        # Commit all orders and product updates
        db.session.commit() 
        
        # Clear the cart ONLY AFTER successful order creation and commit
        CartItem.query.filter_by(user_id=current_user.id).delete()
        db.session.commit()
        
        # Store receipt details in session for the next request
        session['last_order_items'] = cart_items_for_receipt
        session['last_order_total'] = total

        flash("Order placed successfully!", "success")
        return redirect(url_for('receipt'))

    return render_template('checkout.html', items=items, total=total)


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

@app.route('/orders/<int:product_id>')
@login_required
def orders_for_product(product_id):
    product = Product.query.get_or_404(product_id)

    if product.user_id != current_user.id:
        abort(403)

    orders = Order.query.filter_by(product_id=product.id).all()
    return render_template('orders_for_product.html', product=product, orders=orders)


@app.route('/my_orders')
@login_required
def my_orders():
    # Show orders where current user is the product owner (seller)
    orders_as_seller = Order.query.join(Product).filter(Product.user_id == current_user.id).all()
    # Show orders where current user is the buyer
    orders_as_buyer = Order.query.filter_by(buyer_id=current_user.id).all()
    
    return render_template('my_orders.html', orders_as_seller=orders_as_seller, orders_as_buyer=orders_as_buyer)

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

@app.route('/remove_from_cart/<int:item_id>', methods=['POST'])
@login_required
def remove_from_cart(item_id):
    item = CartItem.query.filter_by(id=item_id, user_id=current_user.id).first()
    if item:
        db.session.delete(item)
        db.session.commit()
        flash('Item removed from cart', 'success')
    return redirect(url_for('cart'))

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

@app.route('/add_to_cart/<int:product_id>', methods=['POST'])
@login_required
def add_to_cart(product_id):
    product = Product.query.get_or_404(product_id)
    
    if product.user_id == current_user.id:
        flash("You cannot add your own product to the cart.", "error")
        return redirect(url_for('home'))

    if product.sold:
        flash("This product has already been sold.", "error")
        return redirect(url_for('home'))

    # Prevent duplicate entry
    existing_item = CartItem.query.filter_by(user_id=current_user.id, product_id=product.id).first()
    if existing_item:
        flash("Product already in your cart.", "info")
        return redirect(url_for('home'))

    cart_item = CartItem(user_id=current_user.id, product_id=product.id)
    db.session.add(cart_item)
    db.session.commit()
    flash("Added to cart successfully.", "success")
    return redirect(url_for('home'))

@app.context_processor
def inject_cart_count():
    if current_user.is_authenticated:
        count = CartItem.query.filter_by(user_id=current_user.id).count()
        return dict(cart_count=count)
    return dict(cart_count=0)


@app.route('/buy_now/<int:product_id>', methods=['POST'])
@login_required
def buy_now(product_id):
    # This route should typically redirect to checkout_single, not complete the purchase here.
    # The existing logic here is poor practice (deleting the product immediately).
    # Redirecting to the single checkout route is the correct flow.
    return redirect(url_for('checkout_single', product_id=product_id))


# ---------------- RUN APP ---------------- #

if __name__ == '__main__':
    # db.create_all() is now handled before create_admin()
    print(app.url_map)
    app.run(debug=True)