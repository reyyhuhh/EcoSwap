from flask import Flask, render_template, request, redirect, url_for, abort
from flask import flash, get_flashed_messages
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from flask import session
import os
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash
from flask_migrate import Migrate
from sqlalchemy import or_

from models import db, User, Product  # Make sure User inherits from UserMixin in models.py

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
    return User.query.get(int(user_id))


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
    products = Product.query.all()
    return render_template('home.html', products=products)


from flask import flash

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect('/home')

    if request.method == 'POST':
        login_input = request.form['email']
        password = request.form['password']

        user = User.query.filter(
            or_(
                User.email == login_input,
                User.username == login_input
                )
            ).first()

        if not user:
            flash("Email not found.", "error")
        elif not bcrypt.check_password_hash(user.password, password):
            flash("Incorrect password.", "error")
        else:
            login_user(user)
            flash(f"Welcome back, {user.username}!", "success")
            return redirect('/home')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect('/welcome')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        full_name = request.form['full_name']
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        allowed_domains = ("bilkent.edu.tr", "ug.bilkent.edu.tr", "pg.bilkent.edu.tr")
        if not email.endswith(allowed_domains):
            flash("Please use a valid Bilkent University email address.", "error")
            return redirect(url_for('register'))

        if password != confirm_password:
            flash("Passwords do not match.", "error")
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
        return redirect('/login')
    return render_template('register.html')


@app.route('/add-product', methods=['GET', 'POST'])
@login_required
def add_product():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        swap_option = 'swap' in request.form

        image_file = request.files['image']
        filename = None

        if image_file and allowed_file(image_file.filename):
            filename = secure_filename(image_file.filename)
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            image_file.save(image_path)

        price = request.form.get('price')

        new_product = Product(
            title=title,
            description=description,
            swap_option=swap_option,
            user_id=current_user.id,  # Use actual logged-in user ID
            image_filename=filename,
            price=price
        )
        db.session.add(new_product)
        db.session.commit()

        return redirect('/')
    return render_template('add_product.html')

from models import Message
@app.route('/chat/<int:receiver_id>', methods=['GET', 'POST'])
@login_required
def chat (receiver_id):
    receiver = User.query.get(receiver_id)

    if request.method == 'POST':
        content = request.form['message']
        new_msg = Message(
            sender_id=current_user.id, 
            receiver_id=receiver_id,
            content=content
            )
        db.session.add(new_msg)
        db.session.commit()
        return redirect(url_for('chat', receiver_id=receiver_id))

    messages = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.receiver_id == receiver_id)) | 
        ((Message.sender_id == receiver_id) & (Message.receiver_id == current_user.id))
    ).order_by(Message.timestamp.asc()).all()

    return render_template('chat.html', messages=messages, receiver=receiver)

@app.route('/search')
@login_required
def search():
    search_query = request.args.get('search')
    if search_query:
        products = Product.query.filter(
            or_(
                Product.title.ilike(f"%{search_query}%"),
                Product.description.ilike(f"%{search_query}%")
            )
        ).all()
    else:
        products = Product.query.all()

    return render_template('home.html', products=products, search_query=search_query)

@app.route('/inbox')
@login_required
def inbox():
    # show only chats where the user is sender or receiver
    conversations = Message.query.filter(
        (Message.sender_id == current_user.id) | 
        (Message.receiver_id == current_user.id)
    ).order_by(Message.timestamp.desc()).all()

    unique_threads = {}
    for msg in conversations:
        key = (min(msg.sender_id, msg.receiver_id), max(msg.sender_id, msg.receiver_id))
        if key not in unique_threads:
            unique_threads[key] =  msg
    return render_template('inbox.html', threads=unique_threads.values())

@app.route('/delete_chat/<int:chat_id>', methods=['POST'])
@login_required
def delete_chat(chat_id):
    msg = Message.query.get(chat_id)
    if msg.sender_id == current_user.id or msg.receiver_id == current_user.id:
        db.session.delete(msg)
        db.session.commit()
    return redirect(url_for('inbox'))

from models import CartItem
@app.route('/cart')
def cart():
    items = CartItem.query.filter_by(user_id=current_user.id).all()  # example
    total = sum(item.product.price or 0 for item in items)
    return render_template("cart.html", items=items, total=total)

@app.route('/toggle_sold/<int:product_id>', methods=['POST'])
@login_required
def toggle_sold(product_id):
    product = Product.query.get_or_404(product_id)
    if product.user_id != current_user.id:
        flash("You are not authorized to change this product's status.", "error")
        return redirect(url_for('my_listings'))
    
    product.sold = not product.sold
    db.session.commit()
    return redirect(url_for('my_listings'))

from models import Order
@app.route('/orders/<int:product_id>')
@login_required
def orders_for_product(product_id):
    product = Product.query.get_or_404(product_id)

    if product.user_id != current_user.id:
        abort(403)  # You can only view orders for your own listings

    orders = Order.query.filter_by(product_id=product.id).all()
    return render_template('orders_for_product.html', product=product, orders=orders)



@app.route('/my_orders')
@login_required
def my_orders():
    # Show orders where current user is the product owner
    orders = Order.query.join(Product).filter(Product.user_id == current_user.id).all()
    return render_template('my_orders.html', orders=orders)


@app.route('/remove_from_cart/<int:item_id>', methods=['POST'])
@login_required
def remove_from_cart(item_id):
    item = CartItem.query.filter_by(id=item_id, user_id=current_user.id).first()
    if item:
        db.session.delete(item)
        db.session.commit()
        flash('Item removed from cart', 'success')
    return redirect(url_for('cart'))

@app.route('/my_listings')
@login_required
def my_listings():
    user_products = Product.query.filter_by(user_id=current_user.id).all()
    return render_template('my_listings.html', products=user_products)

@app.route('/delete_product/<int:product_id>', methods=['POST'])
@login_required
def delete_product(product_id):
    product = Product.query.get_or_404(product_id)
    if product.user_id != current_user.id:
        flash("You are not authorized to delete this product.", "error")
        return redirect(url_for('my_listings'))

    db.session.delete(product)
    db.session.commit()
    flash("Product deleted successfully.", "success")
    return redirect(url_for('my_listings'))

@app.route('/add_to_cart/<int:product_id>', methods=['POST'])
@login_required
def add_to_cart(product_id):
    product = Product.query.get_or_404(product_id)

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


from flask_login import logout_user
from flask import redirect, url_for, flash

# ---------------- RUN APP ---------------- #

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        print(app.url_map)  # optional: view routes
    app.run(debug=True)
