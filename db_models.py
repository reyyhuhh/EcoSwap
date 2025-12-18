from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, Float, Boolean, ForeignKey
from sqlalchemy.orm import relationship

db = SQLAlchemy()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(150), nullable=False)
    username = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    products = db.relationship('Product',back_populates='seller',foreign_keys='Product.user_id')

    swapped_items = db.relationship('Product',foreign_keys='Product.buyer_id')

    sent_messages = db.relationship('Message', foreign_keys='Message.sender_id', backref='sender', lazy=True)
    received_messages = db.relationship('Message', foreign_keys='Message.receiver_id', backref='receiver', lazy=True)

    def __repr__(self):
        return f'<User {self.username}>'

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    image_filename = db.Column(db.String(200))
    swap_option = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    seller = db.relationship('User', back_populates='products', foreign_keys=[user_id])
    buyer_id = db.Column(db.Integer, db.ForeignKey('user.id', name='fk_buyer_user'), nullable=True)
    buyer = db.relationship('User', backref="swapped items", foreign_keys=[buyer_id], overlaps="swapped items")
    sold = db.Column(db.Boolean, default=False)
    quality_level = db.Column(db.String(50), nullable=False, default='Good')
    requests= db.relationship('Message', backref='product', lazy=True)

class Message(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
	receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
	content = db.Column(db.Text, nullable=False)
	timestamp = db.Column(db.DateTime, default=datetime.utcnow)
	product_id = db.Column(db.Integer, db.ForeignKey('product.id', name='fk_product_id'), nullable=True)

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    buyer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    delivery_method = db.Column(db.String(50))
    shipping_address = db.Column(db.String(255))
    payment_method = db.Column(db.String(50))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    buyer = db.relationship('User', backref='orders')
    product = db.relationship('Product', backref='order')

class ScamReport(db.Model):
    __tablename__ = 'scam_reports'
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    reporter_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    reason = db.Column(db.String(500), nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())

    # Relationships
    product = db.relationship('Product', backref='reports')
    reporter = db.relationship('User', backref='reports_made')
    
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy # Assuming db is an instance of SQLAlchemy

class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # Fields to match the data being saved in the route
    feedback_topic = db.Column(db.String(100), nullable=False)
    feedback_type = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text, nullable=False)
    contact_info = db.Column(db.String(100), nullable=True) # Optional field
    
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref='feedbacks')

    def __repr__(self):
        return f"Feedback('{self.feedback_topic}', '{self.timestamp}')"