from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///orders.db'
db = SQLAlchemy(app)

class Order(db.Model):
    __tablename__ = 'order'
    id = db.Column(db.Integer, primary_key=True)
    customer_name = db.Column(db.String, nullable=False)
    order_id = db.Column(db.String, nullable=False)
    carta_id = db.Column(db.String, nullable=True)
    status = db.Column(db.String, nullable=True)
    shape_of_carta = db.Column(db.String, nullable=True)
    width_of_carta = db.Column(db.String, nullable=True)
    created_by = db.Column(db.String, nullable=False)
    updated_by = db.Column(db.String, nullable=False)  
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class workerSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    session_active = db.Column(db.Boolean, default=False)
    last_login = db.Column(db.DateTime)
    failed_attempts = db.Column(db.Integer, default=0)
    lockout_until = db.Column(db.DateTime, nullable=True)
    ip_address = db.Column(db.String(120))



class WorkerActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100))
    action = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45))  # For IPv6 support
    details = db.Column(db.String(255))



    def __repr__(self):
        return f"<Order {self.order_id}>"
