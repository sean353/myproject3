
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask import Flask, request, jsonify
from datetime import datetime as dt
from flask_jwt_extended import JWTManager , create_access_token
import datetime 
import json,time,os
from functools import wraps
from flask_cors import CORS, cross_origin
# from sqlalchemy.orm import class_mapper
# from werkzeug.utils import secure_filename
import jwt
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity, jwt_required
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///books.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = '123'  # Replace with your actual secret key
db = SQLAlchemy(app)
jwt = JWTManager(app)
bcrypt = Bcrypt(app)
CORS(app)

BOOK_TYPE_MAX_LOAN_DURATION = {
    '1': 10,
    '2': 5,
    '3': 2
}

class Book(db.Model):
    __tablename__ = 'books'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(45), nullable=False)
    author = db.Column(db.String(45), nullable=False)
    year_published = db.Column(db.String(45), nullable=False)
    book_type = db.Column(db.String(100), nullable=False)

   

class Customer(db.Model):
    __tablename__ = 'customers'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(45), nullable=False)
    city = db.Column(db.String(45), nullable=False)
    age = db.Column(db.String(45), nullable=False)

class Loan(db.Model):
    __tablename__ = 'loans'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    loan_date = db.Column(db.String(45), nullable=False)
    return_date = db.Column(db.String(45), nullable=False)
    
    # Foreign keys referencing Customer and Book
    customer_id = db.Column(db.Integer, db.ForeignKey('customers.id'), nullable=False)
    book_id = db.Column(db.Integer, db.ForeignKey('books.id'), nullable=False)
    
    # Relationships
    customer = db.relationship('Customer', backref='loans')
    book = db.relationship('Book', backref='loans')



class Users(db.Model):
    __tablename__ = 'Users'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(45), nullable=False, unique=True)
    password = db.Column(db.String(45), nullable=False)
    role = db.Column(db.String(45), nullable=False, default='user')  # Assuming 'user' is the default role


    



def generate_token(user_id):
    expiration = int(time.time()) + 3600  # Set the expiration time to 1 hour from the current time
    payload = {'user_id': user_id, 'exp': expiration}
    token = jwt.encode(payload, 'secret-secret-key', algorithm='HS256')
    return token



def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing'}), 401


        try:
            data = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
            current_user_id = data['user_id']
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token'}), 401


        return f(current_user_id, *args, **kwargs)


    return decorated



def model_to_dict(model):
    serialized_model = {}
    for key in model.__mapper__.c.keys():
        serialized_model[key] = getattr(model, key)
    return serialized_model



# Define protected routes
@app.route('/protected_route', methods=['GET'])
@jwt_required()  # This route requires a valid JWT token
def protected_route():
    current_user_id = get_jwt_identity()
    
    # Now you can use the current_user_id to get the user details or perform actions
    
    return jsonify({'message': 'This is a protected route', 'user_id': current_user_id})


@app.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    try:
        # Perform any necessary cleanup or token invalidation logic here...
        return jsonify({'message': 'Logout successful'}), 200
    except Exception as e:
        print(str(e))
        return jsonify({'error': 'Internal Server Error'}), 500


@app.route('/signup', methods=['POST'])
def signup():
    request_data = request.get_json()
    print(request_data)
    username = request_data['username']
    password = request_data['password']
    role = request_data['role']

    # Check if the username is already taken
    existing_user = Users.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({'message': 'Username is already taken'}), 400

    # Hash and salt the password using Bcrypt
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    # Create a new user and add to the database
    new_user = Users(username=username, password=hashed_password, role=role)
    db.session.add(new_user)
    db.session.commit()

    # Customize the response message based on the role
    if role == 'admin':
        return jsonify({'message': 'Admin created successfully'}), 201
    else:
        return jsonify({'message': 'User created successfully'}), 201




@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data["username"]
    password = data["password"]

    # Check if the user exists
    user = Users.query.filter_by(username=username).first()

    if user and bcrypt.check_password_hash(user.password, password):
        # Check if the provided role matches the user's current role
        if 'role' in data and data['role'] != user.role:
            return jsonify({'message': 'Invalid role for this user'}), 401

        # Generate an access token with an expiration time
        expires = datetime.timedelta(hours=1)

        if user.role == 'admin':
            # Admin token
            access_token = create_access_token(identity=user.id, expires_delta=expires, additional_claims={'role': 'admin'})
        else:
            # User token
            access_token = create_access_token(identity=user.id, expires_delta=expires, additional_claims={'role': 'user'})

        # Include the username and role in the response
        return jsonify({'access_token': access_token, 'username': user.username, 'role': user.role}), 200
    else:
        return jsonify({'message': 'Invalid username or password'}), 401




@app.route('/addcustomer', methods=['POST'])
def add_customer():
    data = request.get_json()

    name = data.get('name')
    city = data.get('city')
    age = data.get('age')

    new_customer = Customer(name=name, city=city, age=age)

    db.session.add(new_customer)
    db.session.commit()

    return jsonify({'message': 'Customer added successfully'})

@app.route('/addloan', methods=['POST'])
def add_loan():
    try:
        data = request.get_json()

        # Get customer and book names from the request data
        customer_name = data.get('customer_name')
        book_name = data.get('book_name')

        # Query customer and book by their names
        customer = Customer.query.filter_by(name=customer_name).first()
        book = Book.query.filter_by(name=book_name).first()

        # Check if the customer and book exist
        if not customer or not book:
            return jsonify({'error': 'Customer or book not found'}), 404

        # Create a new loan associated with the customer and book
        new_loan = Loan(loan_date=dt.now().strftime('%Y-%m-%d'), return_date='', customer=customer, book=book)

        db.session.add(new_loan)
        db.session.commit()

        return jsonify({'message': 'Loan added successfully'})

    except Exception as e:
        print(str(e))
        return jsonify({'error': 'Internal Server Error'}), 500



@app.route('/addbook', methods=['POST'])
def add_book():
    data = request.get_json()

    name = data.get('name')
    author = data.get('author')
    year_published = data.get('year_published')
    book_type = data.get('book_type')

    # Determine the maximum loan duration based on the book type
    max_loan_duration = {
        '1': 10,
        '2': 5,
        '3': 2
    }.get(book_type, 0)

    new_book = Book(name=name, author=author, year_published=year_published, book_type=book_type)

    db.session.add(new_book)
    db.session.commit()

    return jsonify({'message': 'Book added successfully', 'max_loan_duration': max_loan_duration})





@app.route('/listloans', methods=['GET'])
def list_loans():
    # Query all loans from the database with related customer and book information
    loans = Loan.query.join(Customer, Loan.customer_id == Customer.id).join(Book, Loan.book_id == Book.id).all()

    # Create a list of dictionaries containing loan information, customer name, and book name
    loan_list = [
        {
            'id': loan.id,
            'loan_date': loan.loan_date,
            'return_date': loan.return_date,
            'customer_name': loan.customer.name,
            'book_name': loan.book.name
        }
        for loan in loans
    ]

    # Return the list of loans as JSON
    return jsonify({'loans': loan_list})



@app.route('/listcustomers', methods=['GET'])
def list_customers():
    # Query all customers from the database
    customers = Customer.query.all()

    # Create a list of dictionaries containing customer information
    customer_list = [
        {
            'id': customer.id,
            'name': customer.name,
            'city': customer.city,
            'age': customer.age
        }
        for customer in customers
    ]

    # Return the list of customers as JSON
    return jsonify({'customers': customer_list})



@app.route('/listbooks', methods=['GET'])
def list_books():
    # Query all books from the database
    books = Book.query.all()

    # Create a list of dictionaries containing book information
    book_list = [
        {
            'id': book.id,
            'name': book.name,
            'author': book.author,
            'year_published': book.year_published,
            'book_type': book.book_type
        }
        for book in books
    ]

    # Return the list of books as JSON
    return jsonify({'books': book_list})

@app.route('/findbook/<string:book_name>', methods=['GET'])
def find_book(book_name):
    # Query the book by name
    book = Book.query.filter_by(name=book_name).first()

    # Check if the book exists
    if not book:
        return jsonify({'error': 'Book not found'}), 404

    # Return book information as JSON
    return jsonify({'book': {
        'id': book.id,
        'name': book.name,
        'author': book.author,
        'year_published': book.year_published,
        'book_type': book.book_type
    }})


@app.route('/findcustomer/<string:customer_name>', methods=['GET'])
def find_customer(customer_name):
    # Query the customer by name
    customer = Customer.query.filter_by(name=customer_name).first()

    # Check if the customer exists
    if not customer:
        return jsonify({'error': 'Customer not found'}), 404

    # Return customer information as JSON
    return jsonify({'customer': {
        'id': customer.id,
        'name': customer.name,
        'city': customer.city,
        'age': customer.age
    }})

@app.route('/returnbook/<string:book_name>', methods=['POST'])
def return_book_by_name(book_name):
    try:
        # Find the book by name
        book = Book.query.filter_by(name=book_name).first()

        # Check if the book exists
        if not book:
            return jsonify({'error': 'Book not found'}), 404

        # Find the latest loan for the book
        latest_loan = Loan.query.filter_by(book_id=book.id).order_by(Loan.id.desc()).first()

        # Check if there's an active loan for the book
        if not latest_loan or latest_loan.return_date:
            return jsonify({'error': 'No active loan for the book'}), 404

        # Update return_date for the loan
        latest_loan.return_date = datetime.now().strftime('%Y-%m-%d')
        db.session.commit()

        return jsonify({'message': 'Book returned successfully'})

    except Exception as e:
        print(str(e))
        return jsonify({'error': 'Internal Server Error'}), 500
    


@app.route('/lateloans', methods=['GET'])
def list_late_loans():
    # Query late loans from the database (loans with a return_date earlier than today)
    today = datetime.now().strftime('%Y-%m-%d')
    late_loans = Loan.query.filter(Loan.return_date < today).all()

    # Create a list of dictionaries containing late loan information
    late_loan_list = [
        {
            'id': loan.id,
            'loan_date': loan.loan_date,
            'return_date': loan.return_date
        }
        for loan in late_loans
    ]

    # Return the list of late loans as JSON
    return jsonify({'late_loans': late_loan_list})



if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

    
    
