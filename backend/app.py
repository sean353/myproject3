
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask import Flask, request, jsonify
from datetime import datetime as dt, timedelta
from flask_jwt_extended import JWTManager , create_access_token
from icecream import ic 
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

# configure the SQLite database, relative to the app instance folder
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
    loans= db.relationship("Loan",backref="books", cascade="all, delete-orphan")

   

class Customer(db.Model):
    __tablename__ = 'customers'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(45), nullable=False, unique=True)
    password = db.Column(db.String(45), nullable=False)
    role = db.Column(db.String(45), nullable=False, default='user')  # Assuming 'user' is the default role
    name = db.Column(db.String(45), nullable=False)
    city = db.Column(db.String(45), nullable=False)
    age = db.Column(db.Integer, nullable=False)
    loans= db.relationship("Loan",backref="customers", cascade="all, delete-orphan")
    
    

class Loan(db.Model):
    __tablename__ = 'loans'
    id = db.Column(db.Integer, primary_key=True,)
    loan_date = db.Column(db.Date ,default = dt.now(), nullable=False)
    return_date = db.Column(db.Date,nullable = True)
    is_returned = db.Column(db.Boolean, default=False, nullable=True)


    # Foreign keys referencing Customer and Book
    customer_id = db.Column(db.Integer, db.ForeignKey('customers.id'), nullable=False)
    book_id = db.Column(db.Integer, db.ForeignKey('books.id'), nullable=False)
    
   

    def __init__(self,customer_id,book_id):
        book = Book.query.get(book_id)
        book_type = ic(book.book_type)
        if book_type == '1':
            self.return_date = dt.now() + timedelta(days=10)
            ic(self.return_date)
        if book_type == '2':
            self.return_date = dt.now() + timedelta(days=5)
        if book_type == '3':
            self.return_date = dt.now() + timedelta(days=2)
        return_date = self.return_date
        ic(return_date)
        super().__init__(customer_id=customer_id,book_id=book_id)


    def is_return_date_passed(self):
        """
        Check if the return date has passed for the loan.

        Returns:
            bool: True if the return date has passed, False otherwise.

        """
       
        if (dt.now().date()) > self.return_date:
            return True
        return False




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

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        username = data["username"]
        password = data["password"]

        # Check if the user exists
        user = Customer.query.filter_by(username=username).first()

        if not user or not bcrypt.check_password_hash(user.password, password):
            return jsonify({'message': 'Invalid username or password'}), 401

            # # Check if the provided role matches the user's current role
            # if 'role' in data and data['role'] != user.role:
            #     return jsonify({'message': 'Invalid role for this user'}), 401
            
            # ic("==========================================")

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

    except Exception as e:
        print("Login error:", str(e))
        return jsonify({'message': 'Internal Server Error'}), 500


@app.route('/addcustomer', methods=['POST'])
def add_customer():
    data = request.get_json()
    name = data.get('name')
    username = data.get('username')
    password = data.get('password')
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    role = data.get('role')
    city = data.get('city')
    age = data.get('age')

    new_customer = Customer(name=name, city=city, age=age,username=username,password=hashed_password,role=role)

    db.session.add(new_customer)
    db.session.commit()


    
    if role.lower() == 'admin':
        return jsonify({'message': 'Admin added successfully'})
    else:
        return jsonify({'message': 'Customer added successfully'})
    
@app.route('/addloan', methods=['POST'])
@jwt_required() 
def add_loan():
    try:
        data = request.get_json()

        # Get customer ID and book name from the request data
        customer_id = get_jwt_identity()
        book_name = data.get('book_name')

        # Query customer by ID and book by name
        customer = Customer.query.filter_by(id=customer_id).first()
        book = Book.query.filter_by(name=book_name).first()

        # Check if the customer and book exist
        if not customer or not book:
            return jsonify({'error': 'Customer or book not found'}), 404
        
         # Check if the customer has already borrowed the book
        existing_loan = Loan.query.filter_by(customer_id=customer.id, book_id=book.id).all()

        if len(existing_loan) > 0 :

            if  existing_loan[-1] and existing_loan[-1].is_returned == False:
                ic("in the if")
                ic( existing_loan[-1] and existing_loan[-1].is_returned == False)
                return jsonify({'error': 'Customer has already borrowed this book'}), 400
            
        
        # Create a new loan associated with the customer and book
        new_loan = Loan(
            # loan_date=dt.now().strftime('%Y-%m-%d'),
            # return_date="",
            customer_id=customer.id,  # Use the customer_id foreign key
            book_id=book.id  # Use the book_id foreign key
        )

        db.session.add(new_loan)
        db.session.commit()

        return jsonify({'message': 'Loan added successfully'}), 201

    except Exception as e:
        print(str(e))
        return jsonify({'error': 'Internal Server Error'}), 500



@app.route('/addbook', methods=['POST'])
@jwt_required() 
def add_book():
    data = request.get_json()
    print(data)

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

    # Create a list of dictionaries containing loan information, customer name, book name, and max_loan_duration
    loan_list = [
        {
            'loan_date': loan.loan_date.strftime('%Y-%m-%d'),  # Format loan_date as 'YYYY-MM-DD'
            'return_date': loan.return_date.strftime('%Y-%m-%d') if loan.return_date else None,  # Format return_date as 'YYYY-MM-DD'
            'customer_name': loan.customers.name,  # Use the 'name' attribute of the Customer model
            'book_name': loan.books.name,  # Use the 'name' attribute of the Book model
            'max_loan_duration': {
                '1': "10 days",
                '2': "5 days",
                '3': "2 days"
            }.get(loan.books.book_type, 0),  # Calculate max_loan_duration based on book_type
            'return_status': "Returned" if loan.is_returned else "Not Returned",  # Add return_status based on return_date
            'availability_status': is_book_available(loan.books.id)  # Check book availability
        }
        for loan in loans
    ]

    # Return the list of loans as JSON
    return jsonify({'loans': loan_list})

def is_book_available(book_id):
    # Implement your logic to check if the book is available
    # For example, check if the book is currently on loan or available in stock
    # You might need to adapt this based on your database structure and loan logic

    # Assuming that if the book is on loan, it is not available
    return not Loan.query.filter_by(book_id=book_id, return_date=None).first()



@app.route('/listcustomers', methods=['GET'])
@jwt_required() 
def list_customers():
    # Query all customers from the database
    customers = Customer.query.all()
    customer_list =[]
    # Create a list of dictionaries containing customer information
    for customer in customers:
        if customer.role == "user":
            customer_list.append({
                "name" :customer.name,
                "role" :customer.role,
                "city" :customer.city,
                "age" :customer.age
                
            })
    ic("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")
    ic(customer_list)


    # Return the list of customers as JSON
    return jsonify({'customers': customer_list})



@app.route('/listbooks', methods=['GET'])
@jwt_required()
def list_books():
    books = Book.query.all()
    book_list = []

    for book in books:
        # Calculate MAX_LOAN_DURATION based on book_type
        max_loan_duration = {
            '1': "10 days",
            '2': "5 days",
            '3': "2 days"
        }.get(book.book_type, 0)

        book_data = {
            'id': book.id,
            'name': book.name,
            'author': book.author,
            'year_published': book.year_published,
            'max_loan_duration': max_loan_duration  # Include MAX_LOAN_DURATION in the response
        }

        book_list.append(book_data)

    return jsonify({'books': book_list})

@app.route('/findbook/<string:book_name>', methods=['GET'])
@jwt_required()
def find_book(book_name):
    # Query the book by name
    book = Book.query.filter_by(name=book_name).first()

    # Check if the book exists
    if not book:
        return jsonify({'error': 'Book not found'})

    # Return book information including max_loan_duration as JSON
    return jsonify({'book': {
        'id': book.id,
        'name': book.name,
        'author': book.author,
        'year_published': book.year_published,
        'book_type': book.book_type,
        'max_loan_duration': {
            '1': "10 days",
            '2': "5 days",
            '3': "2 days"
        }.get(book.book_type, 0)
    }})

@app.route('/findcustomer/<string:customer_name>', methods=['GET'])
@jwt_required() 
def find_customer(customer_name):
    # Query the customer by name
    customer = Customer.query.filter_by(name=customer_name).first()

    # Check if the customer exists
    if not customer:
        return jsonify({'error': 'Customer not found'})

    # Return customer information as JSON
    return jsonify({'customer': {
        'id': customer.id,
        'name': customer.name,
        'city': customer.city,
        'age': customer.age
    }})

@app.route('/deleteloan/', methods=['DELETE'])
@jwt_required()  # Requires a valid access token
def delete_loan_by_id():
    try:
        ic("-------------------------------------")
        current_user = get_jwt_identity()


        # Find the user by ID
        user = Customer.query.filter_by(id=current_user).first()

        ic("------------------------")
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        loan_list_from_payload = request.get_json()["loan_ids"]


        

        for loan_id in loan_list_from_payload:
            # Find the loan by ID
            loan = Loan.query.filter_by(id=loan_id, customer_id=user.id).first()

            ic(loan_list_from_payload)
            if not loan:
                return jsonify({'error': 'Loan not found or does not belong to the user'}), 404
            
            loan.is_returned = True
        

            # Delete the loan
            #db.session.delete(loan)
            db.session.commit()

        return jsonify({'message': 'Loan deleted successfully'})
    except Exception as e:
        print(str(e))
        return jsonify({'error': 'Internal Server Error'}), 500



@app.route('/userloans', methods=['GET'])
@jwt_required()
def get_user_loans():
    try:
        # Get user ID from the JWT token
        user_id = get_jwt_identity()

        # Query user-specific loans from the database
        user_loans = (
            db.session.query(Loan, Book)
            .join(Book, Loan.book_id == Book.id)
            .filter(Loan.customer_id == user_id)
            .all()
        )

        # Create a list of dictionaries containing loan information
        loan_list = [
            {
                'id':loan.Loan.id,
                'loan_date': loan.Loan.loan_date,
                'return_date': loan.Loan.return_date,
                'book_name': loan.Book.name,
                
            }
            for loan in user_loans
        ]
  

        # Return the list of user loans as JSON
        return jsonify({'loans': loan_list})

    except Exception as e:
        print(str(e))
        return jsonify({'error': 'Internal Server Error'}), 500



if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    
    app.run(debug=True)

    
    
