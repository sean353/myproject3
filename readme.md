# Flask Library Management System

## Description

This Flask application serves as a simple library management system. It allows users to perform various tasks such as adding books, listing loans, managing customers, and more.

## Installation

1. **Clone the repository:**
   
   git clone https://github.com/sean353/myproject3.git
   

2. **Install dependencies:**
   
   pip install -r requirements.txt
   

## Usage

1. **Set up the SQLite database:**
   
   python
   from app import db
   db.create_all()
  

2. **Run the Flask application:**
    cd backend and then py app.py
   
   

3. **Access the API endpoints using tools like `curl` or `Postman`.**

## API Endpoints

- `/login` (POST): Endpoint for user authentication and token generation.
- `/logout` (POST): Endpoint to log out a user.
- `/protected_route` (GET): Protected endpoint requiring a valid JWT token.
- `/addcustomer` (POST): Endpoint to add a new customer to the database.
- `/addloan` (POST): Endpoint to add a new loan.
- `/addbook` (POST): Endpoint to add a new book to the database.
- `/listloans` (GET): Endpoint to list all loans.
- `/listcustomers` (GET): Endpoint to list all customers.
- `/listbooks` (GET): Endpoint to list all books.
- `/findbook/<string:book_name>` (GET): Endpoint to find a book by name.
- `/findcustomer/<string:customer_name>` (GET): Endpoint to find a customer by name.
- `/deleteloan` (DELETE): Endpoint to delete a loan by ID.
- `/userloans` (GET): Endpoint to retrieve loans associated with a specific user.

## Dependencies

- Flask
- Flask-CORS
- Flask-SQLAlchemy
- Flask-JWT-Extended
- Flask-Bcrypt

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
