# User-Management
User Management Web App with Flask

This is a user management web application built using Flask, bcrypt for password hashing, and PostgreSQL for the database. The backend is the main focus of this project.

Setup

To set up the app, follow these steps:

Clone the repository to your local machine.

Create a .env file in the root directory and define the following environment variables:

DATABASE_URI=your_database_uri_here
Make sure to replace your_database_uri_here with the URI of your own database. Remember to keep the .env file ignored by Git. Users of your code will need to implement their own database.

Install the required dependencies using pip install -r requirements.txt.

Run the app using python app.py.

User Roles

Admin User

An “admin” user is required for full access to user management functions, including the ability to add, remove, or retrieve user information.

Normal Users

Normal users have limited access and are only able to view the home page of the application.
