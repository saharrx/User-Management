# User Management Web App with Flask

This is a user management web application built using Flask, bcrypt for password hashing, and PostgreSQL for the database. The backend is the main focus of this project.

## Setup

To set up the app, follow these steps:

1. Clone the repository to your local machine.
2. Create a `.env` file in the root directory and define the following environment variables:

   DATABASE_URI=your_database_uri_here

3. Install the required dependencies using `pip install -r requirements.txt`.

4. Run the app using `python app.py`.

## User Roles

### Admin User

An "admin" user is required for full access to user management functions, including the ability to add, remove, or retrieve user information.

### Normal Users

Normal users have limited access and are only able to view the home page of the application.
   
