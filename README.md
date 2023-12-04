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

An "admin" user has full access to user management functions, including:

- Adding new users
- Removing existing users
- Retrieving user information
- Managing user roles and permissions

### Normal Users

Normal users have restricted access and are able to:

- View the home page
- Log in and log out
   
