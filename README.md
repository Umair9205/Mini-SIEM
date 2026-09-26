# Mini-SIEM

A security monitoring project built with Flask and PostgreSQL. It records successful and failed login attempts, database errors, and related IP addresses so an admin can review activity in one place.

## Features

- Live security event feed
- INFO, WARNING, and ERROR log levels
- Admin-only dashboard
- Password hashing with bcrypt
- Parameterized SQL queries
- 15-minute admin session timeout

## Stack

Python · Flask · PostgreSQL (Neon) · HTML · CSS · JavaScript

## Setup

Install the dependencies:

    pip install flask bcrypt pg8000 python-dotenv flask-wtf 

Add your database connection and Flask secret key to `.env`:

    DATABASE_URL=your_database_url
    SECRET_KEY=your_secret_key

Create the database tables required by the backend and an admin account with a bcrypt password hash. Start the Flask app and visit `/admin`.

Never commit your `.env` file.
