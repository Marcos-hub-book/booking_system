# Booking System

This is an online scheduling system designed for beauty salons, clinics, and small businesses. It provides functionalities for managing appointments, professionals, and services through a user-friendly interface.

## Features

- User authentication for clients and administrators
- Scheduling appointments with professionals
- Management of services offered by professionals
- Responsive design suitable for mobile devices
- Admin dashboard for managing users and appointments

## Project Structure

```
booking_system
├── app
│   ├── __init__.py
│   ├── models.py
│   ├── routes.py
│   ├── forms.py
│   ├── static
│   │   ├── css
│   │   │   └── styles.css
│   │   └── js
│   │       └── scripts.js
│   └── templates
│       ├── base.html
│       ├── index.html
│       ├── login.html
│       ├── register.html
│       ├── dashboard.html
│       ├── schedule.html
│       └── admin.html
├── migrations
│   └── README.md
├── config.py
├── requirements.txt
└── README.md
```

## Installation

1. Clone the repository:
   ```
   git clone <repository-url>
   cd booking_system
   ```

2. Create a virtual environment:
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

3. Install the required packages:
   ```
   pip install -r requirements.txt
   ```

4. Set up the database:
   - Update the database URI in `config.py` with your PostgreSQL credentials.
   - Run migrations:
     ```
     flask db init
     flask db migrate
     flask db upgrade
     ```

## Running the Application

To run the application locally, use the following command:
```
flask run
```
The application will be accessible at `http://127.0.0.1:5000`.

## Deployment

For deployment on Render or other platforms, follow the respective documentation for setting up a Flask application.

## Testing

To test the scheduling functionality, navigate to the scheduling page after logging in as a client. You can create, view, and manage appointments.

## License

This project is licensed under the MIT License.