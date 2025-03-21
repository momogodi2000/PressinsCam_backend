# Contour Wash Backend

This repository contains the backend code for the Contour Wash application, a digital platform for laundry and shoe maintenance services in Cameroon.

## Overview

The Contour Wash backend is built with Django and Django REST Framework to provide a robust, scalable API for the web and mobile frontends. The system is designed to handle all business logic, data storage, authentication, and third-party integrations while considering the unique operational context of Cameroon.

## Features

- **User Management**
  - Multi-role authentication (customers, delivery personnel, administrators)
  - Profile management
  - Permission-based access control
  - Session management and token authentication

- **Order Processing**
  - Service catalog management
  - Order creation and tracking
  - Dynamic pricing based on service combinations
  - Scheduling system for pickups and deliveries

- **Payment Integration**
  - MTN Mobile Money integration
  - Orange Money integration
  - Transaction history and receipts
  - Automated payment confirmation

- **Delivery Management**
  - Delivery personnel assignment
  - Route optimization
  - Real-time status updates
  - Geolocation tracking

- **Analytics and Reporting**
  - Business performance metrics
  - Service utilization statistics
  - Financial reporting
  - Operational efficiency metrics

- **Notification System**
  - SMS notifications
  - Email notifications
  - In-app real-time updates via WebSockets

## Tech Stack

- **Django** - Web framework
- **Django REST Framework** - API development
- **PostgreSQL** - Primary database
- **Redis** - Caching and task queue
- **Celery** - Background task processing
- **Channels** - WebSocket support
- **Django CORS Headers** - Cross-origin resource sharing
- **Django OAuth Toolkit** - Authentication
- **dj-rest-auth** - Authentication endpoints
- **Django Storages** - File storage
- **django-phonenumber-field** - Phone number handling

## Requirements

- Python 3.9+
- PostgreSQL 13+
- Redis 6+

## Getting Started

1. Clone the repository:
   ```bash
   git clone https://github.com/contourwash/backend.git
   cd backend
   ```

2. Set up a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Set up environment variables:
   Create a `.env` file in the root directory with the following variables:
   ```
   SECRET_KEY=your_secret_key
   DEBUG=True
   DATABASE_URL=postgres://user:password@localhost:5432/contourwash
   REDIS_URL=redis://localhost:6379/0
   ALLOWED_HOSTS=localhost,127.0.0.1
   CORS_ALLOWED_ORIGINS=http://localhost:3000
   
   # Payment Integration
   MTN_MOMO_API_KEY=your_mtn_api_key
   MTN_MOMO_USER_ID=your_mtn_user_id
   ORANGE_MONEY_API_KEY=your_orange_api_key
   
   # SMS Service
   SMS_API_KEY=your_sms_api_key
   
   # Email
   EMAIL_HOST=smtp.gmail.com
   EMAIL_PORT=587
   EMAIL_HOST_USER=your_email@gmail.com
   EMAIL_HOST_PASSWORD=your_email_password
   ```

5. Run migrations:
   ```bash
   python manage.py migrate
   ```

6. Create a superuser:
   ```bash
   python manage.py createsuperuser
   ```

7. Start the development server:
   ```bash
   python manage.py runserver
   ```

8. Start Celery worker (in a separate terminal):
   ```bash
   celery -A contourwash worker -l info
   ```

## Project Structure

```
contourwash/
├── api/                # Main API application
│   ├── serializers/    # DRF serializers
│   ├── views/          # API views
│   ├── permissions/    # Custom permissions
│   └── validators/     # Custom validators
├── accounts/           # User authentication and profiles
├── services/           # Service catalog management
├── orders/             # Order processing and management
├── payments/           # Payment integrations
├── deliveries/         # Delivery management
├── notifications/      # Notification system
├── analytics/          # Reporting and analytics
├── utils/              # Utility functions and helpers
├── contourwash/        # Project settings
│   ├── settings/       # Split settings for different environments
│   ├── urls.py         # Main URL configuration
│   └── asgi.py         # ASGI configuration (for WebSockets)
└── manage.py           # Django management script
```

## API Documentation

API documentation is available at `/api/docs/` when the server is running in development mode. It provides detailed information about all endpoints, required parameters, and response formats.

## Backend Services

### Celery Tasks

The backend uses Celery for handling background tasks such as:
- Sending notification emails and SMS
- Generating reports
- Processing payment confirmations
- Scheduling reminders
- Daily data backups

### WebSockets

Real-time features are implemented using Django Channels:
- Order status updates
- Delivery tracking
- Chat between customers and delivery personnel
- Admin notifications

## Database Schema

The main entities in the database are:
- Users (Customer, DeliveryPersonnel, Administrator)
- Services (LaundryService, DryCleaningService, ShoeService)
- Orders
- OrderItems
- Payments
- Deliveries
- Locations
- Ratings
- Notifications

## Deployment

The application is designed to be deployed on:
- AWS EC2
- Heroku
- DigitalOcean
- PythonAnywhere

For production deployment:
1. Set `DEBUG=False` in environment variables
2. Configure database connection settings
3. Set up a production-ready web server (Gunicorn, uWSGI)
4. Configure Nginx as a reverse proxy
5. Set up SSL certificates for HTTPS

## Testing

```bash
# Run tests
python manage.py test

# Run tests with coverage
coverage run --source='.' manage.py test
coverage report
```

## Security Considerations

- HTTPS enforced in production
- CSRF protection enabled
- Cross-Origin Resource Sharing (CORS) properly configured
- SQL injection protection via ORM
- XSS protection
- Regular security updates and dependency monitoring
- Sensitive data encryption
- Rate limiting on authentication endpoints

## Monitoring and Logging

- Django Debug Toolbar (development)
- Sentry integration (error tracking)
- Custom logging configuration
- Performance monitoring

## Localization

The backend supports both French and English locales, with translations for API responses, error messages, and notifications.

## Contributing

1. Fork the repository
2. Create your feature branch: `git checkout -b feature/amazing-feature`
3. Commit your changes: `git commit -m 'Add some amazing feature'`
4. Push to the branch: `git push origin feature/amazing-feature`
5. Open a Pull Request

## License

Proprietary - Contour Wash © 2025

## Contact

For any queries related to the backend development, please contact:
- Email: contourwash@gmail.com
- Phone: +237 695922065