# DigitalBank

A microservices-based digital banking platform built with Django REST Framework.  
Each service is independently deployable and comes with a full suite of tests.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)  
2. [Services](#services)  
3. [Prerequisites](#prerequisites)  
4. [Getting Started](#getting-started)  
   - [Clone the Repo](#clone-the-repo)  
   - [Environment Variables](#environment-variables)  
   - [Running Services Locally](#running-services-locally)  
5. [API Documentation](#api-documentation)  
6. [Testing](#testing)  
7. [Continuous Integration](#continuous-integration)  
8. [Deployment](#deployment)  
9. [Contributing](#contributing)  
10. [License](#license)  

---

## Architecture Overview

DigitalBank follows a microservice architecture. Each service is a separate Django project exposing a RESTful API. Services communicate over HTTP (JSON) and share data via events (e.g., via RabbitMQ or Kafka).  

<!-- ![Microservices Diagram](docs/architecture.png) -->

---

## Services

| Service Name            | Description                                         | Port  |
|-------------------------|-----------------------------------------------------|-------|
| **user-service**        | User registration, login, JWT issuance, permissions | 8001  |
| **account-service**     | Account creation, balance inquiries, account types  | 8002  |
| **transaction-service** | Funds transfer, transaction history                 | 8003  |
| **notification-service**| Email/SMS notifications                             | 8004  |
| **gateway-service**     | API gateway / reverse proxy routing to services     | 8000  |

---

## Prerequisites

- Python 3.10+  
- Docker & Docker Compose (optional but recommended)  
- PostgreSQL 13+ (or via Docker)  
- RabbitMQ or Kafka (for event-driven features)  
- Redis (for caching, rate limiting)

---

## Getting Started

### Clone the Repo

```bash
git clone https://github.com/Lokie-codes/digital-bank.git
cd digital-bank
````

### Environment Variables

Create a `.env` file in each service’s root (or centrally) with:

```dotenv
# Example for auth-service
# User service DB
USER_POSTGRES_DB=user_db
USER_POSTGRES_USER=user_db_user
USER_POSTGRES_PASSWORD=user_db_pass
USER_POSTGRES_HOST=user_db
USER_POSTGRES_PORT=5432

# Common
USE_POSTGRES=1
DJANGO_SECRET_KEY=your_secret_key
DEBUG=0
```
Be sure to change values to your current configurations.

### Running Services Locally

#### Option 1: With Docker Compose

```bash
docker-compose up --build
```

All services will be available at `http://localhost:<port>`.

#### Option 2: Manually
0. Choose the service to run:
    ```
    cd <service-name>
    ``` 
1. Create & activate a virtualenv:

   ```bash
   python -m venv .venv
   source .venv/bin/activate
   # For Windows
   # .venv\bin\activate.bat
   ```
2. Install dependencies in each service:

   ```bash
   pip install -r requirements.txt
   ```
3. Apply migrations & run:

   ```bash
   python manage.py migrate
   python manage.py runserver 0.0.0.0:800X
   ```
    Make sure to use different ports for different services.
---

## API Documentation

Each service exposes interactive docs at `/api/docs/` (Swagger / ReDoc):

* Auth:  `http://localhost:8001/api/docs/`
* Account:  `http://localhost:8002/api/docs/`
* Transaction:  `http://localhost:8003/api/docs/`
* Notification:  `http://localhost:8004/api/docs/`

Example endpoint for creating a new user (User Service):

```http
POST /api/users/
Content-Type: application/json

{
  "username": "jdoe",
  "email": "jdoe@example.com",
  "password": "StrongPass!23",
  "password2": "StrongPass!23"
}
```

---

## Testing

Every service includes unit and integration tests using **pytest** and **Django’s TestCase**. To run tests:

```bash
# From the root of each service:
pytest --maxfail=1 --disable-warnings -q
```

Or via Docker Compose:

```bash
docker-compose run --rm auth-service pytest
```

---

## Deployment

1. Build Docker images:

   ```bash
   docker build -t digitalbank/auth-service ./auth-service
   ```
2. Push to your container registry.
3. Deploy with Kubernetes / Docker Swarm / AWS ECS.
4. Use a managed PostgreSQL, Redis, and RabbitMQ in production.
5. Configure environment-specific settings via your orchestrator’s secret manager.

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/awesome-feature`
3. Write tests & code
4. Commit: `git commit -m "Add awesome feature"`
5. Push & open a PR

Please follow our [Code of Conduct](CODE_OF_CONDUCT.md).

---

## License

This project is licensed under the [MIT License](LICENSE).
