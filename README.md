# User Management Service

A microservice for user registration, authentication, profile management, and role-based access control. Built with Node.js, Express, and MongoDB.

## Features

- User registration with email and password
- JWT-based authentication
- Profile retrieval and update
- Role-based access control (Admin/User)
- Password hashing with bcrypt
- Request logging with Winston

## Tech Stack

- **Runtime:** Node.js
- **Framework:** Express
- **Database:** MongoDB (Mongoose)
- **Auth:** JWT + bcrypt
- **Logging:** Winston

## Setup

1. Clone the repository:
```bash
    git clone https://github.com/abunnazeer/user-management-service.git
    cd user-management-service
```

2. Install dependencies:
```bash
    npm install
```

3. Create a `.env` file:
```
    NODE_ENV=development
    PORT=3000
    DATABASE_URL=<your_mongodb_url>
    SECRET_KEY=<your_jwt_secret>
```

4. Run the service:
```bash
    npm run dev
```

## API Endpoints

| Method | Route | Description | Auth |
|--------|-------|-------------|------|
| POST | `/register` | Register a new user | No |
| POST | `/login` | Authenticate and get token | No |
| GET | `/profile` | Get current user profile | Yes |
| PUT | `/profile` | Update current user profile | Yes |
| DELETE | `/users/:id` | Delete a user | Admin |

## Author

**Abdullahi Ahmad** — [GitHub](https://github.com/abunnazeer)

## License

MIT