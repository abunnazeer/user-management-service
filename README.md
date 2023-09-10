
# User Management Service

## Overview

The User Management Service is a microservice responsible for all user-related functionalities in the healthcare management system. This includes user registration, authentication, profile management, and user roles and permissions.

## Table of Contents

- [Installation](#installation)
- [Environment Variables](#environment-variables)
- [Running the Service](#running-the-service)
- [API Endpoints](#api-endpoints)
- [Testing](#testing)
- [Contributing](#contributing)
- [License](#license)

## Installation

1. Clone the repository:
    ```bash
    git clone <repository_url>
    ```

2. Navigate to the project directory:
    ```bash
    cd UserManagementService
    ```

3. Install dependencies:
    ```bash
    npm install
    ```

## Environment Variables

Create a `.env` file in the root directory and add the following:

```
NODE_ENV=development
PORT=3000
DATABASE_URL=<your_database_url>
SECRET_KEY=<your_secret_key>
```

## Running the Service

To start the service, run:

```bash
npm start
```

Or to run in development mode with nodemon:

```bash
npm run dev
```

## API Endpoints

- `POST /register`: Register a new user
- `POST /login`: Authenticate a user
- `GET /profile`: Get the profile of the authenticated user
- `PUT /profile`: Update the profile of the authenticated user
- `DELETE /users/:id`: Delete a user by ID (Admin only)

For detailed API documentation, please refer to [API_DOCS.md](API_DOCS.md).

## Testing

Run the test suite using:

```bash
npm test
```

## Contributing

Please read the [CONTRIBUTING.md](CONTRIBUTING.md) for details on how to contribute to this project.

## License

This project is licensed under the MIT License. See the [LICENSE.md](LICENSE.md) file for details.
