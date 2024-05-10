<!-- @format -->

# User Authentication and Profile Management API

## Introduction

This API provides endpoints for user authentication, registration, login, profile management, and admin functionalities

## Base URL

The base URL for all endpoints is http://yourdomain.com/.

## Authentication

Authentication is handled via JSON Web Tokens (JWT) and OAuth2 with Google.

## Register a New User

Register a new user with the provided information.

URL: /register
Method: POST
Request Body: See example in API documentation.
Response: See example in API documentation.
Request Body

{
"name": "string",
"email": "string",
"password": "string",
"phoneNumber": "string",
"role": "string"
}

## Login

Authenticate a user and retrieve a JWT token.

URL: /login
Method: POST
Request Body: See example in API documentation.
Response: See example in API documentation.
Profile Management
Manage user profiles including viewing and updating user details.

Request Body:
{
"email": "string",
"password": "string"
}

## Get Current User's Profile

Retrieve the profile of the currently authenticated user.

URL: /myProfile
Method: GET
Headers: Authorization: Bearer <token>
Edit User Profile
Update the profile of the currently authenticated user.
Response:
{
"name": "string",
"email": "string",
"bio": "string",
"phoneNumber": "string",
"isPublic": "boolean",
"photo": "string",
"role": "string"
}

URL: /editProfile
Method: PUT
Headers: Authorization: Bearer <token>
Request Body:
{
"name": "string",
"bio": "string",
"phoneNumber": "string",
"email": "string",
"password": "string",
"isPublic": "boolean",
"photo": "string",
"role": "string"
}

Admin Endpoints
Access administrative functionalities such as viewing all users.

## Get All Users

Retrieve the profiles of all users (requires admin privileges).

URL: /allUsers
Method: GET
Headers: Authorization: Bearer <token>
Response :
[
{
"name": "string",
"email": "string",
"bio": "string",
"phoneNumber": "string",
"isPublic": "boolean",
"photo": "string",
"role": "string"
}
]
