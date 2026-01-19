# 🐾 Waggetails Backend API

Backend API for **Waggetails**, a social networking platform for pets and pet lovers. This project is built using the **MERN stack**, leveraging **Node.js**, **Express.js**, and **MongoDB**.

---

## 📖 Table of Contents

* [🌟 Overview](#overview)
* [✨ Features](#features)
* [🛠️ Tech Stack](#tech-stack)
* [🚀 Getting Started](#getting-started)
    * [Prerequisites](#prerequisites)
    * [Installation](#installation)
    * [Running the Server](#running-the-server)
* [🔑 Environment Variables](#environment-variables)
* [🧭 API Endpoints](#api-endpoints)
* [📦 Database Models](#database-models)
* [🔐 Authentication & Authorization](#authentication-authorization)
* [🧪 Running Tests](#running-tests)
* [☁️ Deployment](#deployment)
* [🤝 Contributing](#contributing)
* [📜 License](#license)

---

## 🌟 Overview

The Waggetails backend provides robust **RESTful, JSON-based APIs** to power the social platform, including:

* **User & Pet Profiles:** Management of user and associated pet accounts.
* **Content Management:** APIs for creating, liking, and commenting on posts.
* **Verification Workflow:** System for verifying pet accounts/users.
* **Notifications & Messaging:** Real-time updates and direct communication between users.
* **Admin Moderation:** Tools for content review and user management.

---

## ✨ Features

* **JWT-based Authentication** for secure user sessions.
* Support for **multi-pet accounts** per single user profile.
* **Content uploads** (images/videos) managed via **AWS S3 / Cloudinary**.
* Dynamic **Feed & Discovery System**.
* **Admin Panel** for content moderation and verification.
* **Real-time Notifications** using **WebSocket / Firebase**.

---

## 🛠️ Tech Stack

| Category | Technology | Notes |
| :--- | :--- | :--- |
| **Backend** | Node.js, Express.js | Core server framework |
| **Database** | MongoDB, Mongoose ODM | Data persistence and schema management |
| **Authentication** | JWT, OAuth (Google, Facebook, Apple) | Secure token-based and social login |
| **File Storage** | AWS S3 / Cloudinary | Handling media uploads and storage |
| **Notifications** | Firebase / WebSocket | Real-time communication |
| **Hosting** | AWS EC2 / Heroku | Deployment environment |
| **Other** | `dotenv`, `bcryptjs`, `express-validator` | Configuration, password hashing, and input validation |

---

## 🚀 Getting Started

### Prerequisites

Ensure you have the following software installed:

* **Node.js** `>= 18.x`
* **npm** `>= 9.x`
* **MongoDB Atlas** or a local MongoDB instance.

### Installation

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/mixcommerceco/api.waggetails.com.git](https://github.com/mixcommerceco/api.waggetails.com.git)
    cd api.waggetails.com
    ```
2.  **Install project dependencies:**
    ```bash
    npm install
    ```

### Running the Server

Before running, make sure to set up your environment variables (see next section).

| Command | Purpose |
| :--- | :--- |
| `npm run dev` | Starts the server in **development mode** using `nodemon` for automatic restarts. |
| `npm start` | Starts the server for **production** use. |

---

## 🔑 Environment Variables

Create a file named **`.env`** in the root directory of the project to securely store your configuration. This file is ignored by Git.

```dotenv
# Example .env contents
PORT=5000
NODE_ENV=development

# Database
MONGO_URI=mongodb+srv://<username>:<password>@<cluster-url>/waggetails

# Authentication
JWT_SECRET=YOUR_VERY_SECURE_JWT_SECRET
OAUTH_GOOGLE_CLIENT_ID=...

# File Storage
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
AWS_S3_BUCKET_NAME=...
