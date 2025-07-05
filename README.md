# 🎓 Symposium Registration & Management System

A lightweight web application for managing symposium registrations. Built with **static HTML/CSS/JavaScript** for the frontend and **Node.js + Express.js** for the backend, connected to a **TiDB Cloud** database.

This system enables students to register for events, while admins can manage event data and user submissions through secure backend routes.

---

## 🌐 Live URL

👉 [Live Site](https://phantasm.onrender.com)

---

## 📌 Features

### 👥 User Module
- Register for symposium events via HTML forms
- View personal registration details
- Receive real-time confirmation after registration

### 🔐 Admin Module
- Secure login with JWT authentication
- View, filter, and manage all registered users
- Access event-specific user lists via dynamic routes

---

## 🛠️ Tech Stack

| Layer        | Tech Used                 |
|--------------|---------------------------|
| Frontend     | HTML, CSS, JavaScript     |
| Backend      | Node.js, Express.js       |
| Database     | TiDB Cloud                |
| Auth         | JSON Web Tokens (JWT)     |
| Deployment   | Render  |

---

---

## 🚀 Getting Started

### 1. Clone the repo

```bash
git clone https://github.com/yourusername/symposium-project.git
cd symposium-project
```

### 2. Install backend dependencies

```bash
npm install
```

### 3. Setup environment variables

Create a `.env` file in the root directory:

```env
PORT=5000
DB_URI=gateway01.ap-southeast-1.prod.aws.tidbcloud.com
JWT_SECRET=your_secret_key
```

### 4. Run the server

```bash
node server.js
```

> The server will serve HTML pages from the `/public` folder and expose API endpoints.

---

## 📄 Important Pages

| Route                | Purpose                          |
|----------------------|----------------------------------|
| `/register.html`     | User registration page           |
| `/profile.html`      | Display user's data              |
| `/adminlogin.html`   | Admin login form                 |
| `/adminprofile.html` | Admin dashboard                  |

---

## 🔐 Authentication

- Admin routes are protected using JWT.
- Tokens are stored securely in cookies and verified on each request.

---

## ☁️ Deployment
- **Frontend & Backend** deployed on Render functions.
- **Database** hosted on TiDB Cloud.

---

## 👨‍💻 Developed By

WEB DEVELOPMENT TEAM-2025
-GCE BARGUR
---

## 📜 License

This project is licensed under the MIT License.
