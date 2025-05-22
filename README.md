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

## 📁 Project Structure

```
/public                 # All HTML/CSS/JS files (served statically)
/routes                 # Route files for admin, auth, events, and profile
/controllers            # Logic for handling routes
/models                 # DB queries and schema abstraction
/server.js              # Express.js entry point
.env                    # Environment variables
README.md               # Project overview
```

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
DB_URI=your_tidb_connection_string
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

- **Frontend** deployed as static files on Vercel.
- **Backend** deployed on Render or Vercel functions.
- **Database** hosted on TiDB Cloud.

---

## 👨‍💻 Developed By

**Elango**  
Final Year CSE, Government College of Engineering, Bargur  
[GitHub](https://github.com/yourusername) • [LinkedIn](https://linkedin.com/in/your-profile)

---

## 📜 License

This project is licensed under the MIT License.
