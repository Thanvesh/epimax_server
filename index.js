const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');

// Initialize Express app
const app = express();
app.use(cors());
app.use(bodyParser.json());

// Replace the connection details with SQLite configuration
const db = new sqlite3.Database('task_api.db');



const createTablesScript = `
CREATE TABLE IF NOT EXISTS Users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user' -- Add a role column with a default value
);

CREATE TABLE IF NOT EXISTS Tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    linkedTo TEXT NOT NULL,
    status TEXT NOT NULL,
    assigned_user_id INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    duedate DATETIME,
    FOREIGN KEY (assigned_user_id) REFERENCES Users(id)
);
`;

// Execute table creation script
db.serialize(() => {
    db.run(createTablesScript);
});


const JWT_SECRET = process.env.ACCESS_TOKEN_SECRET || 'your-secret';

// Hash password function using bcrypt
const hashPassword = async (password) => {
    const saltRounds = 10;
    return await bcrypt.hash(password, saltRounds);
};

// Compare password function using bcrypt
const comparePassword = async (password, hash) => {
    return await bcrypt.compare(password, hash);
};


function checkRole(role) {
    return (req, res, next) => {
      // Implement role checking logic here
      // For example, check if the user role matches the required role
      const userRole = req.user.role; // Assuming user role is included in the JWT payload
      if (userRole !== role) {
        return res.status(403).json({ error: 'Not authorized user' });
      }
      next();
    };
  }
  
  // Authentication middleware
  /**
   * Authentication Middleware:
   * Verifies JWT token and sets user information in the request object.
   */
  function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.sendStatus(401);
    jwt.verify(token,JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}
  
  // Routes for user authentication
  /**
   * Route: User Login
   * Endpoint: POST /login
   * Description: Authenticate user and generate JWT token.
   * Request Body: { email, password }
   * Response: { accessToken }
   */
  app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        db.get(`SELECT * FROM Users WHERE email = ?`, [email], async (err, user) => {
            if (err) {
                return res.status(500).json({ error: err.message });
            }
            if (!user || !(await comparePassword(password, user.password_hash))) {
                return res.status(401).json({ error: 'Invalid email or password' });
            }
            const accessToken = jwt.sign({ email: user.email,role:user.role }, JWT_SECRET);
            res.json({ accessToken });
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});
  
  /**
   * Route: User Signup
   * Endpoint: POST /signup
   * Description: Create a new user account.
   * Request Body: { email, password }
   * Response: { message }
   */
  app.post('/signup', async (req, res) => {
    try {
        const {name, email, password, role } = req.body;
        const hashedPassword = await hashPassword(password);
        db.get(`SELECT * FROM Users WHERE email = ?`, [email], async (err, existingUser) => {
            if (err) {
                return res.status(500).json({ error: err.message });
            }
            if (existingUser) {
                return res.status(400).json({ error: 'User already exists' });
            }
            db.run(`INSERT INTO Users (name,email, password_hash, role) VALUES (?,?, ?, ?)`, [name,email, hashedPassword, role || 'user'], function(err) {
                if (err) {
                    return res.status(500).json({ error: err.message });
                }
                res.status(201).json({ message: 'User created successfully' });
            });
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

  
  /**
   * Route: Forgot Password
   * Endpoint: POST /forgot
   * Description: Send password reset email.
   * Request Body: { email }
   * Response: { message }
   */
  app.post('/forgot', async (req, res) => {
    try {
        const { email } = req.body;
        db.get(`SELECT * FROM Users WHERE email = ?`, [email], (err, user) => {
            if (err) {
                return res.status(500).json({ error: err.message });
            }
            if (!user) {
                return res.status(404).json({ error: 'User not found' });
            }
            // Implement logic to send password reset email
            res.json({ message: 'Password reset email sent' });
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});
  
  /**
   * Route: Reset Password
   * Endpoint: POST /reset
   * Description: Reset user password.
   * Request Body: { email, newPassword }
   * Response: { message }
   */
  app.post('/reset', async (req, res) => {
    try {
        const { email, newPassword } = req.body;
        db.run(`UPDATE Users SET password_hash = ? WHERE email = ?`, [newPassword, email], function(err) {
            if (err) {
                return res.status(500).json({ error: err.message });
            }
            res.json({ message: 'Password reset successfully' });
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});


/**
 * Route: Change User Role
 * Endpoint: PUT /users/:email/role
 * Description: Update a user's role by email.
 * Request Body: { role }
 * Response: { message }
 */
app.put('/users/:email/role', authenticateToken, checkRole('admin'), async (req, res) => {
    try {
        const { email } = req.params;
        const { role } = req.body;
        
        db.get(`SELECT * FROM Users WHERE email = ?`, [email], (err, user) => {
            if (err) {
                return res.status(500).json({ error: err.message });
            }
            if (!user) {
                return res.status(404).json({ error: 'User not found' });
            }

            db.run(`UPDATE Users SET role = ? WHERE email = ?`, [role, email], function(err) {
                if (err) {
                    return res.status(500).json({ error: err.message });
                }
                res.json({ message: 'User role updated successfully' });
            });
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

  
  // Routes for tasks
  /**
   * Route: Create Task
   * Endpoint: POST /tasks
   * Description: Create a new task.
   * Request Body: { title, description, status, assigned_user_id }
   * Response: { message }
   */
  app.post('/tasks', authenticateToken,checkRole('admin'), async (req, res) => {
    try {
        const { title, description, status, assigned_user_id } = req.body;
        db.run(`INSERT INTO Tasks (title, description, status, assigned_user_id,duedate) VALUES (?, ?, ?, ?)`, [title, description, status, assigned_user_id,duedate], function(err) {
            if (err) {
                return res.status(400).json({ error: err.message });
            }
            res.status(201).json({ message: 'Task created successfully' });
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});
  
  /**
   * Route: Get All Tasks
   * Endpoint: GET /tasks
   * Description: Retrieve all tasks.
   * Response: Array of tasks
   */
  app.get('/tasks', authenticateToken, async (req, res) => {
    try {
        db.all(`SELECT * FROM Tasks`, [], (err, tasks) => {
            if (err) {
                return res.status(500).json({ error: err.message });
            }
            res.json(tasks);
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

  /**
 * Route: Get Task by ID
 * Endpoint: GET /tasks/:id
 * Description: Retrieve a specific task by its ID.
 * Response: Task object
 */

  app.get('/tasks/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        db.get(`SELECT * FROM Tasks WHERE id = ?`, [id], (err, task) => {
            if (err) {
                return res.status(500).json({ error: err.message });
            }
            if (!task) {
                return res.status(404).json({ error: 'Task not found' });
            }
            res.json(task);
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

  
  /**
   * Route: Update Task
   * Endpoint: PUT /tasks/:id
   * Description: Update an existing task by ID.
   * Request Body: { title, description, status, assigned_user_id }
   * Response: { message }
   */
  app.put('/tasks/:id', authenticateToken,checkRole('admin'), async (req, res) => {
    try {
        const { id } = req.params;
        const { title, description, status, assigned_user_id } = req.body;
        db.run(`UPDATE Tasks SET title = ?, description = ?, status = ?, assigned_user_id = ?, WHERE id = ?,duedate=?`, [title, description, status, assigned_user_id, id], function(err) {
            if (err) {
                return res.status(400).json({ error: err.message });
            }
            res.json({ message: 'Task updated successfully' });
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});
  
  /**
   * Route: Delete Task
   * Endpoint: DELETE /tasks/:id
   * Description: Delete a task by ID.
   * Response: No content (204)
   */
  app.delete('/tasks/:id', authenticateToken,checkRole('admin'), async (req, res) => {
    try {
        const { id } = req.params;
        db.run(`DELETE FROM Tasks WHERE id = ?`, [id], function(err) {
            if (err) {
                return res.status(500).json({ error: err.message });
            }
            res.sendStatus(204);
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});
  
  // Error handling middleware
  app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('Something went wrong!');
  });



const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});

// Close database connection when the app exits
process.on('SIGINT', () => {
    db.close((err) => {
        if (err) {
            return console.error(err.message);
        }
        console.log('Database connection closed.');
        process.exit(0);
    });
});