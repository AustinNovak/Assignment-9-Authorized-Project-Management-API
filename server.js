const jwt = require('jsonwebtoken');
const express = require('express');
const bcrypt = require('bcryptjs');
const { db, User, Project, Task } = require('./database/setup');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '24h';

app.use(express.json());

// Helper: sign JWT for a user
function signUserToken(user) {
    const payload = {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role
    };
    return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
}

// JWT auth middleware
function requireAuth(req, res, next) {
    const auth = req.headers.authorization;
    if (!auth || !auth.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Authorization required (Bearer token).' });
    }
    const token = auth.split(' ')[1];
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded; // contains id, name, email, role
        return next();
    } catch (err) {
        return res.status(401).json({ error: 'Invalid or expired token.' });
    }
}

// Role middleware
function requireManager(req, res, next) {
    if (!req.user) return res.status(401).json({ error: 'Authentication required.' });
    if (req.user.role === 'manager' || req.user.role === 'admin') return next();
    return res.status(403).json({ error: 'Manager or admin access required.' });
}

function requireAdmin(req, res, next) {
    if (!req.user) return res.status(401).json({ error: 'Authentication required.' });
    if (req.user.role === 'admin') return next();
    return res.status(403).json({ error: 'Admin access required.' });
}

// Test DB
async function testConnection() {
    try {
        await db.authenticate();
        console.log('Connection to database established successfully.');
    } catch (error) {
        console.error('Unable to connect to the database:', error);
    }
}
testConnection();


//AUTH: Register / Login


// POST /api/register
app.post('/api/register', async (req, res) => {
    try {
        const { name, email, password, role } = req.body;
        if (!name || !email || !password) {
            return res.status(400).json({ error: 'name, email and password are required' });
        }
        // only allow valid roles if provided
        const allowedRoles = ['employee', 'manager', 'admin'];
        const chosenRole = role && allowedRoles.includes(role) ? role : 'employee';

        const existing = await User.findOne({ where: { email } });
        if (existing) return res.status(400).json({ error: 'User with this email already exists' });

        const hashed = await bcrypt.hash(password, 10);
        const newUser = await User.create({ name, email, password: hashed, role: chosenRole });

        const token = signUserToken(newUser);

        res.status(201).json({
            message: 'User registered successfully',
            user: { id: newUser.id, name: newUser.name, email: newUser.email, role: newUser.role },
            token
        });
    } catch (err) {
        console.error('Error registering user:', err);
        res.status(500).json({ error: 'Failed to register user' });
    }
});

// POST /api/login
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ error: 'email and password required' });

        const user = await User.findOne({ where: { email } });
        if (!user) return res.status(401).json({ error: 'Invalid email or password' });

        const ok = await bcrypt.compare(password, user.password);
        if (!ok) return res.status(401).json({ error: 'Invalid email or password' });

        const token = signUserToken(user);

        res.json({
            message: 'Login successful',
            user: { id: user.id, name: user.name, email: user.email, role: user.role },
            token
        });
    } catch (err) {
        console.error('Error logging in:', err);
        res.status(500).json({ error: 'Failed to login' });
    }
});

// POST /api/logout - stateless with JWT, just respond success
app.post('/api/logout', (req, res) => {
    // With JWT there's no server session to destroy. Client should drop token.
    res.json({ message: 'Logout successful (client should discard token)' });
});


//USER ROUTES


// GET current profile
app.get('/api/users/profile', requireAuth, async (req, res) => {
    try {
        const user = await User.findByPk(req.user.id, { attributes: ['id', 'name', 'email', 'role'] });
        if (!user) return res.status(404).json({ error: 'User not found' });
        res.json(user);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch user profile' });
    }
});

// GET all users (admin only)
app.get('/api/users', requireAuth, requireAdmin, async (req, res) => {
    try {
        const users = await User.findAll({ attributes: ['id', 'name', 'email', 'role'] });
        res.json(users);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch users' });
    }
});

//PROJECT ROUTES


// GET /api/projects
// Managers & admins: get all projects
// Employees: get projects where they have assigned tasks (projects they are part of)
app.get('/api/projects', requireAuth, async (req, res) => {
    try {
        if (req.user.role === 'employee') {
            // projects where this user has tasks assigned
            const projects = await Project.findAll({
                include: [{
                    model: Task,
                    where: { assignedUserId: req.user.id },
                    required: true // only projects with tasks assigned to this user
                },
                {
                    model: User,
                    as: 'manager',
                    attributes: ['id', 'name', 'email']
                }]
            });
            return res.json(projects);
        } else {
            // manager or admin: return all projects
            const projects = await Project.findAll({
                include: [{ model: User, as: 'manager', attributes: ['id', 'name', 'email'] }]
            });
            return res.json(projects);
        }
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch projects' });
    }
});

// GET /api/projects/:id
app.get('/api/projects/:id', requireAuth, async (req, res) => {
    try {
        const project = await Project.findByPk(req.params.id, {
            include: [
                { model: User, as: 'manager', attributes: ['id', 'name', 'email'] },
                { model: Task, include: [{ model: User, as: 'assignedUser', attributes: ['id', 'name', 'email'] }] }
            ]
        });
        if (!project) return res.status(404).json({ error: 'Project not found' });

        // if employee, verify they have a task in this project
        if (req.user.role === 'employee') {
            const tasks = await Task.findAll({ where: { projectId: project.id, assignedUserId: req.user.id } });
            if (!tasks || tasks.length === 0) {
                return res.status(403).json({ error: 'Access denied to this project' });
            }
        }

        res.json(project);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch project' });
    }
});

// POST /api/projects - Manager+ only
app.post('/api/projects', requireAuth, requireManager, async (req, res) => {
    try {
        const { name, description, status = 'active' } = req.body;
        const newProject = await Project.create({ name, description, status, managerId: req.user.id });
        res.status(201).json(newProject);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to create project' });
    }
});

// PUT /api/projects/:id - Manager+ only
app.put('/api/projects/:id', requireAuth, requireManager, async (req, res) => {
    try {
        const { name, description, status } = req.body;
        const [count] = await Project.update({ name, description, status }, { where: { id: req.params.id } });
        if (count === 0) return res.status(404).json({ error: 'Project not found' });
        const updated = await Project.findByPk(req.params.id);
        res.json(updated);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to update project' });
    }
});

// DELETE /api/projects/:id - Admin only
app.delete('/api/projects/:id', requireAuth, requireAdmin, async (req, res) => {
    try {
        const count = await Project.destroy({ where: { id: req.params.id } });
        if (count === 0) return res.status(404).json({ error: 'Project not found' });
        res.json({ message: 'Project deleted successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to delete project' });
    }
});


//TASK ROUTES


// GET tasks for a project
app.get('/api/projects/:id/tasks', requireAuth, async (req, res) => {
    try {
        // if employee, only tasks assigned to them in that project
        if (req.user.role === 'employee') {
            const tasks = await Task.findAll({
                where: { projectId: req.params.id, assignedUserId: req.user.id },
                include: [{ model: User, as: 'assignedUser', attributes: ['id', 'name', 'email'] }]
            });
            return res.json(tasks);
        } else {
            const tasks = await Task.findAll({
                where: { projectId: req.params.id },
                include: [{ model: User, as: 'assignedUser', attributes: ['id', 'name', 'email'] }]
            });
            return res.json(tasks);
        }
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch tasks' });
    }
});

// POST /api/projects/:id/tasks - Manager+ only
app.post('/api/projects/:id/tasks', requireAuth, requireManager, async (req, res) => {
    try {
        const { title, description, assignedUserId, priority = 'medium' } = req.body;
        const newTask = await Task.create({
            title,
            description,
            projectId: req.params.id,
            assignedUserId,
            priority,
            status: 'pending'
        });
        res.status(201).json(newTask);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to create task' });
    }
});

// PUT /api/tasks/:id - allow:
// - employee: only update status on tasks assigned to them
// - manager/admin: update any task
app.put('/api/tasks/:id', requireAuth, async (req, res) => {
    try {
        const task = await Task.findByPk(req.params.id);
        if (!task) return res.status(404).json({ error: 'Task not found' });

        if (req.user.role === 'employee') {
            // employees can only update status and only on tasks assigned to them
            if (task.assignedUserId !== req.user.id) {
                return res.status(403).json({ error: 'Cannot modify tasks not assigned to you' });
            }
            const { status } = req.body;
            if (status === undefined) {
                return res.status(400).json({ error: 'Employees may only update task status' });
            }
            await task.update({ status });
            return res.json(task);
        } else {
            // manager/admin: full update allowed
            const { title, description, status, priority, assignedUserId } = req.body;
            await task.update({ title, description, status, priority, assignedUserId });
            return res.json(task);
        }
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to update task' });
    }
});

// DELETE /api/tasks/:id - Manager+ only
app.delete('/api/tasks/:id', requireAuth, requireManager, async (req, res) => {
    try {
        const count = await Task.destroy({ where: { id: req.params.id } });
        if (count === 0) return res.status(404).json({ error: 'Task not found' });
        res.json({ message: 'Task deleted successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to delete task' });
    }
});

//Start server

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
