// Illustrative source only; this example is not a running web server.
import express from 'express';
import users from './users.js';
const app = express();
app.use('/api', authenticate, users);
app.get('/search', search);
app.post('/api/orders', createOrder);
app.get('/admin/audit', requireAdmin, audit);

function authenticate(req, res, next) {
  // Implementation omitted: review the real application's session policy.
  next();
}
function search(req, res) { res.json({ query: req.query.q }); }
function createOrder(req, res) { return orderService.create(req.body); }
