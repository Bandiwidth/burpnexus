import express from 'express';
const router = express.Router();
router.get('/users/:id', getUser);
export default router;

function getUser(req, res) {
  // Does a global policy verify ownership/tenant before this call?
  // This excerpt alone cannot establish whether access is authorized.
  return userService.findById(req.params.id);
}
