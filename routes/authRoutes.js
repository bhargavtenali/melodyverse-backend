const express = require("express");
const router = express.Router();
const { signup, login } = require("../controllers/authController");
const { protect } = require("../middleware/authMiddleware");

router.post("/signup", signup);
router.post("/login", login);

// Protected route example
router.get("/profile", protect, (req, res) => {
  // we can add actaul api function here
  res.json(req.user);
});

module.exports = router;
