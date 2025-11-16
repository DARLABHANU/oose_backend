import express from "express";
import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import cors from "cors";
import dotenv from "dotenv";
import morgan from "morgan";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import { body, validationResult } from "express-validator";
import nodemailer from "nodemailer";

dotenv.config();
const app = express();

// Essentials and security middleware
app.use(express.json());
app.use(cors({
  origin: ["http://localhost:3000"], // Match your frontend origin
  credentials: true
}));
app.use(morgan("combined"));
app.use(helmet());

const MONGO_URI = process.env.MONGO_URI || "mongodb://localhost:27017/online_voting";
const JWT_SECRET = process.env.JWT_SECRET || "supersecretkey";

// Strong secret check
if (!process.env.JWT_SECRET || process.env.JWT_SECRET === "supersecretkey") {
  console.error("❌ CRITICAL: Set a strong JWT_SECRET in production!");
  process.exit(1);
}

// MongoDB connection
mongoose.connect(MONGO_URI)
  .then(() => console.log("✅ Connected to MongoDB"))
  .catch(err => console.error("❌ MongoDB connection error:", err));

// Schema definitions
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true, index: true },
  password: String,
  isAdmin: { type: Boolean, default: false },
  approved: { type: Boolean, default: false },
  eligibility: { type: String, default: "general" },
  createdAt: { type: Date, default: Date.now }
});

const candidateSchema = new mongoose.Schema({
  name: String,
  party: String,
  electionId: { type: mongoose.Schema.Types.ObjectId, index: true },
  photo: String,
  manifesto: String,
  pending: { type: Boolean, default: false, index: true },
  createdAt: { type: Date, default: Date.now }
});

const electionSchema = new mongoose.Schema({
  title: String,
  candidates: [{ type: mongoose.Schema.Types.ObjectId }],
  start: Date,
  end: Date,
  isActive: { type: Boolean, default: true, index: true },
  eligibility: { type: String, default: "general", index: true },
  createdAt: { type: Date, default: Date.now }
});

const voteSchema = new mongoose.Schema({
  candidate: { type: mongoose.Schema.Types.ObjectId, index: true },
  election: { type: mongoose.Schema.Types.ObjectId, index: true },
  userId: { type: mongoose.Schema.Types.ObjectId, index: true },
  timestamp: { type: Date, default: Date.now }
});
voteSchema.index({ election: 1, userId: 1 }, { unique: true });

const reportSchema = new mongoose.Schema({
  userId: mongoose.Schema.Types.ObjectId,
  subject: String,
  description: String,
  timestamp: { type: Date, default: Date.now }
});

const User = mongoose.model("User", userSchema);
const Candidate = mongoose.model("Candidate", candidateSchema);
const Election = mongoose.model("Election", electionSchema);
const Vote = mongoose.model("Vote", voteSchema);
const Report = mongoose.model("Report", reportSchema);

// Email configuration
const EMAIL_CONFIG = {
  host: process.env.EMAIL_HOST || 'smtp.gmail.com',
  port: parseInt(process.env.EMAIL_PORT || '587'),
  secure: process.env.EMAIL_SECURE === 'true',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD
  }
};
const transporter = nodemailer.createTransport(EMAIL_CONFIG);

const sendApprovalEmail = async (to, name) => {
  const frontendUrl = process.env.FRONTEND_URL || "http://localhost:5173";
  const mailOptions = {
    from: `"VoteSecure" <${EMAIL_CONFIG.auth.user}>`,
    to,
    subject: "🎉 Your VoteSecure Account Has Been Approved!",
    html: `
    <div style="font-family:sans-serif;max-width:600px;margin:auto;background:#f9f9fa;border-radius:10px;padding:24px;border:1px solid #eee">
      <div style="background:linear-gradient(90deg,#8c6aed 60%,#5f67e9 100%);color:white;padding:24px 16px;border-radius:8px 8px 0 0;">
        <h1>🗳️ Welcome to VoteSecure!</h1>
      </div>
      <p style="font-size:1.1em">Dear <b>${name}</b>,<br>Great news! Your registration has been approved by our administrator.</p>
      <div style="background:#fff;border:1px solid #eee;padding:16px;margin:18px 0;border-radius:8px">
        <b>✅ What You Can Do Now:</b>
        <ul style="margin:10px 0 0 0;padding:0 0 0 12px;">
          <li>Log in to your account</li>
          <li>View available elections</li>
          <li>Cast your vote</li>
          <li>Nominate yourself as candidate</li>
          <li>View election results</li>
        </ul>
        <a href="${frontendUrl}/login"
          style="background:#8c6aed;color:white;padding:10px 20px;text-decoration:none;font-weight:bold;border-radius:6px;display:inline-block;margin-top:16px">
          🔒 Login to Your Account
        </a>
      </div>
      <div style="margin-top:16px;font-size:0.9em">
        <b>📧 Your Account Details:</b><br>
        Email: ${to}<br>
        Status: <span style="color:green">✅ Approved</span>
      </div>
      <div style="font-size:0.93em;color:#444;margin-top:40px;">
        Happy Voting!<br>
        <b>The VoteSecure Team</b>
      </div>
      <hr style="border:0;border-top:1px solid #eee;margin:16px 0">
      <div style="color:#888;font-size:0.9em">This is an automated message. Please do not reply.</div>
    </div>
    `,
    text: `Dear ${name}, Your VoteSecure account is approved! You can now login: ${frontendUrl}/login`
  };
  try {
    const info = await transporter.sendMail(mailOptions);
    console.log(`✅ Approval email sent to ${to} [${info.messageId}]`);
    return { success: true, messageId: info.messageId };
  } catch (error) {
    console.error(`❌ Email send error:`, error);
    return { success: false, error: error.message };
  }
};

// Security middleware
const auth = async (req, res, next) => {
  const token = req.headers.authorization && req.headers.authorization.split(" ")[1];
  if (!token) return res.status(401).json({ message: "No token provided" });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(403).json({ message: "Invalid or expired token" });
  }
};

const adminAuth = async (req, res, next) => {
  if (!req.user.isAdmin) {
    return res.status(403).json({ message: "Admin access required" });
  }
  next();
};

// Rate limiter
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: "Too many login attempts, please try again later"
});

// Routes

app.post("/register",
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 8 }).trim(),
  body('name').trim().notEmpty().escape(),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    try {
      const { name, email, password, eligibility } = req.body;
      const hash = await bcrypt.hash(password, 12);
      const user = new User({ name, email, password: hash, eligibility: eligibility || "general" });
      await user.save();
      res.json({ success: true, message: "Registered successfully. Awaiting admin approval." });
    } catch (e) {
      if (e.code === 11000) {
        res.status(400).json({ success: false, message: "Email already exists" });
      } else {
        res.status(500).json({ success: false, message: "Registration failed" });
      }
    }
  }
);

app.post("/login", loginLimiter, async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ message: "Email and password are required" });
  }
  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: "Invalid credentials" });
    }
    if (!user.approved) {
      return res.status(400).json({ message: "Account not approved yet" });
    }
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(400).json({ message: "Invalid credentials" });
    }
    const token = jwt.sign({ userId: user._id, isAdmin: user.isAdmin, eligibility: user.eligibility }, JWT_SECRET, { expiresIn: "7d" });
    res.json({
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        isAdmin: user.isAdmin,
        isApproved: user.approved,
        eligibility: user.eligibility
      }
    });
  } catch (error) {
    res.status(500).json({ message: "Login failed" });
  }
});

// The rest of your CRUD routes remain the same as previous code.

app.get("/dashboard", auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    if (!user.approved) {
      return res.status(400).json({ message: "Not approved" });
    }
    const elections = await Election.find({ isActive: true, eligibility: user.eligibility }).sort({ start: -1 });
    res.json({ elections });
  } catch (error) {
    res.status(500).json({ message: "Failed to fetch dashboard" });
  }
});

app.get("/election/:id/candidates", auth, async (req, res) => {
  try {
    const candidates = await Candidate.find({ electionId: req.params.id, pending: false });
    const userVote = await Vote.findOne({ election: req.params.id, userId: req.user.userId });
    res.json({ candidates, hasVoted: !!userVote });
  } catch (error) {
    res.status(500).json({ message: "Failed to fetch candidates" });
  }
});

app.post("/vote", auth, async (req, res) => {
  try {
    const { candidateId, electionId } = req.body;
    if (!candidateId || !electionId) {
      return res.status(400).json({ message: "Missing candidateId or electionId" });
    }
    const candidate = await Candidate.findById(candidateId);
    if (!candidate || candidate.electionId.toString() !== electionId) {
      return res.status(400).json({ message: "Invalid candidate for this election" });
    }
    const existingVote = await Vote.findOne({ election: electionId, userId: req.user.userId });
    if (existingVote) {
      return res.status(400).json({ success: false, message: "You have already voted in this election" });
    }
    const user = await User.findById(req.user.userId);
    const election = await Election.findById(electionId);
    if (!election) {
      return res.status(404).json({ message: "Election not found" });
    }
    if (election.eligibility !== user.eligibility) {
      return res.status(403).json({ message: "You are not eligible for this election" });
    }
    const now = new Date();
    if (!election.isActive) {
      return res.status(400).json({ message: "Election is not active" });
    }
    if (now < election.start) {
      return res.status(400).json({ message: "Election has not started yet" });
    }
    if (now > election.end) {
      return res.status(400).json({ message: "Election has ended" });
    }
    const vote = new Vote({ candidate: candidateId, election: electionId, userId: req.user.userId });
    await vote.save();
    res.json({ success: true, message: "Vote cast successfully" });
  } catch (error) {
    if (error.code === 11000) {
      res.status(400).json({ success: false, message: "Duplicate vote detected" });
    } else {
      res.status(500).json({ success: false, message: "Failed to cast vote" });
    }
  }
});

app.get("/results/:electionId", auth, async (req, res) => {
  try {
    const election = await Election.findById(req.params.electionId);
    if (!election) {
      return res.status(404).json({ message: "Election not found" });
    }
    const now = new Date();
    if (!req.user.isAdmin && now < election.end) {
      return res.status(403).json({ message: "Results not available until election ends" });
    }
    const votes = await Vote.aggregate([
      { $match: { election: new mongoose.Types.ObjectId(req.params.electionId) } },
      { $group: { _id: "$candidate", count: { $sum: 1 } } },
    ]);
    let total = votes.reduce((sum, v) => sum + v.count, 0);
    let candidateVotes = [];
    for (let v of votes) {
      let candidate = await Candidate.findById(v._id);
      if (candidate) {
        candidateVotes.push({
          _id: candidate._id,
          name: candidate.name,
          party: candidate.party,
          manifesto: candidate.manifesto,
          photo: candidate.photo,
          votes: v.count,
          percentage: parseFloat(((v.count / total) * 100).toFixed(2))
        });
      }
    }
    candidateVotes.sort((a, b) => b.votes - a.votes);
    res.json({ results: candidateVotes });
  } catch (error) {
    res.status(500).json({ message: "Failed to fetch results" });
  }
});

app.get("/stats/:electionId", auth, async (req, res) => {
  try {
    const election = await Election.findById(req.params.electionId);
    if (!election) {
      return res.status(404).json({ message: "Election not found" });
    }
    const eligibleVoters = await User.countDocuments({ approved: true, eligibility: election.eligibility });
    const totalVotes = await Vote.countDocuments({ election: req.params.electionId });
    const turnout = eligibleVoters > 0 ? parseFloat(((totalVotes / eligibleVoters) * 100).toFixed(2)) : 0;
    res.json({ totalVotes, eligibleVoters, turnout });
  } catch (error) {
    res.status(500).json({ message: "Failed to fetch stats" });
  }
});

app.post("/nominate", auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    if (!user.approved) {
      return res.status(403).json({ message: "Your account is not approved" });
    }
    const { electionId, party, manifesto, photo } = req.body;
    const exists = await Candidate.findOne({ name: user.name, electionId });
    if (exists) {
      return res.status(400).json({ message: "You have already nominated for this election" });
    }
    const candidate = new Candidate({ name: user.name, party: party || "", electionId, photo: photo || "", manifesto: manifesto || "", pending: true });
    await candidate.save();
    res.json({ success: true, message: "Nomination submitted. Awaiting admin approval." });
  } catch (error) {
    res.status(500).json({ success: false, message: "Failed to submit nomination" });
  }
});

// Reporting
app.post("/report", auth, async (req, res) => {
  try {
    const { subject, description } = req.body;
    const report = new Report({ userId: req.user.userId, subject, description });
    await report.save();
    res.json({ success: true, message: "Your report has been recorded. We'll look into it." });
  } catch (error) {
    res.status(500).json({ success: false, message: "Failed to submit report" });
  }
});

// ------------------------
// ADMIN APPROVE ROUTE: includes email notification!
app.post("/admin/approve/:id", auth, adminAuth, async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(req.params.id, { approved: true }, { new: true });
    let emailStatus = { success: false, error: "Email disabled/config missing" };
    if (user && process.env.EMAIL_USER && process.env.EMAIL_PASSWORD) {
      emailStatus = await sendApprovalEmail(user.email, user.name);
    } else {
      console.warn("⚠️ Email credentials not configured or user not found");
    }
    res.json({
      success: true,
      message: emailStatus.success
        ? "User approved and notification email sent"
        : "User approved (email notification failed)",
      emailSent: emailStatus.success,
      emailError: emailStatus.success ? undefined : emailStatus.error
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Failed to approve user",
      emailSent: false,
      emailError: error.message
    });
  }
});
// ------------------------

// Other admin endpoints (unchanged)

app.post("/admin/reject/:id", auth, adminAuth, async (req, res) => {
  try {
    await User.findByIdAndDelete(req.params.id);
    res.json({ success: true, message: "User rejected and removed" });
  } catch (error) {
    res.status(500).json({ success: false, message: "Failed to reject user" });
  }
});

app.get("/admin/pending-users", auth, adminAuth, async (req, res) => {
  try {
    const users = await User.find({ approved: false }).select('-password').sort({ createdAt: -1 });
    res.json(users);
  } catch (error) {
    res.status(500).json({ message: "Failed to fetch pending users" });
  }
});

app.get("/admin/pending-candidates", auth, adminAuth, async (req, res) => {
  try {
    const candidates = await Candidate.find({ pending: true }).sort({ createdAt: -1 });
    res.json(candidates);
  } catch (error) {
    res.status(500).json({ message: "Failed to fetch pending candidates" });
  }
});

app.post("/admin/approve-candidate/:id", auth, adminAuth, async (req, res) => {
  try {
    await Candidate.findByIdAndUpdate(req.params.id, { pending: false });
    const candidate = await Candidate.findById(req.params.id);
    await Election.findByIdAndUpdate(candidate.electionId, { $addToSet: { candidates: candidate._id } });
    res.json({ success: true, message: "Candidate approved" });
  } catch (error) {
    res.status(500).json({ success: false, message: "Failed to approve candidate" });
  }
});

app.post("/admin/reject-candidate/:id", auth, adminAuth, async (req, res) => {
  try {
    await Candidate.findByIdAndDelete(req.params.id);
    res.json({ success: true, message: "Candidate nomination rejected" });
  } catch (error) {
    res.status(500).json({ success: false, message: "Failed to reject candidate" });
  }
});

app.post("/admin/elections", auth, adminAuth, async (req, res) => {
  try {
    const { title, start, end, eligibility } = req.body;
    if (!title || !start || !end) {
      return res.status(400).json({ success: false, message: "Title, start date, and end date are required" });
    }
    const election = new Election({ title, start, end, eligibility: eligibility || "general" });
    await election.save();
    res.json({ success: true, election });
  } catch (error) {
    res.status(500).json({ success: false, message: "Failed to create election" });
  }
});

app.get("/elections", auth, async (req, res) => {
  try {
    const elections = await Election.find().populate("candidates").sort({ start: -1 });
    res.json(elections);
  } catch (error) {
    res.status(500).json({ message: "Failed to fetch elections" });
  }
});

app.put("/admin/elections/:id", auth, adminAuth, async (req, res) => {
  try {
    await Election.findByIdAndUpdate(req.params.id, req.body);
    res.json({ success: true, message: "Election updated" });
  } catch (error) {
    res.status(500).json({ success: false, message: "Failed to update election" });
  }
});

app.delete("/admin/elections/:id", auth, adminAuth, async (req, res) => {
  try {
    await Candidate.deleteMany({ electionId: req.params.id });
    await Vote.deleteMany({ election: req.params.id });
    await Election.findByIdAndDelete(req.params.id);
    res.json({ success: true, message: "Election deleted" });
  } catch (error) {
    res.status(500).json({ success: false, message: "Failed to delete election" });
  }
});

app.post("/admin/candidates", auth, adminAuth, async (req, res) => {
  try {
    const { name, party, electionId, photo, manifesto } = req.body;
    if (!name || !electionId) {
      return res.status(400).json({ success: false, message: "Name and election are required" });
    }
    const candidate = new Candidate({ name, party, electionId, photo, manifesto, pending: false });
    await candidate.save();
    await Election.findByIdAndUpdate(electionId, { $addToSet: { candidates: candidate._id } });
    res.json({ success: true, candidate });
  } catch (error) {
    res.status(500).json({ success: false, message: "Failed to create candidate" });
  }
});

app.get("/admin/candidates", auth, adminAuth, async (req, res) => {
  try {
    const candidates = await Candidate.find({ pending: false }).sort({ createdAt: -1 });
    res.json(candidates);
  } catch (error) {
    res.status(500).json({ message: "Failed to fetch candidates" });
  }
});

app.put("/admin/candidates/:id", auth, adminAuth, async (req, res) => {
  try {
    await Candidate.findByIdAndUpdate(req.params.id, req.body);
    res.json({ success: true, message: "Candidate updated" });
  } catch (error) {
    res.status(500).json({ success: false, message: "Failed to update candidate" });
  }
});

app.delete("/admin/candidates/:id", auth, adminAuth, async (req, res) => {
  try {
    const candidate = await Candidate.findById(req.params.id);
    if (candidate) {
      await Election.findByIdAndUpdate(candidate.electionId, { $pull: { candidates: candidate._id } });
    }
    await Candidate.findByIdAndDelete(req.params.id);
    res.json({ success: true, message: "Candidate deleted" });
  } catch (error) {
    res.status(500).json({ success: false, message: "Failed to delete candidate" });
  }
});

app.get("/health", (req, res) => {
  res.json({ status: "OK", timestamp: new Date().toISOString(), uptime: process.uptime() });
});

app.use((err, req, res, next) => {
  console.error("Error:", err);
  res.status(500).json({ message: "Internal server error", error: process.env.NODE_ENV === "development" ? err.message : undefined });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`
    ╔════════════════════════════════════════╗
    ║  🗳️  Online Voting System Backend     ║
    ║  ✅ Server running on port ${PORT}      ║
    ║  📦 MongoDB connected                  ║
    ║  🔐 JWT authentication enabled         ║
    ╚════════════════════════════════════════╝
  `);
});

process.on('SIGINT', async () => {
  console.log('\n🛑 Shutting down gracefully...');
  await mongoose.connection.close();
  process.exit(0);
});
