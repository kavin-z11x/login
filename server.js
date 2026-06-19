const express = require('express');
const cors = require('cors');
const path = require('path');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3005;

// Secret key for JWT signing (In production, load this from process.env.JWT_SECRET)
const JWT_SECRET = process.env.JWT_SECRET || 'kalai_spoken_english_super_secure_jwt_secret_key_2026';

// Deployment ID of the Google Apps Script Web App
const GAS_URL = "https://script.google.com/macros/s/AKfycbzkEotPVqeT916NxBtlUNldAUVbYkmqIqoKwXTNo9jzv0CIXW4I-nwchoIz0PzAs7Ok/exec";

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static frontend assets from the 'public' directory
app.use(express.static(path.join(__dirname, 'public')));

// --- IN-MEMORY CACHE SYSTEM ---
const cacheStore = {};
const CACHE_TTL = 3 * 60 * 1000; // 3 minutes

function getCachedData(key) {
  const cached = cacheStore[key];
  if (cached && (Date.now() - cached.timestamp < CACHE_TTL)) {
    return cached.data;
  }
  return null;
}

function setCachedData(key, data) {
  cacheStore[key] = {
    data: data,
    timestamp: Date.now()
  };
}

function clearCache(studentId) {
  console.log(`[Cache] Clearing cache...`);
  if (studentId) {
    delete cacheStore[`getStudentProfile_${studentId}`];
    delete cacheStore[`getPoints_${studentId}`];
  } else {
    for (const key in cacheStore) {
      delete cacheStore[key];
    }
  }
  delete cacheStore[`getStudents`];
}

// --- PROXY API ENTRANCE (With JWT Verification) ---
app.get('/api', async (req, res) => {
  const { action, id } = req.query;
  
  if (!action) {
    return res.status(400).json({ error: 'Missing action parameter' });
  }

  // Action: verifyLogin (Public, generates JWT on success)
  if (action === 'verifyLogin') {
    try {
      const queryParams = new URLSearchParams(req.query).toString();
      const targetUrl = `${GAS_URL}?${queryParams}`;
      
      console.log(`[Login] Verifying credentials via Google Sheets: ${id}`);
      const response = await fetch(targetUrl);
      const data = await response.json();

      if (data.status === 'success') {
        // Generate secure JWT token containing studentId and studentName
        const token = jwt.sign(
          { studentId: id, studentName: data.name },
          JWT_SECRET,
          { expiresIn: '24h' } // Token expires in 24 hours
        );
        
        console.log(`[Login] JWT Issued successfully for ID: ${id}`);
        // Return status and token
        return res.json({
          status: 'success',
          name: data.name,
          token: token
        });
      } else {
        return res.json(data);
      }
    } catch (error) {
      console.error("Login Verification Error:", error);
      return res.status(502).json({ error: "Failed to verify credentials", details: error.message });
    }
  }

  // --- SECURED ROUTES ---
  // verifyLogin is public, getStudents/getStudentProfile/getPoints are secure
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Extract 'Bearer <token>'

  if (!token) {
    console.log(`[Auth Error] Missing authorization token for action: ${action}`);
    return res.status(401).json({ error: 'Unauthorized: Access token is missing' });
  }

  try {
    // Verify the JWT token
    const decodedUser = jwt.verify(token, JWT_SECRET);
    
    // Force the student ID to be the verified ID from the token
    // This stops spoofing (someone requesting STU-002 data while logged in as STU-001)
    const verifiedId = decodedUser.studentId;
    req.query.id = verifiedId;

    const cacheKey = `${action}_${verifiedId}`;

    // Try serving from in-memory cache
    const cachedData = getCachedData(cacheKey);
    if (cachedData) {
      console.log(`[Proxy GET] [CACHE HIT] Serving from memory: ${cacheKey}`);
      return res.json(cachedData);
    }

    // Cache Miss -> Forward to Google Sheets
    const queryParams = new URLSearchParams(req.query).toString();
    const targetUrl = `${GAS_URL}?${queryParams}`;
    
    console.log(`[Proxy GET] [CACHE MISS] Fetching from Google Sheets: ${targetUrl}`);
    const response = await fetch(targetUrl);
    const data = await response.json();

    // Cache successful responses
    if (!data.error && data.status !== 'error') {
      console.log(`[Proxy GET] Caching response for key: ${cacheKey}`);
      setCachedData(cacheKey, data);
    }

    res.json(data);
  } catch (err) {
    console.error(`[Auth Error] Invalid token for action: ${action}`, err.message);
    return res.status(403).json({ error: 'Forbidden: Invalid or expired access token' });
  }
});

// --- PROXY POST REQUESTS ---
// Clears cache on updates, enforces token validation
app.post('/api', async (req, res) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Unauthorized: Access token is missing' });
  }

  try {
    const decodedUser = jwt.verify(token, JWT_SECRET);
    
    // Force the student ID in updates to match the logged-in user
    if (req.body.formData && req.body.action === 'addPoints') {
      req.body.formData.studentId = decodedUser.studentId;
    }

    console.log(`[Proxy POST] Forwarding update to Google Sheets...`);
    const response = await fetch(GAS_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      body: JSON.stringify(req.body)
    });

    const data = await response.json();

    // Invalidate Cache
    const targetStudentId = decodedUser.studentId;
    console.log(`[Proxy POST] Invalidating cache for student: ${targetStudentId}`);
    clearCache(targetStudentId);

    res.json(data);
  } catch (error) {
    console.error("Proxy POST Error:", error);
    res.status(502).json({ error: "Failed to post update to Sheets", details: error.message });
  }
});

// Default route redirects to login page
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'student_login.html'));
});

// Start Express Server
app.listen(PORT, () => {
  console.log(`=======================================================`);
  console.log(`🚀 Secure JWT Caching Proxy Server running on port ${PORT}`);
  console.log(`📂 Serving static files from "./public"`);
  console.log(`🔒 Authentication: JWT Tokens enabled`);
  console.log(`=======================================================`);
});
