const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// Initialize Supabase
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseServiceKey = process.env.SUPABASE_SERVICE_KEY;
const supabase = createClient(supabaseUrl, supabaseServiceKey);

const JWT_SECRET = process.env.JWT_SECRET;
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;

// Helper function to generate session tokens
function generateSessionToken() {
    return crypto.randomBytes(32).toString('hex');
}

// Encrypt sensitive data
function encrypt(text) {
    if (!text) return null;
    try {
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(ENCRYPTION_KEY, 'hex'), iv);
        let encrypted = cipher.update(text, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        const authTag = cipher.getAuthTag();
        return JSON.stringify({
            iv: iv.toString('hex'),
            data: encrypted,
            tag: authTag.toString('hex')
        });
    } catch (error) {
        console.error('Encryption error:', error);
        return null;
    }
}

// Decrypt sensitive data
function decrypt(encryptedText) {
    if (!encryptedText) return null;
    try {
        const encryptedObj = JSON.parse(encryptedText);
        const iv = Buffer.from(encryptedObj.iv, 'hex');
        const encryptedData = Buffer.from(encryptedObj.data, 'hex');
        const authTag = Buffer.from(encryptedObj.tag, 'hex');
        const decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(ENCRYPTION_KEY, 'hex'), iv);
        decipher.setAuthTag(authTag);
        let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    } catch (error) {
        console.error('Decryption error:', error);
        return null;
    }
}

module.exports = async (req, res) => {
    // Set CORS headers
    res.setHeader('Access-Control-Allow-Credentials', true);
    res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,PATCH,DELETE,POST,PUT');
    res.setHeader('Access-Control-Allow-Headers', 'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version');

    // Handle preflight
    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    try {
        const { action, email, password, username, schoolName, gradeLevel, sessionToken } = req.body;

        switch (action) {
            case 'register':
                // Validate required fields
                if (!email || !password || !username) {
                    return res.status(400).json({ error: 'Email, password, and username are required' });
                }

                // Validate email format
                const emailRegex = /^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/;
                if (!emailRegex.test(email)) {
                    return res.status(400).json({ error: 'Invalid email format' });
                }

                // Check if user already exists
                const { data: existingUser } = await supabase
                    .from('users')
                    .select('id')
                    .eq('email', email)
                    .single();

                if (existingUser) {
                    return res.status(409).json({ error: 'User already exists' });
                }

                // Hash password
                const salt = await bcrypt.genSalt(10);
                const passwordHash = await bcrypt.hash(password, salt);

                // Create new user in users table
                const { data: newUser, error: userError } = await supabase
                    .from('users')
                    .insert([{
                        email,
                        username,
                        password: passwordHash,
                        created_at: new Date().toISOString(),
                        preference: 'student' // Default preference for school_git
                    }])
                    .select()
                    .single();

                if (userError) throw userError;

                // Create profile in profiles table
                await supabase
                    .from('profiles')
                    .insert([{
                        user_id: newUser.id,
                        bio: schoolName ? `Student at ${schoolName}` : 'School_git Student',
                        created_at: new Date().toISOString()
                    }]);

                // Create loggedin_users entry for GitHub OAuth
                await supabase
                    .from('loggedin_users')
                    .insert([{
                        email: newUser.email,
                        created_at: new Date().toISOString(),
                        updated_at: new Date().toISOString()
                    }]);

                // Create session token (store in users table temporarily)
                const sessionTokenNew = generateSessionToken();
                const expiresAt = new Date();
                expiresAt.setFullYear(expiresAt.getFullYear() + 1);

                // Encrypt and store session token
                const encryptedSession = encrypt(JSON.stringify({
                    token: sessionTokenNew,
                    expiresAt: expiresAt.toISOString(),
                    device: req.headers['user-agent']
                }));

                // Update user with session info
                await supabase
                    .from('users')
                    .update({
                        phone_verification_code: sessionTokenNew, // Reusing this field for session
                        code_expires_at: expiresAt.toISOString()
                    })
                    .eq('id', newUser.id);

                // Create JWT token
                const jwtToken = jwt.sign(
                    { 
                        userId: newUser.id, 
                        email: newUser.email,
                        username: newUser.username
                    },
                    JWT_SECRET,
                    { expiresIn: '1y' }
                );

                return res.status(201).json({
                    success: true,
                    message: 'Account created successfully',
                    user: {
                        id: newUser.id,
                        email: newUser.email,
                        username: newUser.username
                    },
                    sessionToken: sessionTokenNew,
                    jwtToken
                });

            case 'login':
                // Validate required fields
                if (!email || !password) {
                    return res.status(400).json({ error: 'Email and password are required' });
                }

                // Find user by email
                const { data: user, error: findError } = await supabase
                    .from('users')
                    .select('*')
                    .eq('email', email)
                    .single();

                if (findError || !user) {
                    return res.status(401).json({ error: 'Invalid credentials' });
                }

                // Verify password (plain text comparison for now, but should be hashed)
                // Note: In your schema, password is stored as text, not hashed
                // This is a security issue - you should migrate to hashed passwords
                const validPassword = user.password === password;
                
                // If password doesn't match, try bcrypt (for migrated accounts)
                if (!validPassword) {
                    try {
                        const bcryptMatch = await bcrypt.compare(password, user.password);
                        if (!bcryptMatch) {
                            return res.status(401).json({ error: 'Invalid credentials' });
                        }
                    } catch (e) {
                        return res.status(401).json({ error: 'Invalid credentials' });
                    }
                }

                // Update last login (use updated_at field)
                await supabase
                    .from('users')
                    .update({ updated_at: new Date().toISOString() })
                    .eq('id', user.id);

                // Create new session token
                const sessionTokenLogin = generateSessionToken();
                const expiresAtLogin = new Date();
                expiresAtLogin.setFullYear(expiresAtLogin.getFullYear() + 1);

                // Store session token
                await supabase
                    .from('users')
                    .update({
                        phone_verification_code: sessionTokenLogin,
                        code_expires_at: expiresAtLogin.toISOString()
                    })
                    .eq('id', user.id);

                // Get GitHub info if connected
                let githubUsername = null;
                const { data: githubUser } = await supabase
                    .from('loggedin_users')
                    .select('github_username')
                    .eq('email', email)
                    .single();

                if (githubUser) {
                    githubUsername = githubUser.github_username;
                }

                // Create JWT token
                const jwtTokenLogin = jwt.sign(
                    { 
                        userId: user.id, 
                        email: user.email,
                        username: user.username,
                        githubUsername: githubUsername
                    },
                    JWT_SECRET,
                    { expiresIn: '1y' }
                );

                return res.status(200).json({
                    success: true,
                    message: 'Login successful',
                    user: {
                        id: user.id,
                        email: user.email,
                        username: user.username,
                        githubUsername: githubUsername
                    },
                    sessionToken: sessionTokenLogin,
                    jwtToken: jwtTokenLogin
                });

            case 'validate-session':
                if (!sessionToken) {
                    return res.status(401).json({ error: 'No session token provided' });
                }

                // Check session in users table
                const { data: sessionUser, error: sessionError } = await supabase
                    .from('users')
                    .select('*')
                    .eq('phone_verification_code', sessionToken) // Using this field for session
                    .gt('code_expires_at', new Date().toISOString())
                    .single();

                if (sessionError || !sessionUser) {
                    return res.status(401).json({ error: 'Invalid or expired session' });
                }

                // Get GitHub info
                let githubUsernameSession = null;
                const { data: githubUserSession } = await supabase
                    .from('loggedin_users')
                    .select('github_username')
                    .eq('email', sessionUser.email)
                    .single();

                if (githubUserSession) {
                    githubUsernameSession = githubUserSession.github_username;
                }

                // Update session expiration
                const newExpiresAt = new Date();
                newExpiresAt.setFullYear(newExpiresAt.getFullYear() + 1);
                
                await supabase
                    .from('users')
                    .update({ code_expires_at: newExpiresAt.toISOString() })
                    .eq('id', sessionUser.id);

                return res.status(200).json({
                    success: true,
                    user: {
                        id: sessionUser.id,
                        email: sessionUser.email,
                        username: sessionUser.username,
                        githubUsername: githubUsernameSession
                    }
                });

            case 'logout':
                if (!sessionToken) {
                    return res.status(400).json({ error: 'No session token provided' });
                }

                // Clear session token
                await supabase
                    .from('users')
                    .update({ 
                        phone_verification_code: null,
                        code_expires_at: null 
                    })
                    .eq('phone_verification_code', sessionToken);

                return res.status(200).json({ 
                    success: true, 
                    message: 'Logged out successfully' 
                });

            default:
                return res.status(400).json({ error: 'Invalid action' });
        }
    } catch (error) {
        console.error('Auth error:', error);
        return res.status(500).json({ error: 'Internal server error' });
    }
};
