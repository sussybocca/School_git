const { createClient } = require('@supabase/supabase-js');
const crypto = require('crypto');

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseServiceKey = process.env.SUPABASE_SERVICE_KEY;
const supabase = createClient(supabaseUrl, supabaseServiceKey);

const GITHUB_CLIENT_ID = process.env.GITHUB_CLIENT_ID;
const GITHUB_CLIENT_SECRET = process.env.GITHUB_CLIENT_SECRET;
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;

// Encrypt function
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

module.exports = async (req, res) => {
    res.setHeader('Access-Control-Allow-Credentials', true);
    res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,PATCH,DELETE,POST,PUT');
    res.setHeader('Access-Control-Allow-Headers', 'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version');

    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    try {
        const { action, code, userId, email, sessionToken } = req.body;

        switch (action) {
            case 'initiate':
                // Generate state parameter
                const state = crypto.randomBytes(16).toString('hex');
                
                // Store state in user's table temporarily
                if (userId) {
                    await supabase
                        .from('users')
                        .update({ two_step_enabled: state }) // Reusing this field for state
                        .eq('id', userId);
                }

                // GitHub OAuth URL with repo scope
                const githubAuthUrl = `https://github.com/login/oauth/authorize?client_id=${GITHUB_CLIENT_ID}&scope=repo,user&state=${state}&redirect_uri=${encodeURIComponent('https://school-git.vercel.app/auth-callback.html')}`;
                
                return res.status(200).json({
                    success: true,
                    authUrl: githubAuthUrl
                });

            case 'callback':
                const { state: receivedState } = req.body;
                
                if (!code || !receivedState) {
                    return res.status(400).json({ error: 'Missing code or state' });
                }

                // Find user by state
                const { data: user } = await supabase
                    .from('users')
                    .select('id, email, two_step_enabled')
                    .eq('two_step_enabled', receivedState)
                    .single();

                if (!user) {
                    return res.status(400).json({ error: 'Invalid state parameter' });
                }

                // Exchange code for access token
                const tokenResponse = await fetch('https://github.com/login/oauth/access_token', {
                    method: 'POST',
                    headers: {
                        'Accept': 'application/json',
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        client_id: GITHUB_CLIENT_ID,
                        client_secret: GITHUB_CLIENT_SECRET,
                        code,
                        state: receivedState
                    })
                });

                const tokenData = await tokenResponse.json();

                if (tokenData.error) {
                    throw new Error(tokenData.error_description || 'GitHub OAuth error');
                }

                // Get GitHub user info
                const userResponse = await fetch('https://api.github.com/user', {
                    headers: {
                        'Authorization': `Bearer ${tokenData.access_token}`,
                        'Accept': 'application/vnd.github.v3+json',
                        'User-Agent': 'School_git'
                    }
                });

                const githubUser = await userResponse.json();

                // Encrypt GitHub token
                const encryptedToken = encrypt(tokenData.access_token);

                // Update or create loggedin_users entry
                const { data: existingLoggedInUser } = await supabase
                    .from('loggedin_users')
                    .select('id')
                    .eq('email', user.email)
                    .single();

                if (existingLoggedInUser) {
                    // Update existing
                    await supabase
                        .from('loggedin_users')
                        .update({
                            github_id: githubUser.id.toString(),
                            github_username: githubUser.login,
                            github_avatar: githubUser.avatar_url,
                            updated_at: new Date().toISOString()
                        })
                        .eq('email', user.email);
                } else {
                    // Create new
                    await supabase
                        .from('loggedin_users')
                        .insert([{
                            email: user.email,
                            github_id: githubUser.id.toString(),
                            github_username: githubUser.login,
                            github_avatar: githubUser.avatar_url,
                            created_at: new Date().toISOString(),
                            updated_at: new Date().toISOString()
                        }]);
                }

                // Clear state from user table
                await supabase
                    .from('users')
                    .update({ two_step_enabled: false })
                    .eq('id', user.id);

                return res.status(200).json({
                    success: true,
                    message: 'GitHub account connected successfully',
                    githubUsername: githubUser.login,
                    githubAvatar: githubUser.avatar_url
                });

            case 'disconnect':
                if (!sessionToken) {
                    return res.status(401).json({ error: 'Authentication required' });
                }

                // Get user from session token
                const { data: sessionUser } = await supabase
                    .from('users')
                    .select('email')
                    .eq('phone_verification_code', sessionToken)
                    .single();

                if (!sessionUser) {
                    return res.status(401).json({ error: 'Invalid session' });
                }

                // Remove GitHub connection from loggedin_users
                await supabase
                    .from('loggedin_users')
                    .update({
                        github_id: null,
                        github_username: null,
                        github_avatar: null,
                        updated_at: new Date().toISOString()
                    })
                    .eq('email', sessionUser.email);

                return res.status(200).json({
                    success: true,
                    message: 'GitHub account disconnected'
                });

            case 'get-status':
                if (!email && !sessionToken) {
                    return res.status(400).json({ error: 'Email or session token required' });
                }

                let userEmail = email;
                
                // If session token provided, get email from it
                if (sessionToken && !email) {
                    const { data: tokenUser } = await supabase
                        .from('users')
                        .select('email')
                        .eq('phone_verification_code', sessionToken)
                        .single();
                    
                    if (tokenUser) {
                        userEmail = tokenUser.email;
                    }
                }

                if (!userEmail) {
                    return res.status(400).json({ error: 'Could not determine user' });
                }

                // Check GitHub connection status
                const { data: githubStatus } = await supabase
                    .from('loggedin_users')
                    .select('github_username, github_avatar')
                    .eq('email', userEmail)
                    .single();

                return res.status(200).json({
                    success: true,
                    connected: !!githubStatus?.github_username,
                    githubUsername: githubStatus?.github_username || null,
                    githubAvatar: githubStatus?.github_avatar || null
                });

            default:
                return res.status(400).json({ error: 'Invalid action' });
        }
    } catch (error) {
        console.error('GitHub auth error:', error);
        return res.status(500).json({ 
            error: 'Failed to process GitHub authentication',
            details: error.message 
        });
    }
};
