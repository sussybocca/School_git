const { createClient } = require('@supabase/supabase-js');
const crypto = require('crypto');

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseServiceKey = process.env.SUPABASE_SERVICE_KEY;
const supabase = createClient(supabaseUrl, supabaseServiceKey);

const GITHUB_CLIENT_ID = process.env.GITHUB_CLIENT_ID;
const GITHUB_CLIENT_SECRET = process.env.GITHUB_CLIENT_SECRET;
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;

// GitHub Proxy Function
async function githubProxy(endpoint, method = 'GET', body = null, accessToken = null, userId = null) {
    try {
        // Check if proxy is enabled globally
        const { data: settings } = await supabase
            .from('settings')
            .select('value')
            .eq('key', 'github_proxy_enabled')
            .single();
            
        if (settings && settings.value === 'false') {
            throw new Error('GitHub proxy is disabled by school administrator');
        }
        
        // Build URL
        let url;
        if (endpoint.startsWith('http')) {
            url = endpoint;
        } else if (endpoint.startsWith('/')) {
            url = `https://api.github.com${endpoint}`;
        } else {
            url = `https://api.github.com/${endpoint}`;
        }
        
        // Headers
        const headers = {
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'SchoolGit-Proxy/1.0'
        };
        
        if (accessToken) {
            headers['Authorization'] = `token ${accessToken}`;
        }
        
        if (body && method !== 'GET') {
            headers['Content-Type'] = 'application/json';
        }
        
        // Make request
        const response = await fetch(url, {
            method,
            headers,
            body: body ? JSON.stringify(body) : null
        });
        
        // Log proxy usage
        if (userId) {
            await supabase
                .from('proxy_logs')
                .insert([{
                    endpoint: endpoint,
                    method: method,
                    user_id: userId,
                    timestamp: new Date().toISOString(),
                    status: response.status
                }]);
        }
        
        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`GitHub API error (${response.status}): ${errorText}`);
        }
        
        return await response.json();
    } catch (error) {
        console.error('GitHub proxy error:', error);
        
        // Check if it's a network block
        if (error.message.includes('network') || 
            error.message.includes('fetch') || 
            error.message.includes('ECONNREFUSED') ||
            error.message.includes('Failed to fetch')) {
            throw new Error('GitHub is blocked by school network. Working in local mode.');
        }
        
        throw error;
    }
}

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

// Decrypt function  
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
    res.setHeader('Access-Control-Allow-Credentials', true);
    res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,PATCH,DELETE,POST,PUT');
    res.setHeader('Access-Control-Allow-Headers', 'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version');

    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    try {
        const { action, code, sessionToken, repoName, description, isPrivate, email, schoolDomain, enabled } = req.body;

        switch (action) {
            case 'initiate':
                if (!sessionToken) {
                    return res.status(401).json({ 
                        error: 'Please log in first',
                        needsLogin: true 
                    });
                }
                
                const { data: authUser } = await supabase
                    .from('users')
                    .select('id, email, two_step_enabled')
                    .eq('phone_verification_code', sessionToken)
                    .single();
                    
                if (!authUser) {
                    return res.status(401).json({ error: 'Invalid session' });
                }
                
                // Check school settings
                const userEmailDomain = authUser.email.split('@')[1];
                const { data: schoolSettings } = await supabase
                    .from('school_settings')
                    .select('allow_github_access')
                    .eq('school_domain', userEmailDomain)
                    .single();
                    
                if (schoolSettings && schoolSettings.allow_github_access === false) {
                    return res.status(403).json({
                        error: 'GitHub access is disabled for your school',
                        localOnly: true,
                        message: 'You can still work locally without GitHub connection.'
                    });
                }
                
                // Generate state
                const state = crypto.randomBytes(16).toString('hex');
                
                // Store state
                await supabase
                    .from('users')
                    .update({ two_step_enabled: state })
                    .eq('id', authUser.id);

                // GitHub OAuth URL
                const callbackUrl = `https://school-git.vercel.app/auth-callback.html`;
                const githubAuthUrl = `https://github.com/login/oauth/authorize?client_id=${GITHUB_CLIENT_ID}&scope=repo&state=${state}&redirect_uri=${encodeURIComponent(callbackUrl)}`;
                
                return res.status(200).json({
                    success: true,
                    authUrl: githubAuthUrl
                });

            case 'callback':
                const { state: receivedState } = req.body;
                
                if (!code || !receivedState) {
                    return res.status(400).json({ error: 'Missing OAuth parameters' });
                }

                // Find user by state
                let callbackUser = null;
                const { data: stateUser } = await supabase
                    .from('users')
                    .select('id, email, two_step_enabled')
                    .eq('two_step_enabled', receivedState)
                    .single();

                if (!stateUser) {
                    if (sessionToken) {
                        const { data: sessionUser } = await supabase
                            .from('users')
                            .select('id, email')
                            .eq('phone_verification_code', sessionToken)
                            .single();
                        callbackUser = sessionUser;
                    }
                    
                    if (!callbackUser) {
                        return res.status(400).json({ 
                            error: 'Session expired',
                            needsLogin: true 
                        });
                    }
                } else {
                    callbackUser = stateUser;
                }

                try {
                    // Use proxy for token exchange
                    const tokenData = await githubProxy(
                        'login/oauth/access_token', 
                        'POST', 
                        {
                            client_id: GITHUB_CLIENT_ID,
                            client_secret: GITHUB_CLIENT_SECRET,
                            code,
                            state: receivedState
                        },
                        null,
                        callbackUser.id
                    );

                    if (tokenData.error) {
                        throw new Error(tokenData.error_description || 'GitHub OAuth error');
                    }

                    // Get user info through proxy
                    const githubUser = await githubProxy(
                        'user', 
                        'GET', 
                        null, 
                        tokenData.access_token,
                        callbackUser.id
                    );
                    
                    // Encrypt and store token
                    const encryptedToken = encrypt(tokenData.access_token);
                    
                    await supabase
                        .from('loggedin_users')
                        .upsert({
                            email: callbackUser.email,
                            github_id: githubUser.id.toString(),
                            github_username: githubUser.login,
                            github_avatar: githubUser.avatar_url,
                            github_token_encrypted: encryptedToken,
                            updated_at: new Date().toISOString()
                        }, {
                            onConflict: 'email'
                        });

                    // Clear state
                    await supabase
                        .from('users')
                        .update({ two_step_enabled: null })
                        .eq('id', callbackUser.id);

                    return res.status(200).json({
                        success: true,
                        githubUsername: githubUser.login,
                        githubAvatar: githubUser.avatar_url,
                        message: 'GitHub connected successfully'
                    });

                } catch (proxyError) {
                    console.error('Proxy error:', proxyError);
                    
                    return res.status(200).json({
                        success: false,
                        error: 'Cannot connect to GitHub',
                        fallback: true,
                        message: 'GitHub appears to be blocked. Working in local mode.',
                        localMode: true
                    });
                }

            case 'create-repo':
                if (!sessionToken) {
                    return res.status(401).json({ error: 'Authentication required' });
                }

                const { data: repoUser } = await supabase
                    .from('users')
                    .select('id, email')
                    .eq('phone_verification_code', sessionToken)
                    .single();

                if (!repoUser) {
                    return res.status(401).json({ error: 'Invalid session' });
                }

                const { data: githubConn } = await supabase
                    .from('loggedin_users')
                    .select('github_token_encrypted, github_username')
                    .eq('email', repoUser.email)
                    .single();

                if (!githubConn || !githubConn.github_token_encrypted) {
                    // No GitHub - store locally
                    const { data: localRepo } = await supabase
                        .from('github_repos')
                        .insert([{
                            user_id: repoUser.id,
                            repo_name: repoName,
                            repo_description: description || '',
                            is_private: isPrivate !== false,
                            status: 'local',
                            created_at: new Date().toISOString()
                        }])
                        .select()
                        .single();

                    return res.status(200).json({
                        success: true,
                        repo: localRepo,
                        message: 'Repository created locally (GitHub not connected)'
                    });
                }

                try {
                    const decryptedToken = decrypt(githubConn.github_token_encrypted);
                    
                    if (!decryptedToken) {
                        throw new Error('Failed to decrypt GitHub token');
                    }

                    const repoData = {
                        name: repoName,
                        description: description || '',
                        private: isPrivate !== false,
                        auto_init: true
                    };

                    const githubRepo = await githubProxy(
                        `user/repos`, 
                        'POST', 
                        repoData, 
                        decryptedToken,
                        repoUser.id
                    );

                    const { data: savedRepo } = await supabase
                        .from('github_repos')
                        .insert([{
                            user_id: repoUser.id,
                            repo_name: repoName,
                            repo_url: githubRepo.html_url,
                            repo_id: githubRepo.id.toString(),
                            status: 'synced',
                            created_at: new Date().toISOString()
                        }])
                        .select()
                        .single();

                    return res.status(200).json({
                        success: true,
                        repo: savedRepo,
                        githubUrl: githubRepo.html_url,
                        message: 'Repository created on GitHub'
                    });

                } catch (error) {
                    console.error('Create repo error:', error);
                    
                    const { data: localRepo } = await supabase
                        .from('github_repos')
                        .insert([{
                            user_id: repoUser.id,
                            repo_name: repoName,
                            repo_description: description || '',
                            is_private: isPrivate !== false,
                            status: 'queued',
                            sync_error: error.message,
                            created_at: new Date().toISOString()
                        }])
                        .select()
                        .single();

                    return res.status(200).json({
                        success: true,
                        repo: localRepo,
                        warning: 'Created locally. Will sync to GitHub when available.',
                        error: error.message
                    });
                }

            case 'admin-toggle':
                if (!sessionToken) {
                    return res.status(401).json({ error: 'Admin authentication required' });
                }

                const { data: adminUser } = await supabase
                    .from('users')
                    .select('email, preference')
                    .eq('phone_verification_code', sessionToken)
                    .single();

                if (!adminUser || adminUser.preference !== 'admin') {
                    return res.status(403).json({ error: 'Admin access required' });
                }

                await supabase
                    .from('school_settings')
                    .upsert({
                        school_domain: schoolDomain,
                        allow_github_access: enabled,
                        updated_by: adminUser.email,
                        updated_at: new Date().toISOString()
                    }, {
                        onConflict: 'school_domain'
                    });

                return res.status(200).json({
                    success: true,
                    message: `GitHub access ${enabled ? 'enabled' : 'disabled'} for ${schoolDomain}`
                });

            case 'get-status':
                if (!sessionToken && !email) {
                    return res.status(400).json({ error: 'Session token or email required' });
                }

                let statusUser = null;
                if (sessionToken) {
                    const { data: tokenUser } = await supabase
                        .from('users')
                        .select('id, email')
                        .eq('phone_verification_code', sessionToken)
                        .single();
                    statusUser = tokenUser;
                } else if (email) {
                    const { data: emailUser } = await supabase
                        .from('users')
                        .select('id, email')
                        .eq('email', email)
                        .single();
                    statusUser = emailUser;
                }
                    
                if (!statusUser) {
                    return res.status(401).json({ error: 'User not found' });
                }

                // Check GitHub connection
                const { data: userStatus } = await supabase
                    .from('loggedin_users')
                    .select('github_username, github_avatar')
                    .eq('email', statusUser.email)
                    .single();

                // Check school settings
                const userDomain = statusUser.email.split('@')[1];
                const { data: schoolStatus } = await supabase
                    .from('school_settings')
                    .select('allow_github_access')
                    .eq('school_domain', userDomain)
                    .single();

                return res.status(200).json({
                    success: true,
                    connected: !!userStatus?.github_username,
                    githubUsername: userStatus?.github_username || null,
                    githubAvatar: userStatus?.github_avatar || null,
                    githubAllowed: !schoolStatus || schoolStatus.allow_github_access !== false,
                    schoolRestricted: schoolStatus?.allow_github_access === false
                });

            default:
                return res.status(400).json({ error: 'Invalid action' });
        }
    } catch (error) {
        console.error('GitHub auth error:', error);
        return res.status(500).json({ 
            success: false,
            error: 'Internal server error',
            details: error.message
        });
    }
};
