const { createClient } = require('@supabase/supabase-js');
const { Octokit } = require('@octokit/rest');
const crypto = require('crypto');

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseServiceKey = process.env.SUPABASE_SERVICE_KEY;
const supabase = createClient(supabaseUrl, supabaseServiceKey);

const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;

// Decrypt GitHub token
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

    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    try {
        const { sessionToken, repoName, description, isPrivate, files, syncToGitHub } = req.body;

        // Validate session
        if (!sessionToken) {
            return res.status(401).json({ error: 'Authentication required' });
        }

        // Get user from session
        const { data: user, error: userError } = await supabase
            .from('users')
            .select('id, email')
            .eq('phone_verification_code', sessionToken)
            .single();

        if (userError || !user) {
            return res.status(401).json({ error: 'Invalid session' });
        }

        // Get GitHub connection info
        const { data: githubUser, error: githubError } = await supabase
            .from('loggedin_users')
            .select('github_username, github_token_encrypted')
            .eq('email', user.email)
            .single();

        if (syncToGitHub && (!githubUser || !githubUser.github_username)) {
            return res.status(400).json({ 
                error: 'GitHub account not connected',
                needsGithubAuth: true 
            });
        }

        let githubRepoId = null;
        let githubRepoUrl = null;
        let webhookSecret = null;

        // If syncing to GitHub
        if (syncToGitHub && githubUser) {
            try {
                // Decrypt GitHub token
                const githubToken = decrypt(githubUser.github_token_encrypted);
                
                if (!githubToken) {
                    return res.status(500).json({ error: 'Failed to decrypt GitHub token' });
                }

                // Initialize GitHub client
                const octokit = new Octokit({ auth: githubToken });

                // Create repository on GitHub
                const repoResponse = await octokit.repos.createForAuthenticatedUser({
                    name: repoName,
                    description: description || 'School project created with School_git',
                    private: isPrivate !== false,
                    auto_init: true // Initialize with README
                });

                githubRepoId = repoResponse.data.id.toString();
                githubRepoUrl = repoResponse.data.html_url;

                // Generate webhook secret
                webhookSecret = crypto.randomBytes(20).toString('hex');

                // Add webhook for syncing
                await octokit.repos.createWebhook({
                    owner: githubUser.github_username,
                    repo: repoName,
                    config: {
                        url: `https://school-git.vercel.app/api/webhook`,
                        content_type: 'json',
                        secret: webhookSecret
                    },
                    events: ['push', 'pull_request']
                });

                // Add initial files if provided
                if (files && Array.isArray(files) && files.length > 0) {
                    for (const file of files) {
                        if (file.path && file.content) {
                            await octokit.repos.createOrUpdateFileContents({
                                owner: githubUser.github_username,
                                repo: repoName,
                                path: file.path,
                                message: file.message || `Add ${file.path}`,
                                content: Buffer.from(file.content).toString('base64')
                            });
                        }
                    }
                }

            } catch (githubError) {
                console.error('GitHub API error:', githubError);
                return res.status(500).json({ 
                    error: 'Failed to create GitHub repository',
                    details: githubError.message 
                });
            }
        }

        // Store in github_repos table (temporary storage)
        const { data: newRepo, error: repoError } = await supabase
            .from('github_repos')
            .insert([{
                repo_name: repoName,
                repo_url: githubRepoUrl || `local://${user.id}/${repoName}`,
                repo_id: githubRepoId || `local-${Date.now()}`,
                user_id: user.id,
                webhook_secret: webhookSecret,
                last_sync: syncToGitHub ? new Date().toISOString() : null,
                created_at: new Date().toISOString()
            }])
            .select()
            .single();

        if (repoError) {
            throw repoError;
        }

        return res.status(201).json({
            success: true,
            message: syncToGitHub ? 'Repository created on GitHub' : 'Repository created locally',
            repo: {
                id: newRepo.id,
                name: newRepo.repo_name,
                url: newRepo.repo_url,
                githubId: newRepo.repo_id,
                isOnGitHub: !!githubRepoUrl,
                githubUrl: githubRepoUrl,
                createdAt: newRepo.created_at
            }
        });

    } catch (error) {
        console.error('Create repo error:', error);
        return res.status(500).json({ 
            error: 'Failed to create repository',
            details: error.message 
        });
    }
};
