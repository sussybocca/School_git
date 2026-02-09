const { createClient } = require('@supabase/supabase-js');

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseServiceKey = process.env.SUPABASE_SERVICE_KEY;
const supabase = createClient(supabaseUrl, supabaseServiceKey);

module.exports = async (req, res) => {
    res.setHeader('Access-Control-Allow-Credentials', true);
    res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,PATCH,DELETE,POST,PUT');
    res.setHeader('Access-Control-Allow-Headers', 'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version');

    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    if (req.method !== 'GET' && req.method !== 'POST') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    try {
        const sessionToken = req.method === 'POST' ? req.body.sessionToken : req.query.sessionToken;

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

        // Get repositories from github_repos table
        const { data: repos, error: reposError } = await supabase
            .from('github_repos')
            .select('*')
            .eq('user_id', user.id)
            .order('created_at', { ascending: false });

        if (reposError) {
            throw reposError;
        }

        // Format response
        const formattedRepos = repos.map(repo => ({
            id: repo.id,
            name: repo.repo_name,
            url: repo.repo_url,
            githubId: repo.repo_id,
            isOnGitHub: !repo.repo_id.startsWith('local-'),
            createdAt: repo.created_at,
            lastSync: repo.last_sync
        }));

        return res.status(200).json({
            success: true,
            repos: formattedRepos,
            count: formattedRepos.length
        });

    } catch (error) {
        console.error('List repos error:', error);
        return res.status(500).json({ 
            error: 'Failed to list repositories',
            details: error.message 
        });
    }
};
