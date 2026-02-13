<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Advanced AUTH System</title>
    <style>
        :root {
            --bg: #0f172a;
            --surface: #1e293b;
            --text: #e2e8f0;
            --muted: #94a3b8;
            --primary: #6366f1;
            --accent: #38bdf8;
            --success: #10b981;
            --danger: #ef4444;
            --code-bg: #020617;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg);
            color: var(--text);
            line-height: 1.6;
            max-width: 900px;
            margin: 0 auto;
            padding: 40px 20px;
        }

        h1, h2, h3 { color: #ffffff; }

        h1 {
            font-size: 2.5rem;
            border-bottom: 2px solid var(--primary);
            padding-bottom: 10px;
            margin-bottom: 20px;
        }

        h2 {
            color: var(--accent);
            margin-top: 40px;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        p { color: var(--muted); font-size: 1.1rem; }

        /* Features List */
        ul { list-style: none; padding-left: 0; }
        li {
            background: var(--surface);
            margin-bottom: 15px;
            padding: 20px;
            border-radius: 12px;
            border-left: 4px solid var(--primary);
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        }
        .feature-title { font-weight: bold; color: var(--accent); font-size: 1.1rem; display: block; margin-bottom: 5px;}

        /* Code Blocks */
        pre {
            background: var(--code-bg);
            padding: 20px;
            border-radius: 12px;
            overflow-x: auto;
            color: #a5b4fc;
            border: 1px solid #334155;
        }
        code { font-family: 'Courier New', Courier, monospace; }

        /* Routes Styling */
        .route-group {
            background: var(--surface);
            padding: 20px;
            border-radius: 12px;
            margin-bottom: 25px;
            border: 1px solid #334155;
        }
        .route-group h3 { margin-top: 0; color: #ffffff; border-bottom: 1px solid #334155; padding-bottom: 10px; }
        .route {
            display: flex;
            flex-direction: column;
            margin-bottom: 15px;
            padding-bottom: 15px;
            border-bottom: 1px dashed #334155;
        }
        .route:last-child { border-bottom: none; margin-bottom: 0; padding-bottom: 0; }

        .method-endpoint { display: flex; align-items: baseline; gap: 10px; margin-bottom: 5px; }
        .method { font-weight: bold; padding: 4px 8px; border-radius: 6px; font-size: 0.85rem; }
        .method.post { background: rgba(16, 185, 129, 0.2); color: var(--success); }
        .method.get { background: rgba(56, 189, 248, 0.2); color: var(--accent); }
        .method.delete { background: rgba(239, 68, 68, 0.2); color: var(--danger); }

        .endpoint { color: #f1f5f9; font-family: monospace; font-size: 1.05rem; }
        .body-req { color: #a5b4fc; font-family: monospace; background: var(--code-bg); padding: 4px 8px; border-radius: 4px; font-size: 0.9rem; }
        .desc { color: var(--muted); font-size: 0.95rem; margin-top: 5px; }

        .warning-badge {
            background: rgba(245, 158, 11, 0.2);
            color: #fbbf24;
            padding: 4px 10px;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: bold;
            margin-left: 10px;
        }

        .footer {
            text-align: center;
            margin-top: 60px;
            padding-top: 20px;
            border-top: 1px solid #334155;
            color: var(--muted);
            font-weight: bold;
        }
    </style>

</head>
<body>

    <h1>🛡️ Advanced AUTH System</h1>
    <p>Yo, welcome to the Auth System. This isn't just a basic login system. This backend handles <strong>Role-Based Access Control (RBAC)</strong>, <strong>Attribute-Based Access Control (ABAC)</strong>, <strong>Device Tracking</strong>, <strong>MFA (2FA)</strong>, and <strong>Google OAuth2</strong> with smart account linking.</p>



    <h2>✨ Features</h2>
    <ul>
        <li><span class="feature-title">🧠 Smart Security Guard (RBAC + ABAC)</span> Doesn't just check if you are an admin. It checks if you own the resource, if it's locked, and if your email is verified.</li>
        <li><span class="feature-title">🎭 The "Socialite" (OAuth2)</span> Custom Google Login flow. If a user logs in
