export async function onRequest(context) {
    const { request } = context;

    // CORSヘッダー
    const corsHeaders = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
    };

    // OPTIONSリクエスト（プリフライト）の処理
    if (request.method === 'OPTIONS') {
        return new Response(null, {
            headers: corsHeaders,
        });
    }

    // POSTメソッドのみ許可
    if (request.method !== 'POST') {
        return new Response(JSON.stringify({ error: 'Method not allowed' }), {
            status: 405,
            headers: {
                'Content-Type': 'application/json',
                ...corsHeaders,
            },
        });
    }

    try {
        const { url } = await request.json();

        if (!url) {
            return new Response(JSON.stringify({ error: 'URL is required' }), {
                status: 400,
                headers: {
                    'Content-Type': 'application/json',
                    ...corsHeaders,
                },
            });
        }

        // URLのバリデーション
        let targetUrl;
        try {
            targetUrl = new URL(url);
        } catch (e) {
            return new Response(JSON.stringify({ error: 'Invalid URL' }), {
                status: 400,
                headers: {
                    'Content-Type': 'application/json',
                    ...corsHeaders,
                },
            });
        }

        // HEADリクエストでサイト情報を取得
        const startTime = Date.now();
        const response = await fetch(targetUrl.toString(), {
            method: 'HEAD',
            headers: {
                'User-Agent': 'Mozilla/5.0 (compatible; SiteInfoTool/1.0)',
            },
        });
        const responseTime = Date.now() - startTime;

        // レスポンス情報を収集
        const info = {
            'Server Hostname': targetUrl.hostname,
            'Server Port': targetUrl.port || (targetUrl.protocol === 'https:' ? '443' : '80'),
            'Protocol': targetUrl.protocol.replace(':', ''),
            'Response Time': `${responseTime}ms`,
            'Status Code': response.status,
        };

        // サーバーソフトウェア
        const server = response.headers.get('server');
        if (server) {
            info['Server Software'] = server;
        }

        // レスポンスヘッダーを追加
        const headersToExtract = [
            'content-type',
            'content-length',
            'content-encoding',
            'cache-control',
            'expires',
            'last-modified',
            'etag',
            'strict-transport-security',
            'x-frame-options',
            'x-content-type-options',
            'content-security-policy',
            'x-powered-by',
            'cf-ray',
            'cf-cache-status',
        ];

        headersToExtract.forEach(header => {
            const value = response.headers.get(header);
            if (value) {
                const displayName = header.split('-')
                    .map(word => word.charAt(0).toUpperCase() + word.slice(1))
                    .join('-');
                info[displayName] = value;
            }
        });

        // Cloudflare固有の情報（利用可能な場合）
        if (response.cf) {
            if (response.cf.tlsVersion) {
                info['TLS Version'] = response.cf.tlsVersion;
            }
            if (response.cf.tlsCipher) {
                info['TLS Cipher'] = response.cf.tlsCipher;
            }
            if (response.cf.colo) {
                info['Cloudflare Data Center'] = response.cf.colo;
            }
        }

        return new Response(JSON.stringify({ success: true, info }), {
            status: 200,
            headers: {
                'Content-Type': 'application/json',
                ...corsHeaders,
            },
        });
    } catch (error) {
        return new Response(
            JSON.stringify({
                error: error.message || 'Failed to fetch site information',
            }),
            {
                status: 500,
                headers: {
                    'Content-Type': 'application/json',
                    ...corsHeaders,
                },
            }
        );
    }
}
