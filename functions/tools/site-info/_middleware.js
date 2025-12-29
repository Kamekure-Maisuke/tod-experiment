// Basic認証のミドルウェア
export async function onRequest(context) {
    const { request, next, env } = context;

    // 環境変数から認証情報を取得（本番環境用）
    // ローカル開発では以下のデフォルト値を使用
    const USERNAME = env.SITE_INFO_USERNAME || 'admin';
    const PASSWORD = env.SITE_INFO_PASSWORD || 'password';

    // Authorizationヘッダーを取得
    const authorization = request.headers.get('Authorization');

    if (!authorization) {
        return unauthorizedResponse();
    }

    // Basic認証の検証
    const [scheme, encoded] = authorization.split(' ');

    // スキームがBasicでない場合は拒否
    if (!scheme || scheme !== 'Basic') {
        return unauthorizedResponse();
    }

    // Base64デコード
    const buffer = Uint8Array.from(atob(encoded), (c) => c.charCodeAt(0));
    const decoded = new TextDecoder().decode(buffer);
    const [username, password] = decoded.split(':');

    // 認証情報の検証
    if (username !== USERNAME || password !== PASSWORD) {
        return unauthorizedResponse();
    }

    // 認証成功、次の処理へ
    return next();
}

function unauthorizedResponse() {
    return new Response('Unauthorized', {
        status: 401,
        headers: {
            'WWW-Authenticate': 'Basic realm="Site Info Tool", charset="UTF-8"',
        },
    });
}
