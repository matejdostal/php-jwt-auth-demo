<?php

require_once "vendor/autoload.php";

use \Firebase\JWT\JWT;

define('ACCESS_TOKEN_SECRET_KEY', '1cb5ba0a280d06a8cd86bf36a2d2faebed2b885e64d798d5f8d0a52bc24cda04');
define('REFRESH_TOKEN_SECRET_KEY', '4596b6ebb719e0b701182419a5c0f8468d0b05d8222bef94e2111de086325be9');

define('ACCESS_TOKEN_EXPIRATION_TIME', 10); // 10 seconds
define('REFRESH_TOKEN_EXPIRATION_TIME', 60); // 60 seconds

function generateAccessToken($payload) {
    return generateToken([
        'iat' => time(),
        'exp' => time() + ACCESS_TOKEN_EXPIRATION_TIME
    ] + $payload, ACCESS_TOKEN_SECRET_KEY);
}

function generateRefreshToken($payload) {
    return generateToken([
        'iat' => time(),
        'exp' => time() + REFRESH_TOKEN_EXPIRATION_TIME
    ] + $payload, REFRESH_TOKEN_SECRET_KEY);
}

function generateToken($payload, $key) {
    $token = JWT::encode($payload, $key);
    return $token;
}

function parseAccessToken($accessToken) {
    return parseToken($accessToken, ACCESS_TOKEN_SECRET_KEY);
}

function parseRefreshToken($refreshToken) {
    return parseToken($refreshToken, REFRESH_TOKEN_SECRET_KEY);
}

function parseToken($token, $key) {
    try {
        $payload = JWT::decode($token, $key, ['HS256']);
        return (array) $payload;
    } catch (Exception $e) {
        return null;
    }
}

function verifyRefreshToken($refreshToken) {
    $tokens = getValidRefreshTokens();
    return in_array($refreshToken, $tokens);
}

function storeRefreshToken($refreshToken) {
    $tokens = getValidRefreshTokens();
    if (!in_array($refreshToken, $tokens)) {
        $tokens[] = $refreshToken;
    }
    saveValidRefreshTokens($tokens);
}

function invalidateRefreshToken($refreshToken) {
    $tokens = getValidRefreshTokens();
    if (in_array($refreshToken, $tokens)) {
        $index = array_search($refreshToken, $tokens);
        unset($tokens[$index]);
        saveValidRefreshTokens($tokens);
    }
}

function getValidRefreshTokens() {
    return json_decode(file_get_contents('tokens.json'));
}

function saveValidRefreshTokens($tokens) {
    file_put_contents('tokens.json', json_encode($tokens));
}

function saveRefreshTokenToCookie($refreshToken) {
    setcookie('refresh_token', $refreshToken, [ 'httponly' => true, 'expires' => time() + REFRESH_TOKEN_EXPIRATION_TIME ]);
}

function deleteRefreshTokenFromCookie() {
    setcookie('refresh_token', '', [ 'httponly' => true, 'expires' => time() - 3600 ]);
}

function getRefreshTokenFromCookie() {
    $refreshToken = isset($_COOKIE['refresh_token']) ? $_COOKIE['refresh_token'] : null;
    return $refreshToken;
}

function getAccessTokenFromHeader() {
    $headers = apache_request_headers();
    $accessToken = isset($headers['X-Access-Token']) ? $headers['X-Access-Token'] : null;
    return $accessToken;
}

function sendResponse($response) {
    header("Content-Type: application/json");
    echo json_encode($response);
    exit;
}

switch ($_SERVER['QUERY_STRING']) {
    case 'login':
        $loginName = '';
        try {
            $params = json_decode(file_get_contents('php://input'), true);
            $loginName = $params['loginName'];
        } catch (Exception $e) {}
        if (!$loginName) {
            sendResponse([
                'success' => false
            ]);
            break;
        }
        $accessToken = generateAccessToken(['loginName' => $loginName]);
        $refreshToken = generateRefreshToken(['loginName' => $loginName]);
        storeRefreshToken($refreshToken);
        saveRefreshTokenToCookie($refreshToken);
        sendResponse([
            'success' => true,
            'access_token' => $accessToken,
            'access_token_expires_in' => ACCESS_TOKEN_EXPIRATION_TIME
        ]);
        break;
    case 'refresh':
        $refreshToken = getRefreshTokenFromCookie();
        if (verifyRefreshToken($refreshToken) === true) {
            invalidateRefreshToken($refreshToken);
            deleteRefreshTokenFromCookie();
            $payload = parseRefreshToken($refreshToken);
            if ($payload !== null) {
                $loginName = $payload['loginName'];
                $accessToken = generateAccessToken(['loginName' => $loginName]);
                $refreshToken = generateRefreshToken(['loginName' => $loginName]);
                storeRefreshToken($refreshToken);
                saveRefreshTokenToCookie($refreshToken);
                sendResponse([
                    'success' => true,
                    'access_token' => $accessToken,
                    'access_token_expires_in' => ACCESS_TOKEN_EXPIRATION_TIME
                ]);
                break;
            }
        }
        sendResponse([
            'success' => false
        ]);
        break;
    case 'logout':
        $refreshToken = getRefreshTokenFromCookie();
        invalidateRefreshToken($refreshToken);
        deleteRefreshTokenFromCookie();
        sendResponse([
            'success' => true
        ]);
        break;
    case 'data':
        $accessToken = getAccessTokenFromHeader();
        if ($accessToken) {
            $payload = parseAccessToken($accessToken);
            if ($payload !== null) {
                sendResponse([
                    'success' => true,
                    'time' => time(),
                    'loginName' => $payload['loginName']
                ]);
                break;
            }
        }
        sendResponse([
            'success' => false
        ]);
        break;
}
