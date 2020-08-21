<?php

require_once "vendor/autoload.php";

use \Firebase\JWT\JWT;

define('ACCESS_TOKEN_SECRET_KEY', '1cb5ba0a280d06a8cd86bf36a2d2faebed2b885e64d798d5f8d0a52bc24cda04');
define('REFRESH_TOKEN_SECRET_KEY', '4596b6ebb719e0b701182419a5c0f8468d0b05d8222bef94e2111de086325be9');

function generateAccessToken() {
    return generateToken([
        'iat' => time(),
        'token_type' => 'access_token'
    ], ACCESS_TOKEN_SECRET_KEY);
}

function generateRefreshToken() {
    return generateToken([
        'iat' => time(),
        'token_type' => 'refresh_token'
    ], REFRESH_TOKEN_SECRET_KEY);
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
    setcookie('refresh_token', $refreshToken, [ 'httponly' => true ]);
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
        // TODO: validate login data
        $accessToken = generateAccessToken();
        $refreshToken = generateRefreshToken();
        storeRefreshToken($refreshToken);
        saveRefreshTokenToCookie($refreshToken);
        sendResponse([
            'success' => true,
            'access_token' => $accessToken
        ]);
        break;
    case 'refresh':
        $refreshToken = getRefreshTokenFromCookie();
        if (verifyRefreshToken($refreshToken) === true) {
            invalidateRefreshToken($refreshToken);
            deleteRefreshTokenFromCookie();
            if (parseRefreshToken($refreshToken) !== null) {
                $accessToken = generateAccessToken();
                $refreshToken = generateRefreshToken();
                storeRefreshToken($refreshToken);
                saveRefreshTokenToCookie($refreshToken);
                sendResponse([
                    'success' => true,
                    'access_token' => $accessToken
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
            if (parseAccessToken($accessToken) !== null) {
                sendResponse([
                    'success' => true,
                    'time' => time(),
                    'data' => 'some data...'
                ]);
                break;
            }
        }
        sendResponse([
            'success' => false
        ]);
        break;
}
