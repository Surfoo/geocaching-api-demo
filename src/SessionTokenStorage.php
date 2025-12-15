<?php

declare(strict_types=1);

namespace GeoDemo;

use League\OAuth2\Client\Token\TokenSet;
use League\OAuth2\Client\Token\TokenStorageInterface;

/**
 * Simple session-based token storage with best-effort locking.
 *
 * In production, replace with a durable store (DB/cache) and real locking.
 */
class SessionTokenStorage implements TokenStorageInterface
{
    private array $locks = [];

    public function getTokens(string $referenceCode): ?TokenSet
    {
        $accessToken = $_SESSION['token'] ?? null;
        if (!$accessToken instanceof \League\OAuth2\Client\Token\AccessTokenInterface) {
            return null;
        }

        $raw = [
            'access_token'  => $accessToken->getToken(),
            'refresh_token' => $accessToken->getRefreshToken(),
            'expires_in'    => $accessToken->getExpires() ? ($accessToken->getExpires() - time()) : 3600,
            'token_type'    => 'Bearer',
        ];

        return TokenSet::fromOAuthResponse($raw, $raw['refresh_token'] ?? null);
    }

    public function saveTokens(string $referenceCode, TokenSet $tokens): void
    {
        $_SESSION['token'] = new \League\OAuth2\Client\Token\AccessToken($tokens->toArray());
    }

    public function lockUser(string $referenceCode, int $timeoutSeconds = 30): bool
    {
        if (!empty($this->locks[$referenceCode])) {
            return false;
        }

        $this->locks[$referenceCode] = true;
        return true;
    }

    public function unlockUser(string $referenceCode): void
    {
        unset($this->locks[$referenceCode]);
    }

    public function isUserLocked(string $referenceCode): bool
    {
        return !empty($this->locks[$referenceCode]);
    }
}
