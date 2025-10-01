<?php

declare(strict_types=1);

namespace App\Auth;

use App\Config\Config;
use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Aws\Exception\AwsException;

final class CognitoClient
{
    private CognitoIdentityProviderClient $client;
    private string $clientId;
    private ?string $clientSecret;
    private string $userPoolId;

    public function __construct(Config $config)
    {
        $this->client = new CognitoIdentityProviderClient([
            'version' => 'latest',
            'region' => (string) $config->get('cognito_region'),
        ]);

        $this->clientId = (string) $config->get('cognito_client_id');
        $this->clientSecret = ($config->get('cognito_client_secret') !== '') ? (string) $config->get('cognito_client_secret') : null;
        $this->userPoolId = (string) $config->get('cognito_user_pool_id');
    }

    /**
     * @return array<string, mixed>
     * @throws AwsException
     */
    public function initiateUserPasswordAuth(string $username, string $password): array
    {
        $params = [
            'AuthFlow' => 'USER_PASSWORD_AUTH',
            'ClientId' => $this->clientId,
            'AuthParameters' => [
                'USERNAME' => $username,
                'PASSWORD' => $password,
            ],
        ];

        if ($this->clientSecret) {
            $params['AuthParameters']['SECRET_HASH'] = $this->secretHash($username);
        }

        return $this->client->initiateAuth($params)->toArray();
    }

    /**
     * @param array<string, string> $challengeResponses
     * @return array<string, mixed>
     */
    public function respondToAuthChallenge(string $challengeName, string $session, array $challengeResponses): array
    {
        if (!isset($challengeResponses['USERNAME'])) {
            throw new \InvalidArgumentException('USERNAME is required in challenge responses');
        }

        if ($this->clientSecret) {
            $challengeResponses['SECRET_HASH'] = $this->secretHash($challengeResponses['USERNAME']);
        }

        return $this->client->respondToAuthChallenge([
            'ChallengeName' => $challengeName,
            'ClientId' => $this->clientId,
            'Session' => $session,
            'ChallengeResponses' => $challengeResponses,
        ])->toArray();
    }

    /**
     * @return array<string, mixed>
     */
    public function initiateRefreshTokenAuth(string $refreshToken, string $username): array
    {
        $authParameters = [
            'REFRESH_TOKEN' => $refreshToken,
            'USERNAME' => $username,
        ];

        if ($this->clientSecret) {
            $authParameters['SECRET_HASH'] = $this->secretHash($username);
        }

        return $this->client->initiateAuth([
            'AuthFlow' => 'REFRESH_TOKEN_AUTH',
            'ClientId' => $this->clientId,
            'AuthParameters' => $authParameters,
        ])->toArray();
    }

    /**
     * @return array<string, mixed>
     */
    public function signUp(string $username, string $password, string $email): array
    {
        $params = [
            'ClientId' => $this->clientId,
            'Username' => $username,
            'Password' => $password,
            'UserAttributes' => [
                ['Name' => 'email', 'Value' => $email],
            ],
        ];

        if ($this->clientSecret) {
            $params['SecretHash'] = $this->secretHash($username);
        }

        return $this->client->signUp($params)->toArray();
    }

    public function confirmSignUp(string $username, string $code): void
    {
        $params = [
            'ClientId' => $this->clientId,
            'Username' => $username,
            'ConfirmationCode' => $code,
        ];

        if ($this->clientSecret) {
            $params['SecretHash'] = $this->secretHash($username);
        }

        $this->client->confirmSignUp($params);
    }

    public function resendConfirmationCode(string $username): void
    {
        $params = [
            'ClientId' => $this->clientId,
            'Username' => $username,
        ];

        if ($this->clientSecret) {
            $params['SecretHash'] = $this->secretHash($username);
        }

        $this->client->resendConfirmationCode($params);
    }

    public function forgotPassword(string $username): void
    {
        $params = [
            'ClientId' => $this->clientId,
            'Username' => $username,
        ];

        if ($this->clientSecret) {
            $params['SecretHash'] = $this->secretHash($username);
        }

        $this->client->forgotPassword($params);
    }

    public function confirmForgotPassword(string $username, string $confirmationCode, string $newPassword): void
    {
        $params = [
            'ClientId' => $this->clientId,
            'Username' => $username,
            'ConfirmationCode' => $confirmationCode,
            'Password' => $newPassword,
        ];

        if ($this->clientSecret) {
            $params['SecretHash'] = $this->secretHash($username);
        }

        $this->client->confirmForgotPassword($params);
    }

    /**
     * @return array<string, mixed>
     */
    public function associateSoftwareToken(string $session): array
    {
        return $this->client->associateSoftwareToken(['Session' => $session])->toArray();
    }

    /**
     * @return array<string, mixed>
     */
    public function verifySoftwareToken(string $session, string $userCode, string $friendlyDeviceName = ''): array
    {
        $params = [
            'Session' => $session,
            'UserCode' => $userCode,
        ];

        if ($friendlyDeviceName !== '') {
            $params['FriendlyDeviceName'] = $friendlyDeviceName;
        }

        return $this->client->verifySoftwareToken($params)->toArray();
    }

    public function setUserMfaPreference(string $accessToken, bool $prefersSoftwareToken, bool $prefersEmail = false): void
    {
        $softwareTokenSettings = $prefersSoftwareToken ? ['Enabled' => true, 'PreferredMfa' => true] : null;
        $emailSettings = $prefersEmail ? ['Enabled' => true, 'PreferredMfa' => true] : null;

        $params = [
            'AccessToken' => $accessToken,
        ];

        if ($softwareTokenSettings) {
            $params['SoftwareTokenMfaSettings'] = $softwareTokenSettings;
        }

        if ($emailSettings) {
            $params['EmailMfaSettings'] = $emailSettings;
        }

        $this->client->setUserMFAPreference($params);
    }

    private function secretHash(string $username): string
    {
        if ($this->clientSecret === null) {
            throw new \LogicException('Client secret is not configured');
        }

        return base64_encode(hash_hmac('sha256', $username . $this->clientId, $this->clientSecret, true));
    }
}
