<?php

namespace App\FormIntegrations;

use App\FormIntegrations\IntegrationInterface;

final class SendIntegrationException extends \RuntimeException 
{
    private IntegrationInterface $integration;

    public function __construct(string $message, IntegrationInterface $integration, int $code = 0, ?\Throwable $previous = null)
    {
        $this->integration = $integration;
        parent::__construct($message, $code, $previous);
    }

    public function getIntegration(): IntegrationInterface
    {
        return $this->integration;
    }
}
