<?php

namespace App\FormIntegrations;

use App\Mail\IntegrationMail;
use App\Models\FormIntegration;
use App\Models\FormResult;
use Illuminate\Support\Facades\Mail;

final class MailIntegration implements IntegrationInterface
{
    public function send(FormIntegration $integration, FormResult $formResult): void
    {
        $sentMessage = Mail::sendNow(new IntegrationMail(
            $integration->from,
            $integration->to,
            $integration->subject,
            $formResult
        ));
        if (!$sentMessage) {
            throw new SendIntegrationException(
                sprintf('The integration "%s" couldn\'t send message to %s.', $this::class, $integration->to), 
                $this
            );
        }
    }

    public function getRules(): array
    {
        return [
            'from' => 'required|string',
            'to' => 'required|string',
            'subject' => 'required|string',
        ];
    }
}