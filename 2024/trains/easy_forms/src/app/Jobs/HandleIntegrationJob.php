<?php

namespace App\Jobs;

use App\FormIntegrations\IntegrationInterface;
use App\Models\FormIntegration;
use App\Models\FormResult;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\App;

final class HandleIntegrationJob implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    private array $integrationAttrs;
    private FormResult $formResult;

    public function __construct(array $integrationAttrs, FormResult $formResult)
    {
        $this->integrationAttrs = $integrationAttrs;
        $this->formResult = $formResult;
    }

    public function handle(): void
    {
        $formIntegration = new FormIntegration($this->integrationAttrs);
        /** @var IntegrationInterface $itegration */
        $itegration = App::make("form_integration:{$formIntegration->type}");
        $itegration->send($formIntegration, $this->formResult);
    }
}
