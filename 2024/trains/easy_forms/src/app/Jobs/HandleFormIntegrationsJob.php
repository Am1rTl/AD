<?php

namespace App\Jobs;

use App\Models\Form;
use App\Models\FormResult;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;

final class HandleFormIntegrationsJob implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    private Form $form;
    private FormResult $formResult;

    public function __construct(Form $form, FormResult $formResult)
    {
        $this->form = $form;
        $this->formResult = $formResult;
    }

    public function handle(): void
    {   
        foreach ($this->form->integrations as $integration) {
            if (!$integration->active) {
                continue;
            }
            HandleIntegrationJob::dispatch($integration->toArray(), $this->formResult);
        }
    }
}
