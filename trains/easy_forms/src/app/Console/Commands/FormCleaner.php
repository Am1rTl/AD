<?php

namespace App\Console\Commands;

use App\Models\Form;
use App\Models\FormResult;
use App\Models\User;
use Illuminate\Console\Command;
use Illuminate\Support\Carbon;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Output\OutputInterface;

#[AsCommand(name: 'cleaner:form')]
final class FormCleaner extends Command
{
    protected $signature = 'cleaner:form {minutes}';

    protected $description = 'Form models cleaner';

    public function handle()
    {
        $this->components->info(
            'Clean old forms',
            $this->getLaravel()->isLocal() ? OutputInterface::VERBOSITY_NORMAL : OutputInterface::VERBOSITY_VERBOSE
        );

        $expired = Carbon::now()->subMinutes($this->argument('minutes'));

        FormResult::where('updated_at', '<', $expired)->delete();
        Form::where('updated_at', '<', $expired)->delete();
        User::where('updated_at', '<', $expired)->delete();
    }
}