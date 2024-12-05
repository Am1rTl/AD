<?php

namespace App\Console\Commands;

use App\Models\User;
use Illuminate\Console\Command;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Output\OutputInterface;

#[AsCommand(name: 'debug:create_user')]
final class CreateDebugUser extends Command
{
    protected $signature = 'debug:create_user {username} {email} {password}';

    protected $description = 'Create debug user';

    public function handle()
    {
        $this->components->info(
            'Create debug user',
            $this->getLaravel()->isLocal() ? OutputInterface::VERBOSITY_NORMAL : OutputInterface::VERBOSITY_VERBOSE
        );

        $username = $this->argument('username');
        $email = $this->argument('email');
        $password = $this->argument('password');

        User::create([
            'name' => $username,
            'email' => $email,
            'password' => $password,
            'can_debug' => true,
        ]);
        $this->components->info('Debug user created');
    }
}