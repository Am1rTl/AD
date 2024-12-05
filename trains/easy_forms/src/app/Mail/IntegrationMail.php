<?php

namespace App\Mail;

use App\Models\FormResult;
use Illuminate\Bus\Queueable;
use Illuminate\Mail\Mailable;
use Illuminate\Mail\Mailables\Content;
use Illuminate\Queue\SerializesModels;

class IntegrationMail extends Mailable
{
    use Queueable, SerializesModels;

    private FormResult $formResult;

    public function __construct(string $from, string $to, string $subject, FormResult $formResult)
    {
        $this->from($from);
        $this->to($to);
        $this->subject($subject);
        $this->formResult = $formResult;
    }

    public function content(): Content
    {
        $resultHtml = '';
        foreach ($this->formResult->toArray() as $attr => $value) {
            $resultHtml .= "<b>{$attr}:</b> {$value}<br/>";
        }

        return new Content(
            htmlString: <<<Mail
    <h1>Form results:</h1>
    <div>{$resultHtml}</div>
Mail,
        );
    }
}
