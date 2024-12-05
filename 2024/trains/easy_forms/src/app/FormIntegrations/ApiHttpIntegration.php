<?php

namespace App\FormIntegrations;

use App\Models\FormIntegration;
use App\Models\FormResult;
use App\Rules\ExternalUrl;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Handler\StreamHandler;
use Illuminate\Support\Str;

final class ApiHttpIntegration implements IntegrationInterface
{
    private Client $client;
    private float $conntect_timeout;
    private float $read_timeout;

    public function __construct(float $conntect_timeout = 1.0, float $read_timeout = 1.5) 
    {
        $this->client = new Client(['handler' => new StreamHandler]);
        $this->conntect_timeout = $conntect_timeout;
        $this->read_timeout = $read_timeout;
    }

    public function send(FormIntegration $integration, FormResult $formResult): void
    {
        // @info: disabling DoS-ssrf abuse for A/D
        if ($this->isGlobalUrl($integration->url)) {
            return;
        }

        try {
            $res = $this->client->request($integration->method, $integration->url, [
                'headers' => $this->parseHeaders($integration->headers),
                'body' => $this->populateBody($integration, $formResult),
                'connect_timeout' => $this->conntect_timeout,
                'read_timeout' => $this->read_timeout,
            ]);
            $status = $res->getStatusCode(); 
            if ($status !== 200) {
                throw new SendIntegrationException(
                    sprintf('The integration "%s" resposne return %d status code.', $this::class, $status), 
                    $this
                );
            }
        } catch (GuzzleException $e) {
            throw new SendIntegrationException($e->getMessage(), $this, $e->getCode(), $e);
        }
    }

    public function getRules(): array
    {
        return [
            'url' => ['required', new ExternalUrl],
            'method' => 'required|string',
            'headers' => 'present|array',
            'headers.*' => 'array',
            'headers.*.name' => 'string',
            'headers.*.value' => 'string',
            'body' => 'string',
        ];
    }

    private function isGlobalUrl(string $url): bool
    {
        $match = preg_match('#https?://([^/]+)/#i', $url, $matches);
        if ($match > 0) {
            $ip = gethostbyname($matches[1]);
            return (bool)filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_GLOBAL_RANGE);
        }
        return False;
    }

    private function parseHeaders(array $headers): array
    {
        $keyValueArr = [];
        foreach ($headers as $header) {
            $name = strtolower($header['name']);
            $value = strtolower($header['value']);
            if ($name == 'host') {
                $keyValueArr[$name] = $value;
            } elseif (!empty($keyValueArr[$name])) {
                $keyValueArr[$name] = [...array($keyValueArr[$name]), $value];
            } else {
                $keyValueArr[$name] = $value;
            }
        }
        return $keyValueArr;
    }

    private function populateBody(FormIntegration $integration, FormResult $formResult): string
    {
        $resultValue = json_encode($formResult->toArray()); 
        if (!$integration->body) {
            return $resultValue;
        }

        return Str::replaceFirst('%FORM_RESULT%', $resultValue, $integration->body);
    }
}