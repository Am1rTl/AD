<?php

namespace App\Exceptions;

use Illuminate\Database\Eloquent\Model;
use Symfony\Component\HttpKernel\Exception\HttpException;

final class ModelLimitException extends HttpException 
{
    private string $modelClass;
    private int $limit;

    public function __construct(Model $model, int $limit, int $code = 0, ?\Throwable $previous = null)
    {
        $this->modelClass = $model::class;
        $this->limit = $limit;
        parent::__construct(
            422, 
            sprintf("The maximum limit for a %s entity is %d.", class_basename($this->modelClass), $this->limit), 
            $previous, 
            code: $code
        );
    }

    public function getModelClass(): string
    {
        return $this->modelClass;
    }
}
