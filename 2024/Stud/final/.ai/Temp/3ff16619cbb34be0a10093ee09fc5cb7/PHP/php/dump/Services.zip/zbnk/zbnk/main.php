<?php

ignore_user_abort(true);

// Boot your app
require __DIR__.'/vendor/autoload.php';

use Lib\Router;
use Lib\SQLDispatcher;

$host     = 'db';
$dbname   = $_ENV['POSTGRES_DB'];
$username = $_ENV['POSTGRES_USER'];
$password = $_ENV['POSTGRES_PASSWORD'];

SQLDispatcher::$connstring = "host=$host dbname=$dbname user=$username password=$password";
SQLDispatcher::connect();

Router::add("/api/login",           'AuthController::login',               'POST');
Router::add("/api/register",        'AuthController::register',            'POST');
Router::add("/api/logout",          'AuthController::logout',              'GET');

Router::add("/api/convert",         'CurrencyController::convert_currency', 'POST');
Router::add("/api/balance",         'CurrencyController::get_balance',      'GET');
Router::add("/api/exchangerate",    'CurrencyController::exchange_rate',   'GET');

Router::add("/api/kopilka/create",  'KopilkaController::create',           'POST');
Router::add("/api/kopilka/get",     'KopilkaController::get',              'GET');
Router::add("/api/kopilka/generate",'KopilkaController::generate_report',  'GET');
Router::add("/api/kopilka/list",    'KopilkaController::userKopilkasList', 'GET');
Router::add("/api/kopilka/joinList",'KopilkaController::userKopilkasJoinList', 'GET');
Router::add("/api/kopilka/join",    'KopilkaController::join',             'POST');

Router::add("/api/info",            'ADDataController::get',               'GET');

Router::add("/login",               'AuthController::reglog',              'GET');
Router::add("/register",            'AuthController::reglog',              'GET');
Router::add("/index",               'AuthController::index',               'GET');
Router::add("/",                    'AuthController::index',               'GET');

Router::add("/balance",             'CurrencyController::currency',        'GET');
Router::add("/kopilka/create",      'KopilkaController::kopilkacreate',    'GET');
Router::add("/kopilka/list",        'KopilkaController::kopilkalist',      'GET');
Router::add("/kopilka/info",        'KopilkaController::kopilkainfo',      'GET');

Router::serve();
