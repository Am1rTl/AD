<?php

namespace Lib;

class Router {
    private static $routes = [];

    public static function add($url, $handler, $method) {
        $url = trim($url, '/');
        $url = "~" . $url . "~";
        if (!array_key_exists($url, self::$routes)) {
            self::$routes[$url] = ["handler" => $handler, "method" => $method];
        }
    }

    private static function parseRequest($request) {
        $request = trim($request, '/');
        $segments = explode('/', $request);
        $uri = [];
        $params = [];
        foreach ($segments as $segment) {
            if (strpos($segment, '?') !== false) {
                $parts = explode('?', $segment);
                $uri[] = $parts[0];
                $params[] = isset($parts[1]) ? $parts[1] : '';
            } else {
                $uri[] = $segment;
            }
        }
        $uri = implode('/', $uri);

        return [
            'uri' => $uri,
            'params' => $params
        ];
    }

    public static function serve() {
        $parsed_request = self::parseRequest(isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '');

        $parsed_uri = $parsed_request['uri'];
        $parsed_params = $parsed_request['params'];
        $parsed_method = isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : '';

        foreach (self::$routes as $uri => $values)
        {
            if (preg_match_all($uri, $parsed_uri, $out) == 1 and (strcmp($parsed_method, $values['method']) === 0 or strcmp($parsed_method, "ANY") === 0))
            {
                call_user_func($values['handler']);
                return;
            }

            $path = realpath("static/$parsed_uri");
            if (str_starts_with($path, "/app/static/"))
            {
                echo file_get_contents($path);
                return;
            }
        }

        http_response_code(404);
        echo "Not found. 404";
    }
}
?>
