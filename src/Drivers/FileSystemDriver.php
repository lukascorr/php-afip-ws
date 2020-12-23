<?php


namespace Multinexo\Drivers;


interface FileSystemDriver
{
    public function exists(String $path): bool;

    public function get(String $path);

    public function put(String $path, $content);

    public function delete(String $path);

    public function isDirectory(String $path): bool;

    public function makeDirectory($path, $mode = 0755, $recursive = false, $force = false);
}
