<?php


namespace Multinexo\Drivers;


class LocalFileSystem implements FileSystemDriver
{

    public function exists(string $path): bool
    {
        return file_exists($path);
    }

    public function get(string $path)
    {
        return file_get_contents($path);
    }

    public function put(string $path, $content)
    {
        return file_put_contents($path, $content);
    }

    public function delete(string $path)
    {
        return unlink($path);
    }

    public function isDirectory(string $path): bool
    {
        return is_dir($path);
    }

    public function makeDirectory($path, $mode = 0755, $recursive = false, $force = false)
    {
        if ($force) {
            return @mkdir($path, $mode, $recursive);
        }

        return mkdir($path, $mode, $recursive);
    }
}
