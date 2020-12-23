<?php
/**
 * Copyright (C) 1997-2020 Reyesoft <info@reyesoft.com>.
 *
 * This file is part of php-afip-ws. php-afip-ws can not be copied and/or
 * distributed without the express permission of Reyesoft
 */

declare(strict_types=1);

namespace Multinexo\WSAA;

use Multinexo\Drivers\FileSystemDriver;
use Multinexo\Drivers\LocalFileSystem;
use Multinexo\Exceptions\WsException;
use Multinexo\Models\GeneralHelper;
use Multinexo\Models\Validaciones;
use SimpleXMLElement;
use SoapClient;
use stdClass;

/**
 * Class wsaa
 * Based in Gerardo Fisanotti wsaa-client.php
 * Define: WSDL, CERT, PRIVATEKEY, PASSPHRASE, SERVICE, WSAAURL
 * Returns: TA.xml (WSAA authorization ticket).
 */
class Wsaa
{
    use Validaciones;

    /**
     * Chequea si necesita renovar el Ticket de Acceso para el ws.
     *
     * @throws WsException
     */
    public function checkTARenovation(stdClass $service): bool
    {
        $path = $service->configuracion->dir->xml_generados . 'TA-' . $service->configuracion->cuit . '-' . $service->ws . '.xml';

        if (!$service->fs->exists($path)) {
            self::authenticate($service);
        }

        $xml = $service->fs->get($path);

        $expirationTime = self::getXmlAttribute($xml, ['header', 'expirationTime']);

        if (strtotime((string) $expirationTime) < strtotime(date('Y-m-d h:i:s'))) {
            self::authenticate($service);

            return true;
        }

        return false;
    }

    /**
     * Crea un pedido de ticket de acceso (Access Request Ticket (TRA)).
     */
    private static function createTRA(stdClass $service): void
    {
        $TRA = new SimpleXMLElement(
            '<?xml version="1.0" encoding="UTF-8"?>' .
            '<loginTicketRequest version="1.0">' .
            '</loginTicketRequest>'
        );
        $TRA->addChild('header');
        $TRA->header->addChild('uniqueId', date('U'));
        $TRA->header->addChild('generationTime', date('c', time() - 60));
        $TRA->header->addChild('expirationTime', date('c', time() + 60));
        $TRA->addChild('service', GeneralHelper::getOriginalWsName($service->ws));
        $content = $TRA->asXML();
        $service->fs->put($service->configuracion->dir->xml_generados . 'TRA-' . $service->ws . '.xml', $content);
    }

    /**
     * Crea la firma PKCS#7 usando entrada el archivo TRA*.xml (Pedido de Ticket de Autorización), el certificado  y
     * la clave privada. Genera un archivo intermedio y finalmente ajusta la cabecera MIME dejando el CMS final
     * requerido por WSAA.
     *
     * @throws WsException
     */
    private static function signTRA(stdClass $service): string
    {
        $configuracion = $service->configuracion;
        $dir = $configuracion->dir;
        $archivos = $configuracion->archivos;

        $inputXmlPath = tempnam(sys_get_temp_dir(), '');
        $certificadoPath = tempnam(sys_get_temp_dir(), '');
        $outputTmpPath = tempnam(sys_get_temp_dir(), '');

        file_put_contents($inputXmlPath, $service->fs->get($dir->xml_generados . 'TRA-' . $service->ws . '.xml'));
        file_put_contents($certificadoPath, $service->fs->get($archivos->certificado));

        $STATUS = openssl_pkcs7_sign(
            $inputXmlPath,
            $outputTmpPath,
            'file://' . $certificadoPath,
            [
                'file://' . $archivos->clavePrivada,
                $configuracion->passPhrase,
            ],
            [],
            0
        );

        if (!$STATUS) {
            throw new WsException('Error en la generacion de la firma PKCS#7');
        }
        $inf = fopen($outputTmpPath, 'r');
        $i = 0;
        $CMS = '';

        while (!feof($inf)) {
            $buffer = fgets($inf);
            if ($i++ >= 4) {
                $CMS .= $buffer;
            }
        }
        fclose($inf);

        unlink($inputXmlPath);
        unlink($certificadoPath);
        unlink($outputTmpPath);

        return $CMS;
    }

    /*
     * Conecta con el servidor remoto y ejecuta el metodo remoto LoginCMS retornando un Ticket de Acceso (TA).
     *
     * param $CMS : Recibe un CMS (Cryptographic Message Syntax)
     *
     * return Ticket de Acceso generado por AFIP en formato xml
     */
    private static function callWSAA(stdClass $service, string $CMS)
    {
        $client = new SoapClient($service->configuracion->archivos->wsaaWsdl, [
            'proxy_port' => $service->configuracion->proxyPort,
            'soap_version' => SOAP_1_2,
            'location' => $service->configuracion->url->wsaa,
            'trace' => 1,
            'exceptions' => 0,
        ]);
        $results = $client->loginCms(['in0' => $CMS]);
        $service->fs->put(
            $service->configuracion->dir->xml_generados . 'request-loginCms.xml',
            $client->__getLastRequest()
        );
        $service->fs->put(
            $service->configuracion->dir->xml_generados . 'response-loginCms.xml',
            $client->__getLastResponse()
        );
        if (is_soap_fault($results)) {
            throw new WsException('SOAP Fault: [' . $results->faultcode . ']: ' . $results->faultstring);
        }

        return $results->loginCmsReturn;
    }

    /**
     * Permite autenticarse al ws.
     *
     * @throws WsException
     */
    private static function authenticate(stdClass $service): bool
    {
        //        ini_set("soap.wsdl_cache_enabled", "0");
        $dir = $service->configuracion->dir;
        $archivos = $service->configuracion->archivos;

        // Se crean los directorios en donde se alojaran las claves y los xmls generados en caso que no existan
        foreach ($dir as $directory) {
            !$service->fs->isDirectory($directory) ? $service->fs->makeDirectory($directory, 0777, true) : false;
        }

        // Se verifica que exista la clave privada, el certificado y el wsaa.wsdl
        foreach ($archivos as $key => $archivo) {
            $exists = false;

            if($key == 'certificado')
                $exists = $service->fs->exists($archivo);
            else
                $exists = file_exists($archivo); // privateKey y wsaa.wsdl son locales a la libreria

            if (!$exists) {
                throw new WsException(
                    'Error al abrir el archivo ' .$archivo . ', verifique su existencia'
                );
            }
        }

        self::createTRA($service);
        $CMS = self::signTRA($service);
        $TA = self::callWSAA($service, $CMS);

        $filename = $dir->xml_generados . 'TA-' . $service->configuracion->cuit . '-' . $service->ws . '.xml';
        if (!$service->fs->put($filename, $TA)) {
            throw new WsException('Hubo un error al tratar de autenticarse');
        }

        return true;
    }

    /**
     * Permite obtener un atributo de un archivo con formato xml.
     *
     * @param mixed[] $nodes
     *
     * @return bool|SimpleXMLElement|SimpleXMLElement[]
     */
    private static function getXmlAttribute(string $xml, array $nodes = [])
    {
        $TaXml = simplexml_load_string($xml);
        foreach ($nodes as $node) {
            if (isset($TaXml->{$node})) {
                $TaXml = $TaXml->{$node};
            } else {
                return false;
            }
        }

        return $TaXml;
    }
}
