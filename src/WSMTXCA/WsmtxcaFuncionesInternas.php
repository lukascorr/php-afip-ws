<?php
/**
 * Copyright (C) 1997-2020 Reyesoft <info@reyesoft.com>.
 *
 * This file is part of php-afip-ws. php-afip-ws can not be copied and/or
 * distributed without the express permission of Reyesoft
 */

declare(strict_types=1);

namespace Multinexo\WSMTXCA;

use Multinexo\Exceptions\ManejadorResultados;
use Multinexo\Exceptions\WsException;
use stdClass;

trait WsmtxcaFuncionesInternas
{
    /** @var ManejadorResultados */
    public $resultado;

    /**
     * Consultar un Comprobante autorizado
     * Permite consultar los datos de un comprobante previamente autorizado, ya sea del tipo Código de Autorización CAE
     * ó CAEA.
     */
    public function wsConsultarComprobante(stdClass $data): stdClass
    {
        $resultado = $this->service->client->consultarComprobante(
            [
                'authRequest' => $this->service->authRequest,
                'consultaComprobanteRequest' => [
                    'codigoTipoComprobante' => $data->codigoComprobante,
                    'numeroPuntoVenta' => $data->puntoVenta,
                    'numeroComprobante' => $data->numeroComprobante,
                ],
            ]
        );

        $this->resultado->procesar($resultado);

        return $resultado->comprobante;
    }

    /**
     * Consultar un CAEA previamente otorgado
     * Permite consultar la información correspondiente a CAEA s que hayan tenido vigencia en algún momento dentro de un
     * rango de fechas determinado.
     */
    public function wsConsultarCAEAEntreFechas(stdClass $data): stdClass
    {
        $resultado = $this->service->client->consultarCAEAEntreFechas(
            [
                'authRequest' => $this->service->authRequest,
                'fechaDesde' => $data->fechaDesde,
                'fechaHasta' => $data->fechaHasta,
            ]
        );

        $this->resultado->procesar($resultado);

        return $resultado->arrayCAEAResponse;
    }

    /**
     * Consultar un CAEA previamente otorgado
     * Permite consultar la información correspondiente a un CAEA previamente otorgado.
     */
    public function wsConsultarCAEA(stdClass $data): stdClass
    {
        $resultado = $this->service->client->consultarCAEA(
            [
                'authRequest' => $this->service->authRequest,
                'CAEA' => $data->caea,
            ]
        );

        $this->resultado->procesar($resultado);

        return $resultado->CAEAResponse;
    }

    /**
     * SolicitarCAEA.
     *
     * retorna la comprobación vía “ping” de los elementos principales de infraestructura del servicio.
     *                * cuit: Cuit Emisora del comprobante.
     *                * codigoTipoComprobante: Especifica el tipo de  comprobante.
     *                * numeroPuntoVenta: Indica el  número de  punto de venta del comprobante  autorizado.
     *                * numeroComprobante: Indica el número del  comprobante aprobado.
     *                * fechaEmision: Fecha de emisión del  comprobante.
     *                * CAE: CAE asignado al  comprobante  autorizado.
     *                * fechaVencimientoCAE: Fecha de  vencimiento del CAE  otorgado
     */
    public function wsSolicitarCAEA(stdClass $data): stdClass
    {
        $resultado = $this->service->client->solicitarCAEA(
            [
                'authRequest' => $this->service->authRequest,
                'solicitudCAEA' => [
                    'periodo' => $data->periodo,
                    'orden' => $data->orden,
                ],
            ]
        );

        $this->resultado->procesar($resultado);

        return $resultado->CAEAResponse;
    }

    /*
     * Autorizar Comprobante CAE.
     *
     * retorna la comprobación vía “ping” de los elementos principales de infraestructura del servicio.
     *                  * cuit: Cuit Emisora del comprobante.
     *                  * codigoTipoComprobante: Especifica el tipo de  comprobante.
     *                  * numeroPuntoVenta: Indica el  número de  punto de venta del comprobante  autorizado.
     *                  * numeroComprobante: Indica el número del  comprobante aprobado.
     *                  * fechaEmision: Fecha de emisión del  comprobante.
     *                  * CAE: CAE asignado al  comprobante  autorizado.
     *                  * fechaVencimientoCAE: Fecha de  vencimiento del CAE  otorgado
     */
    public function wsAutorizarComprobante(stdClass $cbte): stdClass
    {
        $resultado = $this->service->client->autorizarComprobante(
            [
                'authRequest' => $this->service->authRequest,
                'comprobanteCAERequest' => $cbte,
            ]
        );

        $this->resultado->procesar($resultado);

        return $resultado;
    }

    // todo:arrayErrores

    /**
     * Consultar el Último Comprobante Autorizado
     * Permite consultar el último número decomprobante autorizado para undeterminado punto de venta y tipo de
     * comprobante, tanto para comprobantes con código de autorización CAE como CAEA.
     *
     * @param int $cbteTipo : Tipo de comprobante que se desea consultar
     * @param int $ptoVta : Punto de venta para el cual se requiera conocer el último número de
     *                    comprobante autorizado
     */
    public function wsConsultarUltimoComprobanteAutorizado($cbteTipo, $ptoVta): ?int
    {
        $resultado = $this->service->client->consultarUltimoComprobanteAutorizado(
            [
                'authRequest' => $this->service->authRequest,
                'consultaUltimoComprobanteAutorizadoRequest' => [
                    'codigoTipoComprobante' => $cbteTipo,
                    'numeroPuntoVenta' => $ptoVta,
                ],
            ]
        );

        $this->resultado->procesar($resultado);

        return $resultado->numeroComprobante;
    }

    /**
     * Metodo dummy para verificacion de funcionamiento.
     *
     * retorna la comprobación vía “ping” de los elementos principales de infraestructura del servicio.
     * AppServer string(2) Servidor de aplicaciones
     * DbServer string(2) Servidor de base de datos
     * AuthServer string(2) Servidor de autenticación
     *
     * @throws WsException
     */
    public static function dummy(\SoapClient $client): stdClass
    {
        $result = $client->Dummy();

        if (is_soap_fault($result)) {
            throw new WsException($result->getMessage(), 503);
        }

        return $result;
    }

    /**
     * Permite adaptar los datos enviados en el array de comprobante a los campos definidos por el ws de la AFIP
     * para la generacion de comprobantes con items.
     */
    public function parseFacturaArray(stdClass $factura): stdClass
    {
        $importeOtrosTributos = 0;
        $importeGravado = 0;
        if (property_exists($factura, 'importeOtrosTributos')) {
            $importeOtrosTributos = $factura->importeOtrosTributos;
        }

        if (property_exists($factura, 'importeGravado')) {
            $importeGravado = $factura->importeGravado;
        }

        $comprobante = [
            'codigoTipoComprobante' => $factura->codigoComprobante,
            'numeroPuntoVenta' => $factura->puntoVenta,
            'numeroComprobante' => $factura->numeroComprobante,
            'fechaEmision' => $factura->fechaEmision,
            'codigoTipoAutorizacion' => $factura->codigoTipoAutorizacion,
            'codigoTipoDocumento' => $factura->codigoDocumento,
            'numeroDocumento' => $factura->numeroDocumento,
            'importeGravado' => $importeGravado,
            'importeNoGravado' => $factura->importeNoGravado,
            'importeExento' => $factura->importeExento,
            'importeSubtotal' => $factura->importeSubtotal,
            'importeOtrosTributos' => $importeOtrosTributos,
            'importeTotal' => $factura->importeTotal,
            'codigoMoneda' => $factura->codigoMoneda,
            'cotizacionMoneda' => $factura->cotizacionMoneda,
            'observaciones' => $factura->observaciones,
            'codigoConcepto' => $factura->codigoConcepto,
            'fechaServicioDesde' => $factura->fechaServicioDesde,
            'fechaServicioHasta' => $factura->fechaServicioHasta,
            'fechaVencimientoPago' => $factura->fechaVencimientoPago,
            'arrayItems' => $factura->arrayItems,
        ];

        if (!property_exists($factura, 'importeOtrosTributos')) {
            unset($comprobante['importeOtrosTributos']);
        }

        if (!property_exists($factura, 'importeGravado')) {
            unset($comprobante['importeGravado']);
        }

        $comprobante = json_decode(json_encode($comprobante));

        $this->setDocument($factura, $comprobante);

        return json_decode(json_encode($comprobante));
    }

    private function setDocument(stdClass $factura, stdClass &$comprobante): void
    {
        if (isset($factura->arraySubtotalesIVA)) {
            $arraySubtotalesIVA = [];
            foreach ($factura->arraySubtotalesIVA->subtotalIVA as $iva) {
                $arraySubtotalesIVA[] = [
                    'codigo' => $iva->codigoIva,
                    'importe' => $iva->importe,
                ];
            }
            $comprobante->{'arraySubtotalesIVA'} = $arraySubtotalesIVA;
        }

        if (isset($factura->arrayComprobantesAsociados)) {
            $arrayComprobantesAsociados = [];
            foreach ($factura->arrayComprobantesAsociados->comprobanteAsociado as $comprobantesAsociado) {
                $arrayComprobantesAsociados[] = [
                    'codigoTipoComprobante' => $comprobantesAsociado->codigoComprobante,
                    'numeroPuntoVenta' => $comprobantesAsociado->puntoVenta,
                    'numeroComprobante' => $comprobantesAsociado->numeroComprobante,
                ];
            }
            $comprobante->{'arrayComprobantesAsociados'} = $arrayComprobantesAsociados;
        }

        if (isset($factura->arrayOtrosTributos)) {
            $arrayOtrosTributos = [];
            foreach ($factura->arrayOtrosTributos->otroTributo as $tributo) {
                $arrayOtrosTributos[] = [
                    'codigo' => $tributo->codigoComprobante,
                    'descripcion' => $tributo->descripcion,
                    'baseImponible' => $tributo->baseImponible,
                    'importe' => $tributo->importe,
                ];
            }

            $comprobante->{'arrayOtrosTributos'} = $arrayOtrosTributos;
        }
    }

    /**
     * @todo Testar funciones.
     */
    public function wsInformarComprobanteCAEA(string $cbte): string
    {
        $result = $this->service->client->informarComprobanteCAEA(
            [
                'authRequest' => $this->service->authRequest,
                'comprobanteCAEARequest' => $cbte,
            ]
        );

        return $result->comprobante;
    }

    public function wsInformarCAEANoUtilizado(string $caea): string
    {
        $result = $this->service->client->informarCAEANoUtilizado(
            [
                'authRequest' => $this->service->authRequest,
                'CAEA' => $caea,
            ]
        );

        return $result->comprobante;
    }

    public function wsInformarCAEANoUtilizadoPtoVta(string $caea, string $ptoVta): string
    {
        $result = $this->service->client->informarCAEANoUtilizadoPtoVta(
            [
                'authRequest' => $this->service->authRequest,
                'CAEA' => $caea,
                'numeroPuntoVenta' => $ptoVta,
            ]
        );

        return $result->comprobante;
    }

    public function wsConsultarPtosVtaCAEANoInformados(string $caea): array
    {
        $result = $this->service->client->consultarPtosVtaCAEANoInformados(
            [
                'authRequest' => $this->service->authRequest,
                'CAEA' => $caea,
            ]
        );

        return $result->arrayPuntosVenta;
    }
}
